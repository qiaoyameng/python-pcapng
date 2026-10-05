"""Configurable metadata sanitizer for pcapng files."""

import io
import os
import struct
import tempfile

from pcapng.blocks import (
    EnhancedPacket,
    KNOWN_BLOCKS,
    ObsoletePacket,
    SimplePacket,
)
from pcapng.constants.block_types import (
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_NAME_RESOLUTION,
    BLK_PACKET,
    BLK_PACKET_SIMPLE,
    BLK_RESERVED,
    BLK_SECTION_HEADER,
)
from pcapng.scanner import FileScanner
from pcapng.exceptions import PcapngLoadError
from pcapng.structs import (
    BYTE_ORDER_MAGIC,
    BYTE_ORDER_MAGIC_INVERSE,
    Option,
)

DELETE = object()
REPLACE = object()
NAME_RESOLUTION_RECORDS = "records"

KEEP = "keep"
DROP = "drop"

DEFAULT_REPLACEMENT = b"REDACTED"


class SanitizationReport(object):
    """Result of a metadata sanitization run."""

    def __init__(self):
        self.sections = 0
        self.blocks_seen = 0
        self.blocks_written = 0
        self.options_deleted = 0
        self.options_replaced = 0
        self.records_deleted = 0
        self.packets_checked = 0
        self.unknown_options = []
        self.unknown_blocks = []
        self.unknown_records = []
        self.actions = []


def default_rules():
    """Rules which remove host/OS/interface metadata, comments and NRBs."""
    rules = {}
    for block_type, block_cls in KNOWN_BLOCKS.items():
        option_names = _option_names(block_cls)
        block_rules = {}
        if "opt_comment" in option_names:
            block_rules["opt_comment"] = DELETE
        if block_type == BLK_SECTION_HEADER:
            block_rules["shb_os"] = DELETE
        elif block_type == BLK_INTERFACE:
            block_rules["if_name"] = DELETE
            block_rules["if_description"] = DELETE
            block_rules["if_os"] = DELETE
        elif block_type == BLK_NAME_RESOLUTION:
            block_rules[NAME_RESOLUTION_RECORDS] = DELETE
        if block_rules:
            rules[block_type] = block_rules
    return rules


class MetadataSanitizer(object):
    """
    Sanitize pcapng metadata according to block/option-specific rules.

    ``rules`` maps a block type (integer or block class) to a mapping of an
    option code/name to ``DELETE``, replacement bytes, a replacement string or
    a callable.  Unknown options, records and blocks are either kept or
    dropped according to the supplied policies and are always reported.
    """

    def __init__(
        self,
        rules=None,
        unknown_options=KEEP,
        unknown_blocks=KEEP,
        unknown_records=KEEP,
        default_replacement=DEFAULT_REPLACEMENT,
    ):
        defaulted_rules = rules if rules is not None else default_rules()
        self.rules = self._normalize_rules(defaulted_rules)
        self.unknown_options = _policy(unknown_options, "unknown_options")
        self.unknown_blocks = _policy(unknown_blocks, "unknown_blocks")
        self.unknown_records = _policy(unknown_records, "unknown_records")
        self.default_replacement = _as_bytes(default_replacement, "default_replacement")

    def sanitize(self, source, destination):
        """Sanitize a binary stream and write only after full verification."""
        buffered = io.BytesIO()
        report = self._transform(source, buffered)
        buffered.seek(0)
        self._verify(buffered, report)
        buffered.seek(0)
        while True:
            chunk = buffered.read(1024 * 1024)
            if not chunk:
                break
            destination.write(chunk)
        return report

    def sanitize_file(self, source_path, destination_path):
        """Sanitize a file using a temporary file and an atomic replace."""
        destination_directory = os.path.dirname(os.path.abspath(destination_path))
        temporary_name = None
        with open(source_path, "rb") as source:
            temporary = tempfile.NamedTemporaryFile(
                mode="w+b", dir=destination_directory, prefix=".pcapng-sanitize-",
                delete=False,
            )
            temporary_name = temporary.name
            try:
                report = self.sanitize(source, temporary)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary.close()
                os.replace(temporary_name, destination_path)
                temporary_name = None
                return report
            finally:
                if temporary_name is not None:
                    temporary.close()
                    try:
                        os.unlink(temporary_name)
                    except OSError:
                        pass

    def _normalize_rules(self, rules):
        if not isinstance(rules, dict):
            raise TypeError("rules must be a mapping")
        normalized = {}
        for block_key, option_rules in rules.items():
            block_type = _block_type(block_key)
            if not isinstance(option_rules, dict):
                raise TypeError("rules for block 0x%08x must be a mapping" % block_type)
            block_cls = KNOWN_BLOCKS.get(block_type)
            if block_cls is None:
                raise ValueError(
                    "cannot configure options for unknown block type 0x%08x"
                    % block_type
                )
            option_names = _option_names(block_cls)
            has_options = any(
                name == "options" for name, field, default in block_cls.schema
            )
            normalized_options = {}
            for option_key, action in option_rules.items():
                if option_key == NAME_RESOLUTION_RECORDS:
                    if block_type != BLK_NAME_RESOLUTION or action is not DELETE:
                        raise ValueError("name resolution records can only be deleted")
                    normalized_options[NAME_RESOLUTION_RECORDS] = action
                elif not has_options:
                    raise ValueError(
                        "block type 0x%08x does not support options" % block_type
                    )
                else:
                    option_code = self._option_code(
                        block_type, option_names, option_key
                    )
                    normalized_options[option_code] = self._action(action)
            normalized[block_type] = normalized_options
        return normalized

    def _option_code(self, block_type, option_names, key):
        if isinstance(key, str):
            if key in REQUIRED_STRUCTURE_FIELDS:
                raise ValueError("required structure field %r cannot be modified" % key)
            try:
                code = option_names[key]
            except KeyError:
                raise ValueError(
                    "unknown option name %r for block 0x%08x" % (key, block_type)
                )
            if code == 0 or code in PROTECTED_OPTION_CODES:
                raise ValueError("required option code %s cannot be modified" % code)
            return code
        if not isinstance(key, int) or not 0 <= key <= 0xFFFF:
            raise ValueError("option code must be an integer from 0 through 65535")
        if key == 0 or key in PROTECTED_OPTION_CODES:
            raise ValueError("required option code %s cannot be modified" % key)
        return key

    def _action(self, action):
        if action is DELETE or action is REPLACE:
            return action
        if callable(action):
            return action
        return _as_bytes(action, "replacement")

    def _transform(self, source, destination):
        report = SanitizationReport()
        endianness = None
        interfaces = 0
        snaplens = []
        expected_packets = []

        while True:
            block_type_raw = _read_exact(source, 4, allow_eof=True)
            if block_type_raw is None:
                break
            block_type = struct.unpack(
                (endianness if endianness is not None else ">") + "I",
                block_type_raw,
            )[0]

            if block_type == BLK_SECTION_HEADER:
                length_raw = _read_exact(source, 4)
                bom = _read_exact(source, 4)
                if bom == struct.pack(">I", BYTE_ORDER_MAGIC):
                    endianness = ">"
                elif bom == struct.pack(">I", BYTE_ORDER_MAGIC_INVERSE):
                    endianness = "<"
                else:
                    raise PcapngLoadError("invalid section byte-order magic")
                length = struct.unpack(endianness + "I", length_raw)[0]
                _valid_block_length(length)
                rest = _read_exact(source, length - 16)
                source.read((4 - length % 4) % 4)
                trailer = _read_exact(source, 4)
                _check_trailer(length, trailer, endianness)
                fixed = bom + rest[0:4] + b"\xff" * 8
                options_body, _, _ = self._sanitize_options(
                    BLK_SECTION_HEADER, rest[12:], endianness, report
                )
                body = fixed + options_body
                _write_block(destination, block_type, body, endianness)
                report.sections += 1
                report.blocks_seen += 1
                report.blocks_written += 1
                interfaces = 0
                snaplens = []
                continue

            if endianness is None:
                raise PcapngLoadError("file does not start with a section header")

            length_raw = _read_exact(source, 4)
            length = struct.unpack(endianness + "I", length_raw)[0]
            _valid_block_length(length)
            body = _read_exact(source, length - 12)
            source.read((4 - length % 4) % 4)
            trailer = _read_exact(source, 4)
            _check_trailer(length, trailer, endianness)
            report.blocks_seen += 1

            if block_type == BLK_INTERFACE:
                if len(body) < 8:
                    raise PcapngLoadError("truncated interface description block")
                options_body, _, _ = self._sanitize_options(
                    block_type, body[8:], endianness, report
                )
                new_body = body[:8] + options_body
                interfaces += 1
                snaplens.append(_read_uint(body, 4, 4, endianness))
            elif block_type in (BLK_ENHANCED_PACKET, BLK_PACKET):
                fixed_size = 20
                if len(body) < fixed_size:
                    raise PcapngLoadError("truncated packet block")
                id_size = 4 if block_type == BLK_ENHANCED_PACKET else 2
                interface_id = _read_uint(body, 0, id_size, endianness)
                _check_interface(interface_id, interfaces, block_type)
                captured_offset = 12
                captured_len = _read_uint(body, captured_offset, 4, endianness)
                packet_end = fixed_size + _padded(captured_len)
                if packet_end > len(body):
                    raise PcapngLoadError("packet data extends beyond block")
                packet_data = body[fixed_size:fixed_size + captured_len]
                expected_packets.append((block_type, packet_data))
                options_body, _, _ = self._sanitize_options(
                    block_type, body[packet_end:], endianness, report
                )
                new_body = body[:packet_end] + options_body
            elif block_type == BLK_PACKET_SIMPLE:
                if len(body) < 4:
                    raise PcapngLoadError("truncated simple packet block")
                if interfaces < 1:
                    raise PcapngLoadError("simple packet before interface description")
                packet_len = _read_uint(body, 0, 4, endianness)
                snaplen = snaplens[0]
                captured_len = min(packet_len, snaplen) if snaplen else packet_len
                packet_end = 4 + _padded(captured_len)
                if packet_end > len(body):
                    raise PcapngLoadError("simple packet data extends beyond block")
                expected_packets.append(
                    (BLK_PACKET_SIMPLE, body[4:4 + captured_len])
                )
                new_body = body[:packet_end]
            elif block_type == BLK_INTERFACE_STATS:
                if len(body) < 12:
                    raise PcapngLoadError("truncated interface statistics block")
                interface_id = _read_uint(body, 0, 4, endianness)
                _check_interface(interface_id, interfaces, block_type)
                options_body, _, _ = self._sanitize_options(
                    block_type, body[12:], endianness, report
                )
                new_body = body[:12] + options_body
            elif block_type == BLK_NAME_RESOLUTION:
                new_body = self._sanitize_name_resolution(body, endianness, report)
            else:
                _check_reserved_block(block_type)
                item = {
                    "block_type": block_type,
                    "length": length,
                    "section": report.sections - 1,
                    "action": self.unknown_blocks,
                }
                report.unknown_blocks.append(item)
                report.actions.append(dict(item, kind="unknown_block"))
                if self.unknown_blocks == DROP:
                    continue
                new_body = body

            _write_block(destination, block_type, new_body, endianness)
            report.blocks_written += 1

        report._expected_packets = expected_packets
        return report

    def _sanitize_name_resolution(self, body, endianness, report):
        offset = 0
        records = bytearray()
        delete_records = (
            self.rules.get(BLK_NAME_RESOLUTION, {}).get(NAME_RESOLUTION_RECORDS)
            is DELETE
        )

        while True:
            if len(body) - offset < 4:
                raise PcapngLoadError("truncated name resolution record header")
            record_type, record_length = struct.unpack(
                endianness + "HH", body[offset:offset + 4]
            )
            record_end = offset + 4 + _padded(record_length)
            if record_end > len(body):
                raise PcapngLoadError("name resolution record extends beyond block")

            if record_type == 0:
                if record_length != 0:
                    raise PcapngLoadError("name resolution end record has data")
                offset = record_end
                break

            raw_record = body[offset:record_end]
            known_record = record_type in (1, 2)
            action = None
            if not known_record:
                action = self.unknown_records
                item = {
                    "record_type": record_type,
                    "length": record_length,
                    "action": action,
                }
                report.unknown_records.append(item)
                report.actions.append(dict(item, kind="unknown_name_record"))

            if (delete_records and known_record) or action == DROP:
                report.records_deleted += 1
                report.actions.append(
                    {
                        "kind": "name_record",
                        "record_type": record_type,
                        "length": record_length,
                        "action": "delete",
                    }
                )
            else:
                records.extend(raw_record)
            offset = record_end

        records.extend(struct.pack(endianness + "HH", 0, 0))
        options_body, _, _ = self._sanitize_options(
            BLK_NAME_RESOLUTION, body[offset:], endianness, report
        )
        return bytes(records) + options_body

    def _sanitize_options(self, block_type, body, endianness, report):
        result = bytearray()
        offset = 0
        changed = False

        while offset < len(body):
            if len(body) - offset < 4:
                raise PcapngLoadError("truncated option header")
            code, length = struct.unpack(endianness + "HH", body[offset:offset + 4])
            value_end = offset + 4 + _padded(length)
            if value_end > len(body):
                raise PcapngLoadError("option extends beyond block")

            if code == 0:
                if length != 0:
                    raise PcapngLoadError("option end marker has data")
                if offset + 4 != len(body):
                    raise PcapngLoadError("data follows option end marker")
                break

            raw_value = body[offset + 4:offset + 4 + length]
            action = self.rules.get(block_type, {}).get(code)
            known_option = code in _option_codes(KNOWN_BLOCKS[block_type])
            if action is None and not known_option:
                action = self.unknown_options
                item = {
                    "block_type": block_type,
                    "option_code": code,
                    "length": length,
                    "action": action,
                }
                report.unknown_options.append(item)
                report.actions.append(dict(item, kind="unknown_option"))

            if callable(action):
                context = {
                    "block_type": block_type,
                    "option_code": code,
                    "value": bytes(raw_value),
                    "endianness": endianness,
                }
                action = self._action(action(context))

            if action is REPLACE:
                action = self.default_replacement

            if action is DELETE or action is DROP:
                changed = True
                report.options_deleted += 1
                report.actions.append(
                    {
                        "kind": "option",
                        "block_type": block_type,
                        "option_code": code,
                        "length": length,
                        "action": "delete",
                    }
                )
            elif action is None or action is KEEP:
                result.extend(body[offset:value_end])
            else:
                replacement = _as_bytes(action, "option replacement")
                result.extend(struct.pack(endianness + "HH", code, len(replacement)))
                result.extend(replacement)
                result.extend(b"\x00" * ((4 - len(replacement) % 4) % 4))
                changed = True
                report.options_replaced += 1
                report.actions.append(
                    {
                        "kind": "option",
                        "block_type": block_type,
                        "option_code": code,
                        "old_length": length,
                        "new_length": len(replacement),
                        "action": "replace",
                    }
                )
            offset = value_end

        if result:
            result.extend(struct.pack(endianness + "I", 0))
        return bytes(result), changed, offset

    def _verify(self, output, report):
        scanned = list(FileScanner(output))
        packet_blocks = [
            block
            for block in scanned
            if isinstance(block, (EnhancedPacket, ObsoletePacket, SimplePacket))
        ]
        expected = report._expected_packets
        if len(packet_blocks) != len(expected):
            raise PcapngLoadError("packet count changed during sanitization")
        for block, (block_type, packet_data) in zip(packet_blocks, expected):
            magic_number = type(block).magic_number
            if magic_number != block_type or block.packet_data != packet_data:
                raise PcapngLoadError("packet payload changed during sanitization")
            report.packets_checked += 1
        return scanned


def sanitize_metadata(
    source,
    destination,
    rules=None,
    unknown_options=KEEP,
    unknown_blocks=KEEP,
    unknown_records=KEEP,
):
    """Convenience wrapper around :class:`MetadataSanitizer`."""
    sanitizer = MetadataSanitizer(
        rules=rules,
        unknown_options=unknown_options,
        unknown_blocks=unknown_blocks,
        unknown_records=unknown_records,
    )
    return sanitizer.sanitize(source, destination)


PROTECTED_OPTION_CODES = frozenset((9,))
REQUIRED_STRUCTURE_FIELDS = frozenset(
    (
        "version_major",
        "version_minor",
        "section_length",
        "link_type",
        "reserved",
        "snaplen",
        "interface_id",
        "timestamp_high",
        "timestamp_low",
        "captured_len",
        "packet_len",
        "packet_data",
        "drops_count",
        "if_tsresol",
    )
)


def _option_names(block_cls):
    if block_cls is None:
        return {}
    names = {}
    for name, field, default in getattr(block_cls, "schema", []):
        if name != "options":
            continue
        for option in field.options_schema:
            names[option.name] = option.code
        for option in (
            Option(0, "opt_endofopt"),
            Option(1, "opt_comment", "string", multiple=True),
            Option(2988, "custom_str_safe", multiple=True),
            Option(2989, "custom_bytes_safe", multiple=True),
            Option(19372, "custom_str", multiple=True),
            Option(19373, "custom_bytes", multiple=True),
        ):
            names[option.name] = option.code
    return names


def _option_codes(block_cls):
    return set(_option_names(block_cls).values())


def _block_type(key):
    if isinstance(key, int):
        if not 0 <= key <= 0xFFFFFFFF:
            raise ValueError("block type must be an unsigned 32-bit integer")
        return key
    magic = getattr(key, "magic_number", None)
    if isinstance(magic, int):
        return magic
    raise TypeError("block key must be a block type integer or block class")


def _policy(value, name):
    if value not in (KEEP, DROP):
        raise ValueError("%s must be %r or %r" % (name, KEEP, DROP))
    return value


def _as_bytes(value, name):
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("%s must be bytes or text" % name)
    if len(value) > 0xFFFF:
        raise ValueError("%s is longer than 65535 bytes" % name)
    return bytes(value)


def _read_exact(stream, size, allow_eof=False):
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            break
        data += chunk
    if len(data) == size:
        return data
    if allow_eof and not data:
        return None
    raise PcapngLoadError("unexpected end of pcapng stream")


def _valid_block_length(length):
    if length < 12:
        raise PcapngLoadError("invalid block length %s" % length)


def _check_trailer(length, trailer, endianness):
    trailing_length = struct.unpack(endianness + "I", trailer)[0]
    if trailing_length != length:
        raise PcapngLoadError("mismatching block lengths in source block")


def _padded(size):
    return size + ((4 - size % 4) % 4)


def _read_uint(data, offset, size, endianness):
    format_char = "H" if size == 2 else "I"
    return struct.unpack(endianness + format_char, data[offset:offset + size])[0]


def _check_interface(interface_id, interfaces, block_type):
    if interface_id >= interfaces:
        raise PcapngLoadError(
            "block 0x%08x references missing interface %s"
            % (block_type, interface_id)
        )


def _write_block(destination, block_type, body, endianness):
    padded_body = body + b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(padded_body)
    destination.write(struct.pack(endianness + "I", block_type))
    destination.write(struct.pack(endianness + "I", length))
    destination.write(padded_body)
    destination.write(struct.pack(endianness + "I", length))


def _check_reserved_block(block_type):
    if block_type == BLK_RESERVED:
        raise PcapngLoadError("block type 0x00000000 is reserved")
