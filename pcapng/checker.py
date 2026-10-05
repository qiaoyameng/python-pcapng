"""
Read-only pcap-ng consistency checker.

Unlike :class:`pcapng.scanner.FileScanner`, the checker validates references
between blocks without requiring a valid file to decode successfully.
"""

import struct

from pcapng._compat import namedtuple
from pcapng.constants.block_types import (
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_PACKET,
    BLK_PACKET_SIMPLE,
    BLK_SECTION_HEADER,
)
from pcapng.structs import BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_INVERSE

BLOCK_TYPE_NAMES = {
    BLK_SECTION_HEADER: "SHB",
    BLK_INTERFACE: "IDB",
    BLK_PACKET: "PB",
    BLK_PACKET_SIMPLE: "SPB",
    BLK_INTERFACE_STATS: "ISB",
    BLK_ENHANCED_PACKET: "EPB",
}

RULE_UNDEFINED_INTERFACE = "E001"
RULE_CAPTURED_EXCEEDS_PACKET = "E002"
RULE_CAPTURED_EXCEEDS_SNAPLEN = "E003"
RULE_SECTION_LENGTH_MISMATCH = "E004"
RULE_STATISTICS_TIME_RANGE = "E005"
RULE_BLOCK_LENGTH_MISMATCH = "E006"

RULE_TRUNCATED_HEADER = "S001"
RULE_INVALID_BLOCK_LENGTH = "S002"
RULE_TRUNCATED_BLOCK = "S003"
RULE_INVALID_BYTE_ORDER_MAGIC = "S004"
RULE_MISSING_SECTION_HEADER = "S005"

RULE_DESCRIPTIONS = {
    RULE_UNDEFINED_INTERFACE: "Interface ID is not defined in this section",
    RULE_CAPTURED_EXCEEDS_PACKET: "Captured length exceeds original packet length",
    RULE_CAPTURED_EXCEEDS_SNAPLEN: "Captured length exceeds interface snaplen",
    RULE_SECTION_LENGTH_MISMATCH: "Declared section length does not match section size",
    RULE_STATISTICS_TIME_RANGE: "Statistics end time is before start time",
    RULE_BLOCK_LENGTH_MISMATCH: "Trailing block length does not match leading length",
    RULE_TRUNCATED_HEADER: "Block header is truncated",
    RULE_INVALID_BLOCK_LENGTH: "Block length is invalid",
    RULE_TRUNCATED_BLOCK: "Block body is truncated",
    RULE_INVALID_BYTE_ORDER_MAGIC: "Section header byte order magic is invalid",
    RULE_MISSING_SECTION_HEADER: "File does not begin with a section header block",
}


class ConsistencyIssue(
    namedtuple(
        "ConsistencyIssue",
        ("offset", "block_type", "interface_id", "rule", "message"),
    )
):
    """A semantic or independently recoverable consistency issue."""

    __slots__ = ()

    def __new__(cls, offset, block_type, interface_id, rule, message=None):
        if message is None:
            message = RULE_DESCRIPTIONS[rule]
        return super(ConsistencyIssue, cls).__new__(
            cls, offset, block_type, interface_id, rule, message
        )

    @property
    def block_type_name(self):
        return BLOCK_TYPE_NAMES.get(self.block_type, "UNKNOWN")

    def __repr__(self):
        return (
            "ConsistencyIssue(offset={0}, block_type=0x{1:08X} ({2}), "
            "interface_id={3}, rule={4})"
        ).format(
            self.offset,
            self.block_type,
            self.block_type_name,
            self.interface_id,
            self.rule,
        )


class CheckResult(
    namedtuple(
        "CheckResultBase",
        ("issues", "stop_offset", "stop_rule", "stop_reason"),
    )
):
    """Result of :func:`check_file`.

    ``stop_rule`` and ``stop_reason`` are ``None`` when the complete stream was
    examined. Issues found before an unrecoverable boundary remain in
    ``issues``.
    """

    __slots__ = ()

    def __new__(cls, issues, stop_offset=None, stop_rule=None, stop_reason=None):
        if stop_rule is not None and stop_reason is None:
            stop_reason = RULE_DESCRIPTIONS[stop_rule]
        return super(CheckResult, cls).__new__(
            cls, tuple(issues), stop_offset, stop_rule, stop_reason
        )

    @property
    def ok(self):
        return not self.issues and self.stop_rule is None


class _Section(object):
    __slots__ = [
        "index",
        "start_offset",
        "content_start_offset",
        "length",
        "endianness",
        "interfaces",
    ]

    def __init__(self, index, start_offset, content_start_offset, length,
                 endianness):
        self.index = index
        self.start_offset = start_offset
        self.content_start_offset = content_start_offset
        self.length = length
        self.endianness = endianness
        self.interfaces = {}


def check_file(stream):
    """Check a binary pcap-ng stream without seeking or writing.

    :param stream: file-like object supporting ``read()``
    :returns: :class:`CheckResult`
    """
    issues = []
    section = None
    offset = 0
    section_index = -1

    while True:
        block_offset = offset
        type_data = _read_available(stream, 4)
        if not type_data:
            break
        if len(type_data) < 4:
            return CheckResult(
                issues,
                block_offset,
                RULE_TRUNCATED_HEADER,
                _truncated_message(4, len(type_data)),
            )

        if section is None:
            block_type = struct.unpack(">I", type_data)[0]
        else:
            block_type = struct.unpack(section.endianness + "I", type_data)[0]
        offset += 4
        is_shb = block_type == BLK_SECTION_HEADER

        if not is_shb and section is None:
            return CheckResult(
                issues,
                block_offset,
                RULE_MISSING_SECTION_HEADER,
                RULE_DESCRIPTIONS[RULE_MISSING_SECTION_HEADER],
            )

        length_data = _read_available(stream, 4)
        if len(length_data) < 4:
            return CheckResult(
                issues,
                offset,
                RULE_TRUNCATED_HEADER,
                _truncated_message(4, len(length_data)),
            )
        offset += 4

        if is_shb:
            bom_data = _read_available(stream, 4)
            if len(bom_data) < 4:
                return CheckResult(
                    issues,
                    offset,
                    RULE_TRUNCATED_HEADER,
                    _truncated_message(4, len(bom_data)),
                )
            offset += 4

            bom = struct.unpack(">I", bom_data)[0]
            if bom == BYTE_ORDER_MAGIC:
                endianness = ">"
            elif bom == BYTE_ORDER_MAGIC_INVERSE:
                endianness = "<"
            else:
                _finalize_section(section, block_offset, issues)
                return CheckResult(
                    issues,
                    block_offset + 8,
                    RULE_INVALID_BYTE_ORDER_MAGIC,
                    "Invalid section header byte order magic: 0x{0:08X}".format(
                        bom
                    ),
                )

            length = struct.unpack(endianness + "I", length_data)[0]
            if section is not None:
                _finalize_section(section, block_offset, issues)
        else:
            endianness = section.endianness
            length = struct.unpack(endianness + "I", length_data)[0]

        minimum_length = 28 if is_shb else 12
        if length < minimum_length or length % 4:
            return CheckResult(
                issues,
                block_offset + 4,
                RULE_INVALID_BLOCK_LENGTH,
                "Block length must be at least {0} bytes and aligned to 4 "
                "bytes; got {1} bytes".format(minimum_length, length),
            )

        remaining_length = length - (12 if is_shb else 8)
        body = _read_available(stream, remaining_length)
        if len(body) < remaining_length:
            return CheckResult(
                issues,
                offset + len(body),
                RULE_TRUNCATED_BLOCK,
                _truncated_message(remaining_length, len(body)),
            )
        offset += remaining_length

        trailing_length = struct.unpack(endianness + "I", body[-4:])[0]
        block_body = body[:-4]
        if is_shb:
            block_body = bom_data + block_body
        if trailing_length != length:
            issues.append(
                ConsistencyIssue(
                    block_offset,
                    block_type,
                    None,
                    RULE_BLOCK_LENGTH_MISMATCH,
                    "Leading block length is {0}, trailing length is {1}".format(
                        length, trailing_length
                    ),
                )
            )

        if is_shb:
            section_index += 1
            section = _Section(
                section_index,
                block_offset,
                offset,
                _read_section_length(block_body, endianness),
                endianness,
            )
        else:
            _check_block(
                block_type, block_body, block_offset, endianness, section, issues
            )

    _finalize_section(section, offset, issues)
    return CheckResult(issues)


def _read_section_length(body, endianness):
    if len(body) < 16:
        return None
    return struct.unpack(endianness + "q", body[8:16])[0]


def _finalize_section(section, end_offset, issues):
    if section is None or section.length is None or section.length < 0:
        return
    actual_length = end_offset - section.content_start_offset
    if section.length != actual_length:
        issues.append(
            ConsistencyIssue(
                section.start_offset,
                BLK_SECTION_HEADER,
                None,
                RULE_SECTION_LENGTH_MISMATCH,
                "Declared section length is {0} bytes, actual length is "
                "{1} bytes".format(section.length, actual_length),
            )
        )


def _check_block(block_type, body, offset, endianness, section, issues):
    if block_type == BLK_INTERFACE:
        interface_id = len(section.interfaces)
        snaplen = None
        if len(body) >= 8:
            snaplen = struct.unpack(endianness + "I", body[4:8])[0]
        section.interfaces[interface_id] = snaplen
        return

    if block_type == BLK_ENHANCED_PACKET:
        if len(body) < 20:
            return
        interface_id, _, _, captured_len, packet_len = struct.unpack(
            endianness + "IIIII", body[:20]
        )
        _check_packet_lengths(
            offset, block_type, interface_id, captured_len, packet_len, section,
            issues,
        )
        return

    if block_type == BLK_PACKET:
        if len(body) < 20:
            return
        interface_id, _, _, _, captured_len, packet_len = struct.unpack(
            endianness + "HHIIII", body[:20]
        )
        _check_packet_lengths(
            offset, block_type, interface_id, captured_len, packet_len, section,
            issues,
        )
        return

    if block_type == BLK_PACKET_SIMPLE:
        interface_id = 0
        if interface_id not in section.interfaces:
            _undefined_interface(offset, block_type, interface_id, issues)
            return
        if len(body) < 4:
            return
        packet_len = struct.unpack(endianness + "I", body[:4])[0]
        snaplen = section.interfaces[interface_id]
        if len(body) > 4 + _pad4(packet_len):
            issues.append(
                ConsistencyIssue(
                    offset,
                    block_type,
                    interface_id,
                    RULE_CAPTURED_EXCEEDS_PACKET,
                    "Packet data length exceeds original packet length {0}".format(
                        packet_len
                    ),
                )
            )
        if snaplen not in (None, 0) and len(body) > 4 + _pad4(snaplen):
            issues.append(
                ConsistencyIssue(
                    offset,
                    block_type,
                    interface_id,
                    RULE_CAPTURED_EXCEEDS_SNAPLEN,
                    "Packet data length exceeds interface snaplen {0}".format(
                        snaplen
                    ),
                )
            )
        return

    if block_type == BLK_INTERFACE_STATS:
        if len(body) < 12:
            return
        interface_id = struct.unpack(endianness + "I", body[:4])[0]
        if interface_id not in section.interfaces:
            _undefined_interface(offset, block_type, interface_id, issues)
        starttime, endtime = _statistics_times(body[12:], endianness)
        if starttime is not None and endtime is not None and endtime < starttime:
            issues.append(
                ConsistencyIssue(
                    offset,
                    block_type,
                    interface_id,
                    RULE_STATISTICS_TIME_RANGE,
                    "Statistics end time {0} is before start time {1}".format(
                        endtime, starttime
                    ),
                )
            )


def _check_packet_lengths(
    offset, block_type, interface_id, captured_len, packet_len, section, issues
):
    defined = interface_id in section.interfaces
    if not defined:
        _undefined_interface(offset, block_type, interface_id, issues)
    if captured_len > packet_len:
        issues.append(
            ConsistencyIssue(
                offset,
                block_type,
                interface_id,
                RULE_CAPTURED_EXCEEDS_PACKET,
                _length_message(captured_len, packet_len),
            )
        )
    if defined:
        snaplen = section.interfaces[interface_id]
        if snaplen not in (None, 0) and captured_len > snaplen:
            issues.append(
                ConsistencyIssue(
                    offset,
                    block_type,
                    interface_id,
                    RULE_CAPTURED_EXCEEDS_SNAPLEN,
                    _length_message(captured_len, snaplen),
                )
            )


def _undefined_interface(offset, block_type, interface_id, issues):
    issues.append(
        ConsistencyIssue(
            offset,
            block_type,
            interface_id,
            RULE_UNDEFINED_INTERFACE,
            "Interface ID {0} is not defined before this block".format(interface_id),
        )
    )


def _statistics_times(options, endianness):
    values = {}
    position = 0
    while position + 4 <= len(options):
        code, length = struct.unpack(
            endianness + "HH", options[position:position + 4]
        )
        if code == 0:
            break
        value_start = position + 4
        value_end = value_start + length
        if value_end > len(options):
            break
        if code in (2, 3) and length == 8:
            values[code] = struct.unpack(
                endianness + "Q", options[value_start:value_end]
            )[0]
        position = value_end + (_pad4(length) - length)
    return values.get(2), values.get(3)


def _pad4(length):
    return (length + 3) // 4 * 4


def _length_message(actual, limit):
    return "Length {0} exceeds limit {1}".format(actual, limit)


def _read_available(stream, size):
    if size == 0:
        return b""
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _truncated_message(expected, actual):
    return "Expected {0} bytes, only got {1} before end of stream".format(
        expected, actual
    )
