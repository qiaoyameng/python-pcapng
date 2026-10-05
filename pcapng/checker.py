"""Read-only consistency checks for pcapng files.

Rule identifiers:
R001/R003/R004/R005/R006 describe unrecoverable block-boundary failures.
R101 is an undefined interface, R103 a reserved block type, and R104 an
invalid known block body. R201-R203 describe packet-length inconsistencies,
R301 a section-length mismatch, and R401 an inverted statistics interval.
"""

import struct

from pcapng._compat import namedtuple
from pcapng.constants.block_types import (
    BLK_ARINC429,
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_IRIG_TIMESTAMP,
    BLK_PACKET,
    BLK_PACKET_SIMPLE,
    BLK_RESERVED,
    BLK_SECTION_HEADER,
)
from pcapng.structs import BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_INVERSE

ConsistencyFinding = namedtuple(
    "ConsistencyFinding",
    ("offset", "block_type", "interface_id", "rule", "message", "section_id"),
    defaults=(None, None),
)

ConsistencyReport = namedtuple(
    "ConsistencyReport",
    ("findings", "stopped", "stop_offset", "stop_reason"),
    defaults=(False, None, None),
)


class ConsistencyChecker(object):
    """Validate block references while preserving recoverable errors."""

    __slots__ = ("data", "base_offset", "findings", "stopped", "stop_offset",
                 "stop_reason", "pos", "endianness", "section_index",
                 "section_start", "section_header_length", "section_length",
                 "interface_count", "interfaces")

    def __init__(self, source, base_offset=0):
        self.data, stream_offset = self._read_source(source)
        self.base_offset = base_offset
        if stream_offset is not None:
            self.base_offset += stream_offset
        self.findings = []
        self.stopped = False
        self.stop_offset = None
        self.stop_reason = None
        self.pos = 0
        self.endianness = None
        self.section_index = None
        self.section_start = None
        self.section_header_length = None
        self.section_length = None
        self.interface_count = 0
        self.interfaces = {}

    def check(self):
        """Run the consistency check and return a ConsistencyReport."""

        if not self.data:
            self._finding(0, None, None, "R001", "empty file")
            return self._stop(0, "empty file")

        while self.pos < len(self.data):
            block_offset = self.pos
            if len(self.data) - block_offset < 8:
                self._finding(block_offset, None, None, "R001",
                              "incomplete block header")
                self._stop(block_offset, "incomplete block header")
                break

            block_type = struct.unpack_from(">I", self.data, block_offset)[0]
            if block_type == BLK_SECTION_HEADER:
                self._finish_section(block_offset)
                if self.stopped:
                    break
                self._read_section_header(block_offset)
            else:
                self._read_generic_block(block_offset, block_type)

            if self.stopped:
                break

        if not self.stopped:
            self._finish_section(len(self.data))

        return ConsistencyReport(
            tuple(self.findings),
            self.stopped,
            None if self.stop_offset is None else self.base_offset + self.stop_offset,
            self.stop_reason,
        )

    @staticmethod
    def _read_source(source):
        if isinstance(source, (bytes, bytearray, memoryview)):
            return bytes(source), None
        if hasattr(source, "read"):
            stream_offset = None
            if hasattr(source, "tell"):
                try:
                    stream_offset = source.tell()
                except (OSError, ValueError):
                    stream_offset = None
            data = source.read()
            if stream_offset is not None and hasattr(source, "seek"):
                try:
                    source.seek(stream_offset)
                except (OSError, ValueError):
                    pass
            return data, stream_offset
        raise TypeError("source must be bytes-like or a binary file-like object")

    def _read_section_header(self, offset):
        bom = struct.unpack_from(">I", self.data, offset + 8)[0]
        if bom == BYTE_ORDER_MAGIC:
            endianness = ">"
        elif bom == BYTE_ORDER_MAGIC_INVERSE:
            endianness = "<"
        else:
            self._finding(
                offset,
                BLK_SECTION_HEADER,
                None,
                "R006",
                "invalid section header byte-order magic",
                None,
            )
            return self._stop(
                offset,
                "invalid section header byte-order magic at byte 8",
            )
        self.section_index = (
            0 if self.section_index is None else self.section_index + 1
        )

        block_length = self._uint32(offset + 4, endianness)
        if block_length < 28:
            self._finding(offset, BLK_SECTION_HEADER, None, "R104",
                          "section header body is shorter than 16 bytes")
        if not self._validate_frame(offset, block_length, endianness,
                                    BLK_SECTION_HEADER):
            return

        section_length = None
        if block_length >= 28:
            section_length = struct.unpack_from(
                endianness + "q", self.data, offset + 16
            )[0]
            if section_length < -1:
                self._finding(offset, BLK_SECTION_HEADER, None, "R301",
                              "section length has an invalid negative value")
                section_length = None

        self.pos = offset + block_length
        self.endianness = endianness
        self.section_start = offset
        self.section_header_length = block_length
        self.section_length = section_length
        self.interface_count = 0
        self.interfaces = {}

    def _read_generic_block(self, offset, block_type):
        if self.endianness is None:
            self._finding(offset, block_type, None, "R006",
                          "block appears before a section header")
            return self._stop(offset, "block before a section header")

        block_length = self._uint32(offset + 4, self.endianness)
        if not self._validate_frame(
            offset, block_length, self.endianness, block_type
        ):
            return

        body = self.data[offset + 8:offset + block_length - 4]
        self.pos = offset + block_length

        if block_type == BLK_RESERVED or self._is_corruption_marker(block_type):
            self._finding(offset, block_type, None, "R103",
                          "reserved block type must not occur in a capture file")
        elif block_type == BLK_INTERFACE:
            self._check_interface_description(offset, body)
        elif block_type == BLK_PACKET_SIMPLE:
            self._check_simple_packet(offset, body)
        elif block_type in (BLK_ENHANCED_PACKET, BLK_PACKET):
            self._check_packet(offset, block_type, body)
        elif block_type == BLK_INTERFACE_STATS:
            self._check_interface_statistics(offset, body)
        elif block_type in (BLK_IRIG_TIMESTAMP, BLK_ARINC429):
            return

    def _check_interface_description(self, offset, body):
        interface_id = self.interface_count
        self.interface_count += 1
        snaplen = None
        if len(body) < 8:
            self._finding(offset, BLK_INTERFACE, interface_id, "R104",
                          "interface description body is shorter than 8 bytes")
        else:
            snaplen = struct.unpack_from(self.endianness + "I", body, 4)[0]
        self.interfaces[interface_id] = snaplen

    def _check_simple_packet(self, offset, body):
        if not self._interface_defined(offset, BLK_PACKET_SIMPLE, 0):
            return
        if not body:
            self._finding(offset, BLK_PACKET_SIMPLE, 0, "R104",
                          "simple packet body is shorter than 4 bytes")
            return

        packet_len = struct.unpack_from(self.endianness + "I", body, 0)[0]
        snaplen = self.interfaces.get(0)
        expected_len = (
            packet_len if snaplen in (None, 0) else min(snaplen, packet_len)
        )
        actual_len = len(body) - 4
        padded_expected_len = (expected_len + 3) & ~3
        if actual_len != padded_expected_len:
            self._finding(
                offset,
                BLK_PACKET_SIMPLE,
                0,
                "R203",
                "simple packet data field length is {0}, expected {1}".format(
                    actual_len, padded_expected_len
                ),
            )

    def _check_packet(self, offset, block_type, body):
        minimum_header = 20
        if len(body) < minimum_header:
            interface_id = self._packet_interface_id(block_type, body)
            if interface_id is not None:
                self._interface_defined(offset, block_type, interface_id)
            self._finding(offset, block_type, interface_id, "R104",
                          "packet block body is shorter than 20 bytes")
            return

        interface_id = self._packet_interface_id(block_type, body)
        interface_defined = self._interface_defined(
            offset, block_type, interface_id
        )

        captured_len = struct.unpack_from(self.endianness + "I", body, 12)[0]
        packet_len = struct.unpack_from(self.endianness + "I", body, 16)[0]
        if captured_len > packet_len:
            self._finding(
                offset,
                block_type,
                interface_id,
                "R201",
                "captured length {0} exceeds packet length {1}".format(
                    captured_len, packet_len
                ),
            )

        if interface_defined:
            snaplen = self.interfaces.get(interface_id)
            if snaplen and captured_len > snaplen:
                self._finding(
                    offset,
                    block_type,
                    interface_id,
                    "R202",
                    "captured length {0} exceeds interface snaplen {1}".format(
                        captured_len, snaplen
                    ),
                )

        available = len(body) - minimum_header
        padded_captured_len = (captured_len + 3) & ~3
        if padded_captured_len > available:
            self._finding(
                offset,
                block_type,
                interface_id,
                "R203",
                "captured length {0} (padded to {1}) exceeds {2} packet-data "
                "bytes in block".format(captured_len, padded_captured_len,
                                        available),
            )

    def _check_interface_statistics(self, offset, body):
        if len(body) < 4:
            self._finding(offset, BLK_INTERFACE_STATS, None, "R104",
                          "interface statistics body is shorter than 4 bytes")
            return

        interface_id = struct.unpack_from(self.endianness + "I", body, 0)[0]
        self._interface_defined(offset, BLK_INTERFACE_STATS, interface_id)
        if len(body) < 12:
            self._finding(offset, BLK_INTERFACE_STATS, interface_id, "R104",
                          "interface statistics body is shorter than 12 bytes")
            return

        options_ok, start_time, end_time = self._read_statistics_options(body[12:])
        if not options_ok:
            self._finding(offset, BLK_INTERFACE_STATS, interface_id, "R104",
                          "malformed interface statistics options")
        if start_time is not None and end_time is not None and end_time < start_time:
            self._finding(
                offset,
                BLK_INTERFACE_STATS,
                interface_id,
                "R401",
                "statistics end timestamp {0} is earlier than start {1}".format(
                    end_time, start_time
                ),
            )

    def _read_statistics_options(self, data):
        pos = 0
        start_time = None
        end_time = None
        ended = False
        while pos < len(data):
            if ended:
                return False, start_time, end_time
            if len(data) - pos < 4:
                return False, start_time, end_time
            code, length = struct.unpack_from(self.endianness + "HH", data, pos)
            pos += 4
            padded_length = (length + 3) & ~3
            if code == 0:
                if length != 0 or padded_length > len(data) - pos:
                    return False, start_time, end_time
                ended = True
                pos += padded_length
                continue
            if padded_length > len(data) - pos:
                return False, start_time, end_time
            if code in (2, 3) and length == 8:
                value = struct.unpack_from(
                    self.endianness + "Q", data, pos
                )[0]
                if code == 2 and start_time is None:
                    start_time = value
                elif code == 3 and end_time is None:
                    end_time = value
            pos += padded_length
        return True, start_time, end_time

    def _packet_interface_id(self, block_type, body):
        if not body:
            return None
        if block_type == BLK_PACKET:
            return struct.unpack_from(self.endianness + "H", body, 0)[0]
        return struct.unpack_from(self.endianness + "I", body, 0)[0]

    def _interface_defined(self, offset, block_type, interface_id):
        if interface_id is None or interface_id not in self.interfaces:
            self._finding(
                offset,
                block_type,
                interface_id,
                "R101",
                "interface {0} is not defined in section {1}".format(
                    interface_id, self.section_index
                ),
            )
            return False
        return True

    def _validate_frame(self, offset, block_length, endianness, block_type):
        if block_length < 12:
            self._finding(offset, block_type, None, "R003",
                          "declared block length is smaller than 12 bytes")
            self._stop(
                offset,
                "declared block length {0} is smaller than the 12-byte frame".format(
                    block_length
                ),
            )
            return False
        if block_length % 4 != 0:
            self._finding(offset, block_type, None, "R003",
                          "declared block length is not aligned to 4 bytes")
            self._stop(
                offset,
                "declared block length {0} is not aligned to 4 bytes".format(
                    block_length
                ),
            )
            return False
        if offset + block_length > len(self.data):
            self._finding(offset, block_type, None, "R004",
                          "declared block extends beyond end of input")
            self._stop(
                offset,
                "declared block length {0} extends beyond end of input".format(
                    block_length
                ),
            )
            return False
        trailing_length = self._uint32(offset + block_length - 4, endianness)
        if trailing_length != block_length:
            self._finding(offset + block_length - 4, block_type, None, "R005",
                          "leading and trailing block lengths do not match")
            self._stop(
                offset + block_length - 4,
                "trailing block length {0} does not match leading length {1}".format(
                    trailing_length, block_length
                ),
            )
            return False
        return True

    def _finish_section(self, section_end):
        if self.section_start is None:
            return
        section_body_start = self.section_start + self.section_header_length
        following_length = section_end - section_body_start
        if self.section_length >= 0 and self.section_length != following_length:
            self._finding(
                self.section_start,
                BLK_SECTION_HEADER,
                None,
                "R301",
                "declared section length {0} does not match {1} bytes following "
                "the section header".format(self.section_length, following_length),
            )
        self.section_start = None
        self.section_header_length = None
        self.section_length = None
        self.interface_count = 0
        self.interfaces = {}

    @staticmethod
    def _is_corruption_marker(block_type):
        if (block_type >> 8) in (0x0A0D0A, 0x0D0D0A):
            return True
        return (block_type & 0xFFFFFF) in (0x0A0D0A, 0x0A0D0D)

    def _uint32(self, offset, endianness):
        return struct.unpack_from(endianness + "I", self.data, offset)[0]

    def _finding(self, offset, block_type, interface_id, rule, message,
                 section_id="__unset__"):
        if section_id == "__unset__":
            section_id = self.section_index
        self.findings.append(
            ConsistencyFinding(
                self.base_offset + offset,
                block_type,
                interface_id,
                rule,
                message,
                section_id,
            )
        )

    def _stop(self, offset, reason):
        self.stop_offset = offset
        self.stop_reason = reason
        self.stopped = True


def check_pcapng(source, base_offset=0):
    """Check a bytes-like value or binary stream without modifying it."""

    return ConsistencyChecker(source, base_offset).check()
