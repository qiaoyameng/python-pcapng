import io
import struct

import pytest

from pcapng.checker import (
    RULE_BLOCK_LENGTH_MISMATCH,
    RULE_CAPTURED_EXCEEDS_PACKET,
    RULE_CAPTURED_EXCEEDS_SNAPLEN,
    RULE_INVALID_BLOCK_LENGTH,
    RULE_MISSING_SECTION_HEADER,
    RULE_SECTION_LENGTH_MISMATCH,
    RULE_STATISTICS_TIME_RANGE,
    RULE_TRUNCATED_BLOCK,
    RULE_UNDEFINED_INTERFACE,
    check_file,
)
from pcapng.scanner import FileScanner
from pcapng.structs import BYTE_ORDER_MAGIC

BLK_SHB = 0x0A0D0D0A
BLK_IDB = 0x00000001
BLK_PB = 0x00000002
BLK_SPB = 0x00000003
BLK_ISB = 0x00000005
BLK_EPB = 0x00000006
BLK_IRIG_TIMESTAMP = 0x00000007
BLK_ARINC429 = 0x00000008


def pad4(data):
    return data + b"\x00" * ((-len(data)) % 4)


def block(block_type, payload=b"", endianness=">", trailing_length=None):
    total_length = 12 + len(pad4(payload))
    if trailing_length is None:
        trailing_length = total_length
    return (
        struct.pack(endianness + "I", block_type)
        + struct.pack(endianness + "I", total_length)
        + pad4(payload)
        + struct.pack(endianness + "I", trailing_length)
    )


def section_header(section_length=-1, endianness=">"):
    payload = (
        struct.pack(endianness + "I", BYTE_ORDER_MAGIC)
        + struct.pack(endianness + "HH", 1, 0)
        + struct.pack(endianness + "q", section_length)
        + struct.pack(endianness + "HH", 0, 0)
    )
    return block(BLK_SHB, payload, endianness)


def interface_description(snaplen=0, endianness=">"):
    payload = (
        struct.pack(endianness + "HHI", 1, 0, snaplen)
        + struct.pack(endianness + "HH", 0, 0)
    )
    return block(BLK_IDB, payload, endianness)


def enhanced_packet(
    interface_id,
    captured_len,
    packet_len,
    packet_data=b"",
    endianness=">",
):
    payload = (
        struct.pack(
            endianness + "IIIII",
            interface_id,
            0,
            0,
            captured_len,
            packet_len,
        )
        + pad4(packet_data)
        + struct.pack(endianness + "HH", 0, 0)
    )
    return block(BLK_EPB, payload, endianness)


def simple_packet(packet_len, packet_data, endianness=">"):
    payload = struct.pack(endianness + "I", packet_len) + packet_data
    return block(BLK_SPB, payload, endianness)


def obsolete_packet(
    interface_id,
    captured_len,
    packet_len,
    packet_data=b"",
    endianness=">",
):
    payload = (
        struct.pack(
            endianness + "HHIIII",
            interface_id,
            0,
            0,
            0,
            captured_len,
            packet_len,
        )
        + pad4(packet_data)
        + struct.pack(endianness + "HH", 0, 0)
    )
    return block(BLK_PB, payload, endianness)


def interface_stats(interface_id, starttime, endtime, endianness=">"):
    payload = (
        struct.pack(endianness + "III", interface_id, 0, 0)
        + struct.pack(endianness + "HHQ", 2, 8, starttime)
        + struct.pack(endianness + "HHQ", 3, 8, endtime)
        + struct.pack(endianness + "HH", 0, 0)
    )
    return block(BLK_ISB, payload, endianness)


@pytest.mark.parametrize("endianness", [">", "<"])
def test_reports_independent_reference_errors_with_offsets_and_sources(endianness):
    data = b"".join(
        [
            section_header(endianness=endianness),
            interface_description(4, endianness),
            enhanced_packet(9, 6, 5, b"123456", endianness),
            enhanced_packet(0, 5, 4, b"12345", endianness),
            interface_stats(3, 10, 9, endianness),
            section_header(1000, endianness),
            interface_description(4, endianness),
            enhanced_packet(0, 2, 2, b"ab", endianness),
        ]
    )

    result = check_file(io.BytesIO(data))

    assert result.stop_rule is None
    assert [
        (issue.offset, issue.block_type, issue.interface_id, issue.rule)
        for issue in result.issues
    ] == [
        (56, BLK_EPB, 9, RULE_UNDEFINED_INTERFACE),
        (56, BLK_EPB, 9, RULE_CAPTURED_EXCEEDS_PACKET),
        (100, BLK_EPB, 0, RULE_CAPTURED_EXCEEDS_PACKET),
        (100, BLK_EPB, 0, RULE_CAPTURED_EXCEEDS_SNAPLEN),
        (144, BLK_ISB, 3, RULE_UNDEFINED_INTERFACE),
        (144, BLK_ISB, 3, RULE_STATISTICS_TIME_RANGE),
        (196, BLK_SHB, None, RULE_SECTION_LENGTH_MISMATCH),
    ]


@pytest.mark.parametrize("endianness", [">", "<"])
def test_unknown_extension_blocks_and_zero_snaplen_are_valid(endianness):
    packet_data = bytes(bytearray(range(100)))
    data = b"".join(
        [
            section_header(endianness=endianness),
            interface_description(0, endianness),
            enhanced_packet(0, 100, 100, packet_data, endianness),
            simple_packet(100, packet_data, endianness),
            block(BLK_IRIG_TIMESTAMP, b"extension", endianness),
            block(BLK_ARINC429, b"extension", endianness),
        ]
    )

    result = check_file(io.BytesIO(data))

    assert result == ((), None, None, None)
    assert len(list(FileScanner(io.BytesIO(data)))) == 6


@pytest.mark.parametrize("endianness", [">", "<"])
def test_obsolete_packet_lengths_are_checked(endianness):
    data = b"".join(
        [
            section_header(endianness=endianness),
            interface_description(4, endianness),
            obsolete_packet(7, 3, 2, b"abc", endianness),
            obsolete_packet(0, 5, 6, b"abcde", endianness),
        ]
    )

    result = check_file(io.BytesIO(data))

    assert [
        (issue.offset, issue.block_type, issue.interface_id, issue.rule)
        for issue in result.issues
    ] == [
        (56, BLK_PB, 7, RULE_UNDEFINED_INTERFACE),
        (56, BLK_PB, 7, RULE_CAPTURED_EXCEEDS_PACKET),
        (96, BLK_PB, 0, RULE_CAPTURED_EXCEEDS_SNAPLEN),
    ]


@pytest.mark.parametrize("endianness", [">", "<"])
def test_simple_packet_lengths_are_checked(endianness):
    data = b"".join(
        [
            section_header(endianness=endianness),
            interface_description(0, endianness),
            simple_packet(4, b"abcdef", endianness),
            section_header(endianness=endianness),
            interface_description(4, endianness),
            simple_packet(8, b"abcdef", endianness),
        ]
    )

    result = check_file(io.BytesIO(data))

    assert [
        (issue.offset, issue.block_type, issue.interface_id, issue.rule)
        for issue in result.issues
    ] == [
        (56, BLK_SPB, 0, RULE_CAPTURED_EXCEEDS_PACKET),
        (136, BLK_SPB, 0, RULE_CAPTURED_EXCEEDS_SNAPLEN),
    ]


@pytest.mark.parametrize("endianness", [">", "<"])
def test_declared_section_length_excluding_shb_is_accepted(endianness):
    data = b"".join(
        [
            section_header(24, endianness),
            interface_description(0, endianness),
        ]
    )

    result = check_file(io.BytesIO(data))

    assert result == ((), None, None, None)


def test_trailing_block_length_mismatch_is_independent_and_scanning_continues():
    bad_unknown = block(BLK_IRIG_TIMESTAMP, b"abcd", trailing_length=20)
    data = section_header() + bad_unknown + block(BLK_ARINC429, b"abcd")

    result = check_file(io.BytesIO(data))

    assert result.stop_rule is None
    assert [
        (issue.offset, issue.block_type, issue.rule)
        for issue in result.issues
    ] == [(32, BLK_IRIG_TIMESTAMP, RULE_BLOCK_LENGTH_MISMATCH)]


def test_truncated_block_stops_with_boundary_reason_but_keeps_issues():
    truncated = (
        struct.pack(">II", BLK_IRIG_TIMESTAMP, 100)
        + b"only eight bytes"
    )
    data = section_header() + truncated

    result = check_file(io.BytesIO(data))

    assert result.stop_offset == 56
    assert result.stop_rule == RULE_TRUNCATED_BLOCK
    assert "Expected 92 bytes" in result.stop_reason
    assert list(result.issues) == []


def test_invalid_block_length_stops_before_using_it_as_next_boundary():
    data = section_header() + struct.pack(">II", BLK_IRIG_TIMESTAMP, 13)

    result = check_file(io.BytesIO(data))

    assert result.stop_offset == 36
    assert result.stop_rule == RULE_INVALID_BLOCK_LENGTH
    assert "aligned to 4 bytes" in result.stop_reason


def test_file_without_section_header_stops_at_start():
    result = check_file(io.BytesIO(block(BLK_IRIG_TIMESTAMP, b"abcd")))

    assert result.stop_offset == 0
    assert result.stop_rule == RULE_MISSING_SECTION_HEADER
