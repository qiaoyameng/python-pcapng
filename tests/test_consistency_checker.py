import io
import struct

from pcapng.checker import check_pcapng
from pcapng.constants.block_types import (
    BLK_ARINC429,
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_IRIG_TIMESTAMP,
    BLK_PACKET_SIMPLE,
    BLK_SECTION_HEADER,
)

SHB_LENGTH = 28
IDB_LENGTH = 20


def block(block_type, body, endianness=">"):
    length = len(body) + 12
    return (
        struct.pack(endianness + "II", block_type, length)
        + body
        + struct.pack(endianness + "I", length)
    )


def section_header(section_length=-1, endianness=">"):
    body = struct.pack(
        endianness + "IHHq",
        0x1A2B3C4D if endianness == ">" else 0x4D3C2B1A,
        1,
        0,
        section_length,
    )
    return block(BLK_SECTION_HEADER, body, endianness)


def interface_description(snaplen=0, link_type=1):
    return block(
        BLK_INTERFACE,
        struct.pack(">HHI", link_type, 0, snaplen),
    )


def enhanced_packet(interface_id=0, captured_len=0, packet_len=0,
                    packet_data=b"", endianness=">"):
    body = struct.pack(
        endianness + "IIIII",
        interface_id,
        0,
        0,
        captured_len,
        packet_len,
    ) + packet_data
    padding = b"\x00" * ((-len(body)) % 4)
    return block(BLK_ENHANCED_PACKET, body + padding, endianness)


def simple_packet(packet_len, data=None):
    data = b"x" * packet_len if data is None else data
    body = struct.pack(">I", packet_len) + data
    body += b"\x00" * ((-len(body)) % 4)
    return block(BLK_PACKET_SIMPLE, body)


def interface_statistics(start=None, end=None, interface_id=0):
    body = struct.pack(">III", interface_id, 0, 0)
    if start is not None:
        body += struct.pack(">HHQ", 2, 8, start)
    if end is not None:
        body += struct.pack(">HHQ", 3, 8, end)
    body += struct.pack(">I", 0)
    return block(BLK_INTERFACE_STATS, body)


def rule_tuples(report):
    return [
        (
            item.offset,
            item.block_type,
            item.section_id,
            item.interface_id,
            item.rule,
        )
        for item in report.findings
    ]


def test_reports_undefined_interface_and_captured_length_errors():
    bad_packet_offset = SHB_LENGTH + IDB_LENGTH
    data = (
        section_header()
        + interface_description(snaplen=10)
        + enhanced_packet(
            interface_id=1,
            captured_len=12,
            packet_len=10,
            packet_data=b"abcdefghijkl",
        )
    )

    report = check_pcapng(data)

    assert not report.stopped
    assert (
        bad_packet_offset,
        BLK_ENHANCED_PACKET,
        0,
        1,
        "R101",
    ) in rule_tuples(report)
    assert (
        bad_packet_offset,
        BLK_ENHANCED_PACKET,
        0,
        1,
        "R201",
    ) in rule_tuples(report)
    assert not any(rule == "R202" for *_, rule in rule_tuples(report))


def test_interface_identifiers_are_scoped_to_each_section():
    first_packet_offset = SHB_LENGTH + IDB_LENGTH
    second_section_offset = first_packet_offset + IDB_LENGTH + 32
    data = (
        section_header()
        + interface_description(snaplen=10)
        + enhanced_packet(captured_len=11, packet_len=11, packet_data=b"x" * 11)
        + section_header()
        + interface_description(snaplen=0)
        + enhanced_packet(captured_len=11, packet_len=11, packet_data=b"x" * 11)
    )

    report = check_pcapng(data)

    assert second_section_offset == 100
    assert not report.stopped
    assert rule_tuples(report) == [
        (first_packet_offset, BLK_ENHANCED_PACKET, 0, 0, "R202")
    ]
    assert report.findings[0].section_id == 0


def test_interface_must_be_defined_before_reference():
    packet_offset = SHB_LENGTH
    data = (
        section_header()
        + enhanced_packet(interface_id=0)
        + interface_description()
    )

    report = check_pcapng(data)

    assert (
        packet_offset,
        BLK_ENHANCED_PACKET,
        0,
        0,
        "R101",
    ) in rule_tuples(report)


def test_reports_statistics_time_range_inversion():
    stats_offset = SHB_LENGTH + IDB_LENGTH
    data = (
        section_header()
        + interface_description()
        + interface_statistics(start=20, end=10)
    )

    report = check_pcapng(data)

    assert rule_tuples(report) == [
        (stats_offset, BLK_INTERFACE_STATS, 0, 0, "R401")
    ]


def test_reports_section_length_mismatch_excluding_section_header():
    following_length = IDB_LENGTH
    data = (
        section_header(section_length=following_length + 1)
        + interface_description()
    )

    report = check_pcapng(data)

    assert not report.stopped
    assert rule_tuples(report) == [
        (0, BLK_SECTION_HEADER, 0, None, "R301")
    ]
    assert str(following_length) in report.findings[0].message


def test_continues_after_independent_recoverable_errors():
    bad_packet_offset = SHB_LENGTH + IDB_LENGTH
    unknown_offset = bad_packet_offset + 32
    data = (
        section_header()
        + interface_description(snaplen=10)
        + enhanced_packet(
            captured_len=12,
            packet_len=10,
            packet_data=b"abcdefghijkl",
        )
        + block(0x40000001, b"ext-")
    )

    report = check_pcapng(data)

    assert not report.stopped
    assert unknown_offset == 80
    assert rule_tuples(report) == [
        (bad_packet_offset, BLK_ENHANCED_PACKET, 0, 0, "R201"),
        (bad_packet_offset, BLK_ENHANCED_PACKET, 0, 0, "R202"),
    ]


def test_unknown_extension_blocks_and_zero_snaplen_are_accepted():
    data = (
        section_header()
        + interface_description(snaplen=0)
        + enhanced_packet(captured_len=5, packet_len=5, packet_data=b"abcde")
        + simple_packet(5)
        + block(BLK_IRIG_TIMESTAMP, b"irig")
        + block(BLK_ARINC429, b"afdx")
        + block(0x80000001, b"priv")
    )

    report = check_pcapng(data)

    assert report.findings == ()
    assert not report.stopped


def test_truncated_declared_block_stops_at_reliable_boundary():
    block_offset = SHB_LENGTH
    data = (
        section_header()
        + enhanced_packet(captured_len=4, packet_len=4, packet_data=b"abcd")[:-8]
    )

    report = check_pcapng(data)

    assert report.stopped
    assert report.stop_offset == block_offset
    assert rule_tuples(report) == [
        (block_offset, BLK_ENHANCED_PACKET, 0, None, "R004")
    ]


def test_mismatched_trailing_length_stops_with_boundary_reason():
    packet_offset = SHB_LENGTH
    valid_packet = enhanced_packet(captured_len=4, packet_len=4, packet_data=b"abcd")
    data = section_header() + valid_packet[:-4] + struct.pack(">I", 0)

    report = check_pcapng(data)

    assert report.stopped
    assert report.stop_offset == packet_offset + len(valid_packet) - 4
    assert rule_tuples(report) == [
        (report.stop_offset, BLK_ENHANCED_PACKET, 0, None, "R005")
    ]


def test_invalid_section_header_magic_stops_without_a_section():
    data = block(BLK_SECTION_HEADER, b"\x00\x00\x00\x00")

    report = check_pcapng(data)

    assert report.stopped
    assert rule_tuples(report) == [
        (0, BLK_SECTION_HEADER, None, None, "R006")
    ]


def test_check_preserves_stream_position_and_applies_base_offset():
    payload = (
        section_header()
        + interface_description()
        + enhanced_packet(interface_id=1)
    )
    stream = io.BytesIO(b"prefix" + payload)
    stream.seek(6)

    report = check_pcapng(stream, base_offset=100)

    assert stream.tell() == 6
    expected_offset = 100 + 6 + SHB_LENGTH + IDB_LENGTH
    assert rule_tuples(report) == [
        (expected_offset, BLK_ENHANCED_PACKET, 0, 1, "R101")
    ]
