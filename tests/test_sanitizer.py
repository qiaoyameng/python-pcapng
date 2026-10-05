import io
import struct

import pytest

from pcapng import (
    DELETE,
    DROP,
    FileScanner,
    FileWriter,
    KEEP,
    MetadataSanitizer,
    REPLACE,
    blocks as block_classes,
    sanitize_metadata,
)
from pcapng.constants.block_types import (
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_INTERFACE_STATS,
    BLK_NAME_RESOLUTION,
    BLK_PACKET_SIMPLE,
    BLK_SECTION_HEADER,
)
from pcapng.blocks import UnknownBlock
from pcapng.exceptions import PcapngStrictnessWarning
from pcapng.strictness import Strictness, set_strictness


def _section_payloads(
    endianness,
    include_name_resolution=False,
    include_simple_packet=False,
):
    section_header = block_classes.SectionHeader(
        endianness=endianness,
        options={
            "shb_hardware": "capturer hardware",
            "shb_os": "secret operating system",
            "opt_comment": "section comment",
        },
    )
    interface = section_header.new_member(
        block_classes.InterfaceDescription,
        link_type=1 if endianness == "<" else 101,
        snaplen=65535 if endianness == "<" else 128,
        options={
            "if_name": "host-interface",
            "if_description": "host interface description",
            "if_os": "interface operating system",
            "if_tsresol": b"\x06" if endianness == "<" else b"\x09",
            "if_speed": 1000000,
            "opt_comment": "interface comment",
        },
    )
    packet_data = (
        b"first secret-free payload"
        if endianness == "<"
        else b"second payload"
    )
    packet = section_header.new_member(
        block_classes.EnhancedPacket,
        timestamp_high=0x11111111,
        timestamp_low=0x22222222,
        packet_data=packet_data,
        options={
            "epb_dropcount": 7,
            "opt_comment": "packet comment",
        },
    )
    output = io.BytesIO()
    writer = FileWriter(output, section_header)
    writer.write_block(packet)
    simple_packet_data = None
    if include_simple_packet:
        simple_packet_data = b"x" * 200
        simple_packet = section_header.new_member(
            block_classes.SimplePacket,
            packet_data=simple_packet_data,
        )
        writer.write_block(simple_packet)

    name_resolution = None
    if include_name_resolution:
        name_resolution = section_header.new_member(
            block_classes.NameResolution,
            records=[
                {
                    "type": 1,
                    "address": "192.0.2.10",
                    "names": ["host.example"],
                },
                {"type": 99, "raw": b"unknown record"},
            ],
            options={
                "ns_dnsname": "resolver.example",
                "opt_comment": "resolution comment",
            },
        )
        writer.write_block(name_resolution)

    statistics = section_header.new_member(
        block_classes.InterfaceStatistics,
        interface_id=0,
        timestamp_high=0x33333333,
        timestamp_low=0x44444444,
        options={
            "isb_ifrecv": 42,
            "opt_comment": "statistics comment",
        },
    )
    writer.write_block(statistics)
    return (
        output.getvalue(),
        section_header,
        interface,
        packet,
        simple_packet_data,
        name_resolution,
        statistics,
    )


def _unknown_block(endianness):
    body = b"unknown vendor block!!"
    padded_body = body + b"\x00" * ((4 - len(body) % 4) % 4)
    length = 12 + len(padded_body)
    return (
        struct.pack(endianness + "II", 0x00000BAD, length)
        + padded_body
        + struct.pack(endianness + "I", length)
    )


def _append_unknown_interface_option(data, endianness, value):
    section_length = struct.unpack(endianness + "I", data[4:8])[0]
    idb_offset = section_length
    idb_length = struct.unpack(
        endianness + "I", data[idb_offset + 4:idb_offset + 8]
    )[0]
    option = struct.pack(
        endianness + "HH",
        0x1234,
        len(value),
    ) + value
    option += b"\x00" * ((4 - len(option) % 4) % 4)
    insert_at = idb_offset + idb_length - 8
    new_length = idb_length + len(option)
    result = (
        data[:idb_offset + 4]
        + struct.pack(endianness + "I", new_length)
        + data[idb_offset + 8:insert_at]
        + option
        + data[insert_at:idb_offset + idb_length - 4]
        + struct.pack(endianness + "I", new_length)
        + data[idb_offset + idb_length:]
    )
    return result


def _build_multi_section():
    first = _section_payloads("<", include_name_resolution=True)
    first_data = _append_unknown_interface_option(
        first[0], "<", b"unknown option"
    )
    first_data = first_data + _unknown_block("<")
    second = _section_payloads(
        ">",
        include_name_resolution=False,
        include_simple_packet=True,
    )
    second_data = _append_unknown_interface_option(
        second[0], ">", b"unknown option"
    )
    data = first_data + second_data
    originals = {
        BLK_ENHANCED_PACKET: [first[3].packet_data, second[3].packet_data],
        BLK_PACKET_SIMPLE: [second[4][:128]],
    }
    return data, originals


def _block_lengths_are_valid(data):
    offset = 0
    endianness = None
    while offset < len(data):
        block_type = struct.unpack(
            (endianness or ">") + "I", data[offset:offset + 4]
        )[0]
        if block_type == BLK_SECTION_HEADER:
            endianness = "<" if data[offset + 8:offset + 12] == b"M<+\x1a" else ">"
        length = struct.unpack(endianness + "I", data[offset + 4:offset + 8])[0]
        trailing = struct.unpack(
            endianness + "I", data[offset + length - 4:offset + length]
        )[0]
        assert length % 4 == 0
        assert trailing == length
        offset += length
    assert offset == len(data)


def _block_type(block):
    if isinstance(block, UnknownBlock):
        return block.block_type
    return type(block).magic_number


def test_default_rules_sanitize_multi_section_while_preserving_packets():
    data, originals = _build_multi_section()
    source = io.BytesIO(data)
    destination = io.BytesIO()

    report = sanitize_metadata(
        source,
        destination,
        unknown_options=KEEP,
        unknown_blocks=KEEP,
        unknown_records=KEEP,
    )
    output = destination.getvalue()
    _block_lengths_are_valid(output)

    original_blocks = list(FileScanner(io.BytesIO(data)))
    sanitized_blocks = list(FileScanner(io.BytesIO(output)))
    assert len(sanitized_blocks) == len(original_blocks)
    assert report.sections == 2
    assert report.blocks_written == len(original_blocks)
    assert report.packets_checked == 3
    assert report.options_deleted > 0
    assert report.records_deleted == 1
    assert len(report.unknown_options) == 2
    assert len(report.unknown_blocks) == 1
    assert len(report.unknown_records) == 1

    section_headers = [
        block for block in sanitized_blocks
        if _block_type(block) == BLK_SECTION_HEADER
    ]
    interfaces = [
        block for block in sanitized_blocks if _block_type(block) == BLK_INTERFACE
    ]
    packets = [
        block for block in sanitized_blocks
        if _block_type(block) == BLK_ENHANCED_PACKET
    ]
    simple_packets = [
        block for block in sanitized_blocks
        if _block_type(block) == BLK_PACKET_SIMPLE
    ]
    resolutions = [
        block for block in sanitized_blocks
        if _block_type(block) == BLK_NAME_RESOLUTION
    ]
    statistics = [
        block for block in sanitized_blocks
        if _block_type(block) == BLK_INTERFACE_STATS
    ]

    assert [block.packet_data for block in packets] == originals[BLK_ENHANCED_PACKET]
    assert [block.packet_data for block in simple_packets] == [
        originals[BLK_PACKET_SIMPLE][0]
    ]
    assert [(block.link_type, block.snaplen) for block in interfaces] == [
        (1, 65535),
        (101, 128),
    ]
    assert [block.options["if_tsresol"] for block in interfaces] == [
        b"\x06",
        b"\x09",
    ]

    for section_header in section_headers:
        assert "opt_comment" not in section_header.options
        assert "shb_os" not in section_header.options
        assert section_header.options["shb_hardware"] == "capturer hardware"

    for interface in interfaces:
        assert "if_name" not in interface.options
        assert "if_description" not in interface.options
        assert "if_os" not in interface.options
        assert "opt_comment" not in interface.options
        assert interface.options["if_speed"] == 1000000
        assert interface.options[0x1234] == b"unknown option"

    for packet in packets:
        assert "opt_comment" not in packet.options
        assert packet.options["epb_dropcount"] == 7

    name_resolution = resolutions[0]
    assert [record["type"] for record in name_resolution.records] == [99]
    assert name_resolution.records[0]["raw"] == b"unknown record"
    assert "opt_comment" not in name_resolution.options
    assert name_resolution.options["ns_dnsname"] == "resolver.example"

    assert statistics[0].interface_id == 0
    assert statistics[0].timestamp_high == 0x33333333
    assert statistics[0].timestamp_low == 0x44444444
    assert statistics[0].options["isb_ifrecv"] == 42
    assert "opt_comment" not in statistics[0].options


def test_unknown_items_can_be_dropped_and_are_reported():
    data, originals = _build_multi_section()
    destination = io.BytesIO()
    report = MetadataSanitizer(
        unknown_options=DROP,
        unknown_blocks=DROP,
        unknown_records=DROP,
    ).sanitize(io.BytesIO(data), destination)

    blocks = list(FileScanner(io.BytesIO(destination.getvalue())))
    packets = [
        block for block in blocks if _block_type(block) == BLK_ENHANCED_PACKET
    ]
    interfaces = [block for block in blocks if _block_type(block) == BLK_INTERFACE]
    name_resolutions = [
        block for block in blocks if _block_type(block) == BLK_NAME_RESOLUTION
    ]

    assert [block.packet_data for block in packets] == originals[BLK_ENHANCED_PACKET]
    assert all(0x1234 not in block.options for block in interfaces)
    assert name_resolutions[0].records == []
    assert all(item["action"] == DROP for item in report.unknown_options)
    assert all(item["action"] == DROP for item in report.unknown_blocks)
    assert all(item["action"] == DROP for item in report.unknown_records)


def test_options_can_be_replaced():
    data = _section_payloads("<")[0]
    rules = {
        BLK_SECTION_HEADER: {"shb_os": b"replaced os"},
        BLK_INTERFACE: {"if_name": "replaced interface"},
    }
    destination = io.BytesIO()
    report = MetadataSanitizer(rules=rules).sanitize(
        io.BytesIO(data), destination
    )
    blocks = list(FileScanner(io.BytesIO(destination.getvalue())))

    assert blocks[0].options["shb_os"] == "replaced os"
    assert blocks[1].options["if_name"] == "replaced interface"
    assert report.options_replaced == 2
    assert report.options_deleted == 0


def test_replace_sentinel_uses_configured_default():
    data = _section_payloads("<")[0]
    destination = io.BytesIO()
    MetadataSanitizer(
        rules={BLK_SECTION_HEADER: {"shb_os": REPLACE}},
        default_replacement="generic host",
    ).sanitize(io.BytesIO(data), destination)
    blocks = list(FileScanner(io.BytesIO(destination.getvalue())))
    assert blocks[0].options["shb_os"] == "generic host"


def test_unknown_block_options_cannot_be_configured():
    with pytest.raises(ValueError, match="unknown block type"):
        MetadataSanitizer({0x00000BAD: {1: DELETE}})
    with pytest.raises(ValueError, match="does not support options"):
        MetadataSanitizer({BLK_PACKET_SIMPLE: {1: DELETE}})


def test_obsolete_packet_metadata_can_change_without_payload_change():
    section_header = block_classes.SectionHeader(
        endianness="<", options={"opt_comment": "section comment"}
    )
    section_header.new_member(
        block_classes.InterfaceDescription,
        link_type=1,
        snaplen=65535,
    )
    packet_data = b"obsolete packet payload!!"
    packet = section_header.new_member(
        block_classes.ObsoletePacket,
        drops_count=3,
        packet_data=packet_data,
        options={"opt_comment": "packet comment"},
    )
    output = io.BytesIO()
    writer = FileWriter(output, section_header)
    set_strictness(Strictness.WARN)
    try:
        with pytest.warns(PcapngStrictnessWarning, match="obsolete"):
            writer.write_block(packet)
    finally:
        set_strictness(Strictness.FORBID)

    sanitized = io.BytesIO()
    report = MetadataSanitizer().sanitize(io.BytesIO(output.getvalue()), sanitized)
    rescanned = list(FileScanner(io.BytesIO(sanitized.getvalue())))

    _block_lengths_are_valid(sanitized.getvalue())
    assert "opt_comment" not in rescanned[0].options
    assert "opt_comment" not in rescanned[2].options
    assert rescanned[2].drops_count == 3
    assert rescanned[2].interface_id == 0
    assert rescanned[2].packet_data == packet_data
    assert rescanned[2].packet_len == len(packet_data)
    assert report.packets_checked == 1


def test_required_structure_fields_and_if_tsresol_cannot_be_rules():
    with pytest.raises(ValueError, match="required structure field"):
        MetadataSanitizer({BLK_INTERFACE: {"link_type": DELETE}})
    with pytest.raises(ValueError, match="required structure field"):
        MetadataSanitizer({BLK_INTERFACE: {"if_tsresol": DELETE}})
    with pytest.raises(ValueError, match="required option code"):
        MetadataSanitizer({BLK_INTERFACE: {9: b"bad"}})


def test_rule_rejection_does_not_partially_write_target(tmpdir):
    data = _section_payloads("<")[0]
    source_path = tmpdir.join("input.pcapng")
    destination_path = tmpdir.join("output.pcapng")
    source_path.write_binary(data)
    destination_path.write_binary(b"existing destination")

    with pytest.raises(ValueError):
        MetadataSanitizer({BLK_INTERFACE: {"link_type": DELETE}}).sanitize_file(
        str(source_path), str(destination_path)
    )
    assert destination_path.read_binary() == b"existing destination"
