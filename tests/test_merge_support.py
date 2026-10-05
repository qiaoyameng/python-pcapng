import io
from fractions import Fraction

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter, PcapngMerger, SimplePacketAction
from pcapng.exceptions import PcapngMergeError
from pcapng.utils import pack_timestamp_resolution


def timestamp_parts(ticks):
    return ticks >> 32, ticks & 0xFFFFFFFF


def add_packet(section, interface_id, ticks, payload, packet_len=None):
    timestamp_high, timestamp_low = timestamp_parts(ticks)
    packet = section.new_member(
        blocks.EnhancedPacket,
        interface_id=interface_id,
        timestamp_high=timestamp_high,
        timestamp_low=timestamp_low,
        packet_len=len(payload) if packet_len is None else packet_len,
        packet_data=payload,
    )
    return packet


def make_capture(spec, endianness="<"):
    section = blocks.SectionHeader(endianness=endianness)

    for interface_spec in spec["interfaces"]:
        interface_options = {
            "if_tsresol": pack_timestamp_resolution(
                interface_spec["resolution_base"],
                -interface_spec["resolution_exponent"],
            )
        }
        interface_options.update(interface_spec.get("options", {}))
        interface = section.new_member(
            blocks.InterfaceDescription,
            link_type=interface_spec["link_type"],
            snaplen=interface_spec["snaplen"],
            options=interface_options,
        )
    stream = io.BytesIO()
    writer = FileWriter(stream, section)

    for interface_id, ticks, payload, packet_len in spec["packets"]:
        writer.write_block(
            add_packet(section, interface_id, ticks, payload, packet_len)
        )

    stream.seek(0)
    return stream

def merge(streams, action=SimplePacketAction.REJECT, endianness="<"):
    output = io.BytesIO()
    PcapngMerger(
        streams,
        simple_packets=action,
        endianness=endianness,
    ).write(output)
    output.seek(0)
    return list(FileScanner(output))


def make_simple_capture(endianness="<"):
    section = blocks.SectionHeader(endianness=endianness)
    interface = section.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=10,
        options={
            "if_name": "simple-only",
            "if_tsresol": pack_timestamp_resolution(2, -10),
        },
    )
    stream = io.BytesIO()
    writer = FileWriter(stream, section)
    packet = section.new_member(
        blocks.SimplePacket,
        packet_len=20,
        packet_data=b"0123456789",
    )
    writer.write_block(packet)
    stream.seek(0)
    return stream, interface, packet


def test_exact_decimal_and_binary_times_are_not_sorted_as_floats():
    decimal_ticks = 10_000_000_000 * 10**9 + 1
    binary_ticks = (decimal_ticks * 2**30 + 10**9 - 1) // 10**9

    binary_stream = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 2,
                    "resolution_exponent": 30,
                }
            ],
            "packets": [(0, binary_ticks, b"binary", None)],
        }
    )
    decimal_stream = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 9,
                }
            ],
            "packets": [(0, decimal_ticks, b"decimal", None)],
        }
    )

    assert float(Fraction(binary_ticks, 2**30)) == float(
        Fraction(decimal_ticks, 10**9)
    )
    assert Fraction(decimal_ticks, 10**9) < Fraction(binary_ticks, 2**30)

    merged_blocks = merge([binary_stream, decimal_stream])
    packets = [
        block for block in merged_blocks if isinstance(block, blocks.EnhancedPacket)
    ]

    assert [block.packet_data for block in packets] == [b"decimal", b"binary"]
    assert packets[0].timestamp_exact < packets[1].timestamp_exact
    assert packets[0].timestamp == packets[1].timestamp
    assert packets[0].interface.options["if_tsresol"] == pack_timestamp_resolution(
        10, -9
    )
    assert packets[1].interface.options["if_tsresol"] == pack_timestamp_resolution(
        2, -30
    )


def test_equal_times_keep_input_order_and_original_packet_order():
    first = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 16,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                },
                {
                    "link_type": 12,
                    "snaplen": 32,
                    "resolution_base": 2,
                    "resolution_exponent": 20,
                },
            ],
            "packets": [
                (0, 2_000_000, b"a0", 100),
                (1, 3 * 2**20, b"a1", None),
            ],
        }
    )
    second = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 23,
                    "snaplen": 48,
                    "resolution_base": 10,
                    "resolution_exponent": 3,
                },
                {
                    "link_type": 101,
                    "snaplen": 64,
                    "resolution_base": 2,
                    "resolution_exponent": 10,
                },
            ],
            "packets": [
                (0, 2000, b"b0", 200),
                (1, 3 * 2**20, b"b1", None),
            ],
        }
    )

    merged_blocks = merge([first, second])
    interfaces = [
        block
        for block in merged_blocks
        if isinstance(block, blocks.InterfaceDescription)
    ]
    packets = [
        block for block in merged_blocks if isinstance(block, blocks.EnhancedPacket)
    ]

    assert len(interfaces) == 4
    assert [(block.link_type, block.snaplen) for block in interfaces] == [
        (1, 16),
        (12, 32),
        (23, 48),
        (101, 64),
    ]
    assert [block.timestamp_resolution_exact for block in interfaces] == [
        Fraction(1, 10**6),
        Fraction(1, 2**20),
        Fraction(1, 10**3),
        Fraction(1, 2**10),
    ]
    assert [block.packet_data for block in packets] == [b"a0", b"b0", b"a1", b"b1"]
    assert [block.interface_id for block in packets] == [0, 2, 1, 3]
    assert [(block.captured_len, block.packet_len) for block in packets] == [
        (2, 100),
        (2, 200),
        (2, 2),
        (2, 2),
    ]
    for packet in packets:
        assert packet.interface is interfaces[packet.interface_id]


def test_reject_simple_packet_requires_explicit_policy():
    stream, _, _ = make_simple_capture()

    with pytest.raises(
        PcapngMergeError,
        match="Simple Packet Block has no timestamp",
    ):
        merge([stream])


def test_simple_packet_policy_must_be_an_explicit_action():
    stream = io.BytesIO()

    with pytest.raises(TypeError, match="SimplePacketAction"):
        PcapngMerger([stream], simple_packets="keep-separate")


def test_keep_simple_packet_in_independent_section():
    stream, source_interface, source_packet = make_simple_capture()

    merged_blocks = merge([stream], SimplePacketAction.KEEP_SEPARATE)
    section_headers = [
        block for block in merged_blocks if isinstance(block, blocks.SectionHeader)
    ]
    simple_packets = [
        block for block in merged_blocks if isinstance(block, blocks.SimplePacket)
    ]

    assert len(section_headers) == 1
    assert len(simple_packets) == 1
    simple_packet = simple_packets[0]
    assert simple_packet.section is section_headers[0]
    assert simple_packet.interface.link_type == source_interface.link_type
    assert simple_packet.interface.snaplen == source_interface.snaplen
    assert simple_packet.interface.timestamp_resolution_exact == Fraction(
        1, 2**10
    )
    assert simple_packet.packet_len == source_packet.packet_len
    assert simple_packet.captured_len == 10
    assert simple_packet.packet_data == source_packet.packet_data


def test_keep_simple_packet_sections_are_separate_from_timeline():
    timed_stream = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [(0, 1_000_000, b"timed", None)],
        }
    )
    simple_stream, _, _ = make_simple_capture()

    merged_blocks = merge(
        [timed_stream, simple_stream],
        SimplePacketAction.KEEP_SEPARATE,
    )

    section_headers = [
        block for block in merged_blocks if isinstance(block, blocks.SectionHeader)
    ]
    timed_packets = [
        block
        for block in merged_blocks
        if isinstance(block, blocks.EnhancedPacket)
    ]
    simple_packets = [
        block for block in merged_blocks if isinstance(block, blocks.SimplePacket)
    ]

    assert len(section_headers) == 2
    assert [block.packet_data for block in timed_packets] == [b"timed"]
    assert timed_packets[0].section is section_headers[0]
    assert len(simple_packets) == 1
    assert simple_packets[0].section is section_headers[1]


def test_input_positions_are_restored_after_merge():
    first = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                    "options": {"if_tsoffset": 1},
                }
            ],
            "packets": [(0, 1, b"first", None)],
        }
    )
    second = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [(0, 2, b"second", None)],
        }
    )

    first.seek(0)
    second.seek(0)
    merge([first, second])

    assert first.tell() == 0
    assert second.tell() == 0


def test_interface_time_offset_is_included_in_exact_ordering():
    first = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [(0, 2_000_000, b"offset-first", None)],
        }
    )
    second = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [(0, 1_000_000, b"offset-second", None)],
        }
    )
    second.seek(0)

    merged_blocks = merge([first, second])
    packets = [
        block
        for block in merged_blocks
        if isinstance(block, blocks.EnhancedPacket)
    ]

    assert [block.packet_data for block in packets] == [
        b"offset-second",
        b"offset-first",
    ]


def test_zero_length_packets_remain_valid_after_remapping():
    first = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [(0, 1, b"", None)],
        }
    )

    merged_blocks = merge([first])
    packet = next(
        block
        for block in merged_blocks
        if isinstance(block, blocks.EnhancedPacket)
    )

    assert packet.packet_data == b""
    assert packet.captured_len == 0
    assert packet.packet_len == 0


def test_inputs_must_be_seekable():
    class ReadOnlyStream(object):
        def read(self, size=-1):
            return b""

    with pytest.raises(TypeError, match="seekable"):
        PcapngMerger([ReadOnlyStream()], SimplePacketAction.REJECT)


def test_each_input_must_have_non_decreasing_timestamps():
    stream = make_capture(
        {
            "interfaces": [
                {
                    "link_type": 1,
                    "snaplen": 64,
                    "resolution_base": 10,
                    "resolution_exponent": 6,
                }
            ],
            "packets": [
                (0, 2, b"later", None),
                (0, 1, b"earlier", None),
            ],
        }
    )

    with pytest.raises(PcapngMergeError, match="non-decreasing"):
        merge([stream])


def test_timestamped_block_must_reference_a_valid_interface():
    packet_data = b"bad-interface"
    output = io.BytesIO(
        b"\x0a\x0d\x0d\x0a"
        b"\x1c\x00\x00\x00"
        b"\x4d\x3c\x2b\x1a"
        b"\x01\x00\x00\x00"
        b"\xff\xff\xff\xff\xff\xff\xff\xff"
        b"\x1c\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x14\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x40\x00\x00\x00"
        b"\x14\x00\x00\x00"
        b"\x06\x00\x00\x00"
        b"\x34\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
        b"\x0d\x00\x00\x00"
        b"\x0d\x00\x00\x00"
        + packet_data
        + b"\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x34\x00\x00\x00"
    )

    with pytest.raises(PcapngMergeError, match="unknown interface"):
        merge([output])
