import io
from fractions import Fraction

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner
from pcapng.merge import (
    SP_REJECT,
    SP_SEPARATE_SECTION,
    MergeError,
    Merger,
    merge,
    packet_timestamp,
)
from pcapng.utils import pack_timestamp_resolution
from pcapng.writer import FileWriter


def make_input(endianness, interfaces, items):
    """
    Build an in-memory pcap-ng stream.

    ``interfaces`` is a list of dicts with ``link_type``, ``snaplen`` and
    an optional ``tsresol`` tuple of ``(base, exponent)``.

    ``items`` is a list of tuples describing the blocks to write:

    - ``("epb", interface_id, raw_timestamp, packet_data, packet_len)``
    - ``("spb", packet_data, packet_len)``
    """
    shb = blocks.SectionHeader(endianness=endianness)
    for spec in interfaces:
        options = {}
        if "tsresol" in spec:
            options["if_tsresol"] = pack_timestamp_resolution(*spec["tsresol"])
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=spec.get("link_type", 1),
            snaplen=spec.get("snaplen", 65535),
            options=options,
        )
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for item in items:
        if item[0] == "epb":
            _, interface_id, raw_ts, data, packet_len = item
            writer.write_block(
                shb.new_member(
                    blocks.EnhancedPacket,
                    interface_id=interface_id,
                    timestamp_high=raw_ts >> 32,
                    timestamp_low=raw_ts & 0xFFFFFFFF,
                    packet_len=packet_len,
                    packet_data=data,
                )
            )
        elif item[0] == "spb":
            _, data, packet_len = item
            writer.write_block(
                shb.new_member(
                    blocks.SimplePacket, packet_len=packet_len, packet_data=data
                )
            )
        else:  # pragma: no cover
            raise ValueError("unknown item {0!r}".format(item))
    stream.seek(0)
    return stream


def scan(stream):
    stream.seek(0)
    return list(FileScanner(stream))


def packets_of(scanned):
    return [b for b in scanned if isinstance(b, blocks.EnhancedPacket)]


def test_merge_orders_across_inputs_and_remaps_interfaces():
    # Two collectors, both numbering their interfaces from zero, with
    # different link types, snaplens and timestamp resolutions.
    input_a = make_input(
        "<",
        [
            {"link_type": 101, "snaplen": 65535, "tsresol": (10, 6)},
            {"link_type": 102, "snaplen": 128, "tsresol": (10, 9)},
        ],
        [
            ("epb", 1, 7, b"a2", 2),  # 7e-9 s
            ("epb", 0, 3, b"a1", 100),  # 3e-6 s, original len 100
        ],
    )
    input_b = make_input(
        ">",
        [{"link_type": 103, "snaplen": 9600, "tsresol": (2, 10)}],
        [("epb", 0, 1, b"b1", 2)],  # 2^-10 s
    )

    output = io.BytesIO()
    merge([input_a, input_b], output, SP_REJECT)

    scanned = scan(output)
    sections = [b for b in scanned if isinstance(b, blocks.SectionHeader)]
    assert len(sections) == 1

    # All interfaces are mapped into a single output section, and their
    # metadata must survive the remapping
    assert sections[0].interfaces[0].link_type == 101
    assert sections[0].interfaces[0].snaplen == 65535
    assert sections[0].interfaces[1].link_type == 102
    assert sections[0].interfaces[1].snaplen == 128
    assert sections[0].interfaces[2].link_type == 103
    assert sections[0].interfaces[2].snaplen == 9600
    assert sections[0].interfaces[0].options["if_tsresol"] == (
        pack_timestamp_resolution(10, 6)
    )
    assert sections[0].interfaces[1].options["if_tsresol"] == (
        pack_timestamp_resolution(10, 9)
    )
    assert sections[0].interfaces[2].options["if_tsresol"] == (
        pack_timestamp_resolution(2, 10)
    )

    pkts = packets_of(scanned)
    assert [p.packet_data for p in pkts] == [b"a2", b"a1", b"b1"]

    # Every packet must reference a valid interface of its own section,
    # and the referenced interface must be the right one.
    for pkt in pkts:
        assert pkt.interface is pkt.section.interfaces[pkt.interface_id]
    assert len({p.interface_id for p in pkts}) == 3
    assert pkts[0].interface.link_type == 102
    assert pkts[1].interface.link_type == 101
    assert pkts[2].interface.link_type == 103

    # Packet length information is preserved
    assert pkts[1].packet_len == 100
    assert pkts[1].captured_len == 2

    # The merged timeline is non-decreasing under exact comparison
    times = [packet_timestamp(p, p.interface) for p in pkts]
    assert times == sorted(times)
    assert times == [Fraction(7, 10**9), Fraction(3, 10**6), Fraction(1, 2**10)]


def test_merge_is_stable_for_equal_timestamps():
    input_a = make_input(
        "<",
        [{"tsresol": (10, 6)}],
        [("epb", 0, 5, b"a1", 2), ("epb", 0, 5, b"a2", 2)],
    )
    input_b = make_input(
        "<", [{"tsresol": (10, 6)}], [("epb", 0, 5, b"b1", 2)]
    )

    output = io.BytesIO()
    merge([input_a, input_b], output, SP_REJECT)

    # Same timestamp: input order first, then original packet order
    pkts = packets_of(scan(output))
    assert [p.packet_data for p in pkts] == [b"a1", b"a2", b"b1"]


def test_merge_exact_comparison_beats_float_rounding():
    # Adjacent timestamps with decimal and binary resolutions:
    #   decimal: 100000 * 10^-6   = 0.1 s
    #   binary:  14411518807585587 * 2^-57 = 0.1 - 2^-57/5 s (< 0.1)
    dec_raw, bin_raw = 100000, 14411518807585587
    exact_dec = Fraction(dec_raw, 10**6)
    exact_bin = Fraction(bin_raw, 2**57)
    assert exact_bin < exact_dec

    # ...but a float-based comparison orders them the other way round
    assert dec_raw * (10**-6) < bin_raw * (2**-57)

    input_a = make_input(
        "<",
        [{"tsresol": (10, 6)}],
        [("epb", 0, dec_raw, b"decimal", 2)],
    )
    input_b = make_input(
        "<",
        [{"tsresol": (2, 57)}],
        [("epb", 0, bin_raw, b"binary", 2)],
    )

    output = io.BytesIO()
    merge([input_a, input_b], output, SP_REJECT)

    pkts = packets_of(scan(output))
    assert [p.packet_data for p in pkts] == [b"binary", b"decimal"]
    # The exact timestamps survive the round trip unchanged
    assert packet_timestamp(pkts[0], pkts[0].interface) == exact_bin
    assert packet_timestamp(pkts[1], pkts[1].interface) == exact_dec


def test_simple_packet_rejected():
    stream = make_input(
        "<", [{"snaplen": 100}], [("spb", b"x" * 80, 80)]
    )
    with pytest.raises(MergeError, match="SimplePacket"):
        merge([stream], io.BytesIO(), SP_REJECT)


def test_simple_packet_kept_in_dedicated_section():
    stream = make_input(
        "<",
        [{"link_type": 101, "snaplen": 100, "tsresol": (10, 6)}],
        [
            ("spb", b"s" * 80, 80),
            ("epb", 0, 1, b"e1", 2),
            ("spb", b"t" * 90, 90),
        ],
    )

    output = io.BytesIO()
    merge([stream], output, SP_SEPARATE_SECTION)

    scanned = scan(output)
    sections = [b for b in scanned if isinstance(b, blocks.SectionHeader)]
    assert len(sections) == 2

    spbs = [b for b in scanned if isinstance(b, blocks.SimplePacket)]
    assert len(spbs) == 2
    assert [s.packet_data for s in spbs] == [b"s" * 80, b"t" * 90]
    assert [s.packet_len for s in spbs] == [80, 90]

    # The dedicated section holds a single interface, preserving the
    # link type and snaplen the SimplePacket blocks depend on
    spb_section = spbs[0].section
    assert spb_section is not sections[0]
    assert len(spb_section.interfaces) == 1
    assert spb_section.interfaces[0].link_type == 101
    assert spb_section.interfaces[0].snaplen == 100
    assert spbs[0].captured_len == 80
    assert spbs[1].captured_len == 90

    # The timestamped packet is in the main section
    pkts = packets_of(scanned)
    assert len(pkts) == 1
    assert pkts[0].section is sections[0]


def test_unordered_input_rejected():
    stream = make_input(
        "<",
        [{"tsresol": (10, 6)}],
        [("epb", 0, 10, b"a", 1), ("epb", 0, 5, b"b", 1)],
    )
    with pytest.raises(MergeError, match="non-decreasing"):
        merge([stream], io.BytesIO(), SP_REJECT)


def test_policy_must_be_valid():
    with pytest.raises(ValueError):
        merge([], io.BytesIO(), "guess")


def test_inputs_must_be_seekable():
    class NonSeekable(io.BytesIO):
        def seekable(self):
            return False

    stream = NonSeekable(b"")
    with pytest.raises(MergeError, match="seekable"):
        merge([stream], io.BytesIO(), SP_REJECT)


def test_merger_class_api():
    stream = make_input(
        "<", [{"tsresol": (10, 6)}], [("epb", 0, 1, b"a", 1)]
    )
    output = io.BytesIO()
    Merger(output, SP_REJECT).merge([stream])
    assert [p.packet_data for p in packets_of(scan(output))] == [b"a"]
