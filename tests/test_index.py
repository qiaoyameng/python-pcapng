"""
Tests for the sidecar random-access packet index
(:mod:`pcapng.index`).

These tests cover:

* indexing and random reads over files containing multiple sections with
  different byte orders, multiple interfaces, unknown blocks and all
  three packet block variants (EPB, obsolete Packet, SPB);
* binding the index to file size + content fingerprint, including
  rejection of replaced files and same-length rewrites;
* proving via a byte-counting stream that locating packets near the end
  does not rescan the file (reads are proportional to the target range
  plus a small, bounded amount of context);
* item-by-item comparison of random-read metadata with a full scan.
"""

import io
import json
import os
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner
from pcapng.index import (
    ANCHOR_WINDOW_SIZE,
    CountingReader,
    FULL_FINGERPRINT_MAX_SIZE,
    INDEX_MAGIC,
    INDEX_SUFFIX,
    PcapngIndex,
    SAMPLE_WINDOW_SIZE,
    IndexedReader,
    build_index,
    build_index_file,
    fingerprint_windows,
    load_index_file,
)
from pcapng.exceptions import (
    InvalidIndexError,
    StaleIndexError,
)
from pcapng.strictness import Strictness, set_strictness


# ---------------------------------------------------------------------------
# Test data construction helpers
# ---------------------------------------------------------------------------


def _write_section(buf, endianness, interfaces, packets, unknown_blocks=()):
    """
    Write one pcapng section to ``buf``.

    :param interfaces: list of ``(link_type, snaplen, tsresol)`` tuples
    :param packets: list of ``(interface_id, kind, payload)`` where kind is
        ``"epb"``, ``"spb"`` or ``"pb"`` (obsolete packet block)
    :param unknown_blocks: offsets within the packet list after which an
        unknown block is inserted (``"start"`` is also accepted)
    """
    from pcapng import FileWriter

    shb = blocks.SectionHeader(
        endianness=endianness,
        options={"shb_userappl": "pcapng-index-tests"},
    )
    for link_type, snaplen, tsresol in interfaces:
        options = {}
        if tsresol is not None:
            options["if_tsresol"] = tsresol
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=link_type,
            snaplen=snaplen,
            options=options,
        )

    writer = FileWriter(buf, shb)

    insert_at = set(unknown_blocks)
    if "start" in insert_at:
        _append_unknown_block(buf, endianness)

    for position, (interface_id, kind, payload) in enumerate(packets):
        if kind == "epb":
            packet = shb.new_member(
                blocks.EnhancedPacket,
                interface_id=interface_id,
                timestamp_high=0x00010000,
                timestamp_low=position,
                packet_len=len(payload) + 7,
                packet_data=payload,
            )
        elif kind == "spb":
            packet = shb.new_member(
                blocks.SimplePacket,
                packet_len=len(payload),
                packet_data=payload,
            )
        elif kind == "pb":
            packet = shb.new_member(
                blocks.ObsoletePacket,
                interface_id=interface_id,
                drops_count=2,
                timestamp_high=0x00020000,
                timestamp_low=position,
                packet_len=len(payload),
                packet_data=payload,
            )
        else:
            raise ValueError(kind)
        writer.write_block(packet)
        if position in insert_at:
            _append_unknown_block(buf, endianness)


def _append_unknown_block(buf, endianness):
    # A valid but unregistered block type (0x0000BE00), with an odd payload
    # length to exercise padding handling.
    payload = b"unknown-block-payload!"  # 21 bytes -> 3 bytes padding
    body = payload + b"\x00" * ((4 - len(payload) % 4) % 4)
    block_length = 12 + len(body)
    buf.write(struct.pack(endianness + "I", 0x0000BE00))
    buf.write(struct.pack(endianness + "I", block_length))
    buf.write(body)
    buf.write(struct.pack(endianness + "I", block_length))


def build_capture():
    """
    Build a small (fully-hashed) capture exercising all tricky features:
    two sections of opposite byte order, multiple interfaces per
    section, SPB/EPB/obsolete packet blocks and unknown blocks.
    """
    set_strictness(Strictness.WARN)
    buf = io.BytesIO()

    _write_section(
        buf,
        "<",
        interfaces=[
            (1, 65535, b"\x06"),  # microsecond
            (12, 0, b"\x09"),  # nanosecond, unlimited snaplen
        ],
        packets=[
            (0, "epb", b"packet-00 little-eth0"),
            (1, "epb", b"packet-01 little-lo!!"),
            (0, "pb", b"packet-02 obsolete!!"),
            (0, "epb", b"packet-03 little-eth0"),
        ],
        unknown_blocks={2},
    )
    _write_section(
        buf,
        ">",
        interfaces=[
            (1, 262144, b"\x06"),
        ],
        packets=[
            (0, "spb", b"packet-04 big-spb-data"),
            (0, "epb", b"packet-05 big-endian!!"),
        ],
        unknown_blocks={"start"},
    )
    set_strictness(Strictness.FORBID)
    return buf.getvalue()


def all_packet_blocks(data):
    return [
        block
        for block in FileScanner(io.BytesIO(data))
        if isinstance(
            block,
            (blocks.EnhancedPacket, blocks.SimplePacket, blocks.ObsoletePacket),
        )
    ]


def packet_metadata(block):
    """Metadata (no raw payload) used to compare full-scan vs random reads."""
    options = getattr(block, "options", None)
    raw_options = None
    if options is not None:
        raw_options = {
            name: options.get_all_raw(name) for name in options
        }
    return (
        type(block),
        block.interface_id,
        block.captured_len,
        block.packet_len,
        getattr(block, "timestamp_high", None),
        getattr(block, "timestamp_low", None),
        getattr(block, "timestamp", None),
        raw_options,
        bytes(block.packet_data),
    )


@pytest.fixture(autouse=True)
def restore_strictness():
    set_strictness(Strictness.FORBID)
    yield
    set_strictness(Strictness.FORBID)


# ---------------------------------------------------------------------------
# Basic indexing and item-by-item comparison with a full scan
# ---------------------------------------------------------------------------


def test_index_records_all_packets_with_context():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    assert index.packet_count == 6
    assert len(index.sections) == 2
    assert index.sections[0]["endianness"] == "<"
    assert index.sections[1]["endianness"] == ">"
    assert [iface["interface_id"] for iface in index.sections[0]["interfaces"]] == [
        0,
        1,
    ]
    assert [record.section_id for record in index.records] == [0, 0, 0, 0, 1, 1]
    assert [record.block_type for record in index.records] == [
        blocks.EnhancedPacket.magic_number,
        blocks.EnhancedPacket.magic_number,
        blocks.ObsoletePacket.magic_number,
        blocks.EnhancedPacket.magic_number,
        blocks.SimplePacket.magic_number,
        blocks.EnhancedPacket.magic_number,
    ]
    assert [record.interface_id for record in index.records] == [0, 1, 0, 0, 0, 0]


def test_random_reads_match_full_scan_item_by_item():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    scanned = all_packet_blocks(data)

    reader = IndexedReader(index, io.BytesIO(data))

    # Every individual random read matches the full scan.
    for ordinal in range(index.packet_count):
        assert packet_metadata(reader.read_packet(ordinal)) == packet_metadata(
            scanned[ordinal]
        )

    # Contiguous ranges of various starts/stops, incl. negative indices.
    for range_spec in [
        (0, 6),
        (0, 1),
        (5, 6),
        (2, 4),
        (None, None),
        (-3, None),
        (None, -2),
        (-4, -1),
    ]:
        start, stop = range_spec
        result = list(reader.read_range(start, stop))
        expected = scanned[slice(start, stop)]
        assert len(result) == len(expected)
        for got, want in zip(result, expected):
            assert packet_metadata(got) == packet_metadata(want)

    # Slicing and single-item access.
    assert [packet_metadata(block) for block in reader[1:4]] == [
        packet_metadata(block) for block in scanned[1:4]
    ]
    assert packet_metadata(reader[-1]) == packet_metadata(scanned[-1])
    assert len(reader) == 6


def test_unknown_blocks_are_indexed_around():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    # Unknown blocks don't shift packet locations: offsets are strictly
    # increasing and the packets themselves parse correctly.
    offsets = [record.offset for record in index.records]
    assert offsets == sorted(offsets)
    assert len(set(offsets)) == len(offsets)


def test_multi_interface_context_resolves_correct_interface():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    reader = IndexedReader(index, io.BytesIO(data))

    packet_lo = reader.read_packet(1)
    assert packet_lo.interface_id == 1
    # Nanosecond interface (tsresol 9) vs microsecond interface 0.
    assert packet_lo.interface.timestamp_resolution == 1e-9
    packet_eth0 = reader.read_packet(0)
    assert packet_eth0.interface.timestamp_resolution == 1e-6


def test_spb_uses_first_interface_snaplen():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    reader = IndexedReader(index, io.BytesIO(data))
    spb = reader.read_packet(4)
    assert isinstance(spb, blocks.SimplePacket)
    assert spb.interface_id == 0
    assert spb.packet_data == b"packet-04 big-spb-data"


# ---------------------------------------------------------------------------
# Sidecar save / load and on-disk path workflow
# ---------------------------------------------------------------------------


def test_index_save_load_roundtrip():
    data = build_capture()
    index = build_index(io.BytesIO(data))

    buf = io.BytesIO()
    index.save(buf)
    raw = buf.getvalue()
    assert raw.startswith(INDEX_MAGIC)

    # Index must not contain packet payload bytes.
    assert b"packet-00 little-eth0" not in raw
    assert b"packet-05 big-endian!!" not in raw

    loaded = PcapngIndex.load(io.BytesIO(raw))
    assert loaded.packet_count == index.packet_count
    assert loaded.size == index.size
    assert loaded.fingerprint == index.fingerprint
    assert loaded.windows == index.windows
    assert loaded.records == index.records
    assert loaded.sections == index.sections

    reader = IndexedReader(loaded, io.BytesIO(data))
    scanned = all_packet_blocks(data)
    for ordinal in range(loaded.packet_count):
        assert packet_metadata(reader.read_packet(ordinal)) == packet_metadata(
            scanned[ordinal]
        )


@pytest.mark.parametrize("tamper", [b"", b"garbage", b"PXIDX001\n{}\n"])
def test_loading_corrupt_index_raises(tamper):
    with pytest.raises(InvalidIndexError):
        PcapngIndex.load(io.BytesIO(tamper))


def test_index_with_corrupt_fingerprint_field_rejected():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    buf = io.BytesIO()
    index.save(buf)
    raw = bytearray(buf.getvalue())
    line_end = raw.index(b"\n")
    header = json.loads(raw[len(INDEX_MAGIC):line_end])
    header["fingerprint"] = "zz-not-hex"
    tampered = (
        INDEX_MAGIC
        + json.dumps(header).encode()
        + b"\n"
        + raw[line_end + 1:]
    )
    with pytest.raises(InvalidIndexError):
        PcapngIndex.load(io.BytesIO(tampered))


def test_build_and_open_via_paths(tmp_path):
    pcap_path = tmp_path / "capture.pcapng"
    pcap_path.write_bytes(build_capture())

    index_path = build_index_file(str(pcap_path))
    assert index_path == str(pcap_path) + INDEX_SUFFIX
    assert os.path.exists(index_path)

    loaded = load_index_file(index_path)
    assert loaded.packet_count == 6

    with IndexedReader.open_path(str(pcap_path)) as reader:
        assert len(reader) == 6
        assert reader[0].packet_data == b"packet-00 little-eth0"
        assert reader[-1].packet_data == b"packet-05 big-endian!!"


def test_index_works_on_real_capture_files():
    paths = [
        os.path.join("test_data", name)
        for name in os.listdir("test_data")
        if name.endswith(".ntar") and name != "test006.ntar"
    ]
    assert paths
    for path in paths:
        with open(path, "rb") as fp:
            data = fp.read()
        with open(path, "rb") as fp:
            index = build_index(fp)
        with open(path, "rb") as fp:
            scanned = all_packet_blocks(data)
        assert index.packet_count == len(scanned), path
        reader = IndexedReader(index, open(path, "rb"))
        try:
            for ordinal in range(index.packet_count):
                assert packet_metadata(reader.read_packet(ordinal)) == packet_metadata(
                    scanned[ordinal]
                ), (path, ordinal)
        finally:
            reader.close()


@pytest.mark.parametrize("name", ["test007.ntar", "test010.ntar"])
def test_odd_length_blocks_real_files_match_full_scan(name):
    # These files contain blocks whose declared length is not a multiple
    # of 4 (unpadded); the index must still resume parsing at the packet.
    path = os.path.join("test_data", name)
    with open(path, "rb") as fp:
        data = fp.read()
    index = build_index(io.BytesIO(data))
    scanned = all_packet_blocks(data)
    assert index.packet_count == len(scanned)
    reader = IndexedReader(index, io.BytesIO(data))
    for ordinal in range(index.packet_count):
        assert packet_metadata(reader.read_packet(ordinal)) == packet_metadata(
            scanned[ordinal]
        )


def test_build_index_restores_stream_position():
    data = build_capture()
    stream = io.BytesIO(data)
    stream.seek(42)
    build_index(stream)
    assert stream.tell() == 42


# ---------------------------------------------------------------------------
# Stale index detection: replaced / resized / same-length rewritten files
# ---------------------------------------------------------------------------


def test_stale_index_rejects_resized_file():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    with pytest.raises(StaleIndexError, match="size"):
        IndexedReader(index, io.BytesIO(data + b"\x00"))
    with pytest.raises(StaleIndexError, match="size"):
        IndexedReader(index, io.BytesIO(data[:-1]))


def test_stale_index_rejects_same_length_rewrite():
    data = bytearray(build_capture())
    index = build_index(io.BytesIO(bytes(data)))

    # Flip a byte in the file head (covered by the fingerprint window).
    tampered = bytearray(data)
    tampered[4] ^= 0xFF
    assert len(tampered) == len(data)
    with pytest.raises(StaleIndexError, match="fingerprint"):
        IndexedReader(index, io.BytesIO(bytes(tampered)))


def test_stale_index_rejects_replaced_same_length_file():
    data = bytearray(build_capture())
    index = build_index(io.BytesIO(bytes(data)))

    # Build a different, equally long capture (different payload strings).
    replacement = bytearray(
        build_capture().replace(b"little-eth0", b"XXXXXXXXXXXX")
        .replace(b"big-endian!!", b"YYYYYYYYYYYY")
    )
    if len(replacement) != len(data):
        # Padding/equal-size guarantee: fall back to an interior rewrite.
        replacement = bytearray(data)
        replacement[40] ^= 0xAA
    assert len(replacement) == len(data)
    with pytest.raises(StaleIndexError):
        IndexedReader(index, io.BytesIO(bytes(replacement)), validate=True)


def test_packet_block_rewrite_is_rejected_even_in_fingerprint_gap():
    # A large file where fingerprint sampling leaves gaps; tampering a
    # packet that sits in such a gap must still be refused at read time.
    data, index, gap_packet_ordinal = build_large_capture_with_gap_packet()
    record = index.records[gap_packet_ordinal]

    tampered = bytearray(data)
    # Flip one payload byte inside the packet block (keeps length).
    tampered[record.offset + 40] ^= 0x01
    assert len(tampered) == len(data)

    reader = IndexedReader(index, io.BytesIO(bytes(tampered)), validate=False)
    with pytest.raises(StaleIndexError, match="changed"):
        reader.read_packet(gap_packet_ordinal)


def test_section_header_rewrite_is_rejected():
    data = bytearray(build_capture())
    index = build_index(io.BytesIO(bytes(data)))
    shb_offset = index.sections[0]["offset"]
    data[shb_offset + 20] ^= 0x01  # inside SHB, length unchanged
    with pytest.raises(StaleIndexError):
        IndexedReader(index, io.BytesIO(bytes(data)))


def test_interface_description_rewrite_is_rejected():
    data = bytearray(build_capture())
    index = build_index(io.BytesIO(bytes(data)))
    idb_offset = index.sections[0]["interfaces"][1]["offset"]
    data[idb_offset + 12] ^= 0x01  # link type / reserved byte
    assert len(data) == len(data)
    reader = IndexedReader(index, io.BytesIO(bytes(data)), validate=False)
    with pytest.raises(StaleIndexError, match="interface"):
        reader.read_packet(1)  # packet on interface 1 needs that IDB


def test_validate_can_be_skipped_and_repeated():
    data = build_capture()
    index = build_index(io.BytesIO(data))
    reader = IndexedReader(index, io.BytesIO(data), validate=False)
    index.validate(io.BytesIO(data))  # explicit validation works
    assert reader[2].packet_data == b"packet-02 obsolete!!"


def build_large_capture_with_gap_packet():
    """
    Build a capture large enough to use sampled fingerprinting and return
    ``(data, index, ordinal)`` for a packet whose block lies strictly
    outside every fingerprint window (an interior sampling gap).

    Packets are small and separated by large unknown blocks, so each
    packet block fits entirely inside a sampling gap rather than a
    fingerprint window.
    """
    set_strictness(Strictness.WARN)
    buf = io.BytesIO()
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    from pcapng import FileWriter

    writer = FileWriter(buf, shb)

    # Filler pushing everything well beyond the fingerprint head window.
    _append_unknown_payload(buf, "<", 300 * 1024)

    payload_size = 100
    count = 80
    gap_size = 60 * 1024  # much larger than the 4 KiB sampling window
    for position in range(count):
        packet = shb.new_member(
            blocks.EnhancedPacket,
            interface_id=0,
            timestamp_high=0x00010000,
            timestamp_low=position,
            packet_len=payload_size,
            packet_data=b"P%04d" % position + b"X" * (payload_size - 5),
        )
        writer.write_block(packet)
        if position != count - 1:
            _append_unknown_payload(buf, "<", gap_size)
    set_strictness(Strictness.FORBID)

    data = buf.getvalue()
    assert len(data) > FULL_FINGERPRINT_MAX_SIZE
    index = build_index(io.BytesIO(data))
    windows = fingerprint_windows(len(data), index.section_offsets)
    assert len(windows) > 2  # sampled mode is active

    def in_any_window(offset, length):
        return any(
            start <= offset and offset + length <= end for start, end in windows
        )

    gap_ordinal = None
    for record in index.records:
        if not in_any_window(record.offset, record.length):
            gap_ordinal = record.ordinal
            break
    assert gap_ordinal is not None, "expected a packet fully inside a fingerprint gap"
    return data, index, gap_ordinal


def _append_unknown_payload(buf, endianness, size):
    body = bytes((size * 7 + 13) & 0xFF for _ in range(size))
    body = body + b"\x00" * ((4 - len(body) % 4) % 4)
    block_length = 12 + len(body)
    buf.write(struct.pack(endianness + "I", 0x0000BE01))
    buf.write(struct.pack(endianness + "I", block_length))
    buf.write(body)
    buf.write(struct.pack(endianness + "I", block_length))


# ---------------------------------------------------------------------------
# Read byte budget: random access must not rescan the file
# ---------------------------------------------------------------------------


def test_reading_last_packets_does_not_rescan_file():
    data, index, gap_ordinal = build_large_capture_with_gap_packet()

    # Read a contiguous tail range through a counting stream. Counters
    # start after index validation so the budget reflects reads needed to
    # locate/parse the target range only.
    counter = CountingReader(io.BytesIO(data))
    reader = IndexedReader(index, counter, validate=False)

    start = index.packet_count - 8
    counter.reset_counters()
    tail_packets = list(reader.read_range(start, index.packet_count))
    assert len(tail_packets) == 8

    # Upper bound: one SHB + one IDB context block + 8 target packets.
    # This is dominated by the target range, not by file size; in
    # particular it is nowhere near a full rescan.
    target_bytes = sum(
        record.length for record in index.records[start:index.packet_count]
    )
    context_bytes = (
        index.sections[0]["length"]
        + index.sections[0]["interfaces"][0]["length"]
    )
    bound = target_bytes + context_bytes + 1024
    assert counter.bytes_read <= bound, (counter.bytes_read, bound)
    assert counter.bytes_read < len(data) // 8


def test_reading_single_middle_packet_is_bounded():
    data, index, gap_ordinal = build_large_capture_with_gap_packet()

    counter = CountingReader(io.BytesIO(data))
    reader = IndexedReader(index, counter, validate=False)
    counter.reset_counters()
    packet = reader.read_packet(gap_ordinal)

    record = index.records[gap_ordinal]
    context_bytes = (
        index.sections[0]["length"]
        + index.sections[0]["interfaces"][0]["length"]
    )
    bound = record.length + context_bytes + 256
    assert counter.bytes_read <= bound, (counter.bytes_read, bound)
    assert packet.timestamp_low == gap_ordinal
    assert packet.packet_data[:1] == b"P"


def test_random_read_metadata_matches_full_scan_on_large_file():
    data, index, _ = build_large_capture_with_gap_packet()
    scanned = all_packet_blocks(data)
    assert len(scanned) == index.packet_count

    # Check head, middle and tail ranges item by item.
    reader = IndexedReader(index, io.BytesIO(data), validate=False)
    picks = (
        list(range(0, 5))
        + list(range(index.packet_count // 2 - 2, index.packet_count // 2 + 3))
        + list(range(index.packet_count - 5, index.packet_count))
    )
    for ordinal in picks:
        assert packet_metadata(reader.read_packet(ordinal)) == packet_metadata(
            scanned[ordinal]
        )


def test_sequential_range_read_is_primarily_range_sized():
    data, index, _ = build_large_capture_with_gap_packet()
    counter = CountingReader(io.BytesIO(data))
    reader = IndexedReader(index, counter, validate=False)

    start = 50
    stop = 60
    counter.reset_counters()
    packets = list(reader.read_range(start, stop))
    assert len(packets) == 10

    range_bytes = sum(record.length for record in index.records[start:stop])
    # Context (SHB+IDB) is read once; nothing before the range is scanned.
    assert counter.bytes_read <= range_bytes + 8 * 1024
