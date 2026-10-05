"""
Tests for the sidecar pcapng index and random-access reader.

These tests synthesize captures covering:

* multiple concatenated sections with *different byte orders*;
* multiple interfaces per section (different link types, snap lengths
  and timestamp resolutions);
* Enhanced Packet, Simple Packet and obsolete Packet blocks;
* unknown block types interleaved with packets;
* enough packets to make a full scan measurably more expensive than a
  targeted read.

They verify, packet by packet, that random reads reproduce the metadata
and payload produced by a complete :class:`FileScanner` scan, that reads
near the end do not rescan the file (via a byte-counting stream), and
that indexes are rejected after replacement, truncation or a
same-length rewrite of the capture.
"""

import hashlib
import os
import struct

import pytest

from pcapng import (
    CountingReader,
    FileScanner,
    build_index,
    open_index,
)
from pcapng.blocks import (
    EnhancedPacket,
    ObsoletePacket,
    SimplePacket,
)
from pcapng.exceptions import StaleIndexError

PACKET_TYPES = (EnhancedPacket, SimplePacket, ObsoletePacket)


# --------------------------------------------------------------------- #
# Tiny hand-rolled pcapng writer (full control over byte order/blocks)
# --------------------------------------------------------------------- #


def _pad4(data):
    return data + b"\x00" * ((-len(data)) % 4)


def _block(endianness, block_type, body):
    """Wrap a block body (everything between the two length words)."""
    payload = _pad4(body)
    length = 12 + len(payload)
    out = struct.pack(endianness + "II", block_type, length)
    out += payload
    out += struct.pack(endianness + "I", length)
    return out


def _shb(endianness):
    # BOM goes between length and version, so build the SHB manually
    # rather than using _block() (which places body right after length).
    payload = _pad4(
        struct.pack(endianness + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack(endianness + "I", 0)
    )
    length = 12 + len(payload)
    return (
        struct.pack(endianness + "II", 0x0A0D0D0A, length)
        + payload
        + struct.pack(endianness + "I", length)
    )


def _idb(endianness, link_type, snaplen, tsresol_byte=None):
    body = struct.pack(endianness + "HHI", link_type, 0, snaplen)
    if tsresol_byte is not None:
        value = struct.pack("B", tsresol_byte)
        body += struct.pack(endianness + "HH", 9, len(value)) + value
        body = _pad4(body)
    body += struct.pack(endianness + "I", 0)
    return _block(endianness, 0x00000001, body)


def _epb(endianness, interface_id, ts_high, ts_low, data, packet_len=None):
    if packet_len is None:
        packet_len = len(data)
    body = struct.pack(
        endianness + "IIIII",
        interface_id,
        ts_high,
        ts_low,
        len(data),
        packet_len,
    )
    body += _pad4(data)
    body += struct.pack(endianness + "I", 0)
    return _block(endianness, 0x00000006, body)


def _spb(endianness, packet_len, data):
    body = struct.pack(endianness + "I", packet_len) + _pad4(data)
    return _block(endianness, 0x00000003, body)


def _obsolete(endianness, interface_id, ts_high, ts_low, data):
    body = struct.pack(
        endianness + "HHIIII",
        interface_id,
        0,
        ts_high,
        ts_low,
        len(data),
        len(data),
    )
    body += _pad4(data)
    body += struct.pack(endianness + "I", 0)
    return _block(endianness, 0x00000002, body)


def _unknown(endianness, block_type, payload):
    return _block(endianness, block_type, payload)


# --------------------------------------------------------------------- #
# Fixture: two sections, different byte orders, multiple interfaces,
# unknown blocks and all three packet block flavours.
# --------------------------------------------------------------------- #


N_PACKETS_SECTION = 400


def _payload(section_idx, packet_idx):
    # Deterministic, unique payload with a recognisable marker.
    head = b"PKT" + bytes([section_idx, packet_idx & 0xFF])
    size = 40 + (packet_idx * 37) % 180
    body = bytes(
        ((packet_idx * 31 + shift * 7 + section_idx * 13) & 0xFF)
        for shift in range(size - len(head))
    )
    return head + body


def build_complex_capture():
    """Return the bytes of the synthesized multi-section capture."""
    out = bytearray()

    # --- Section 0: little endian, two interfaces --------------------
    out += _shb("<")
    out += _idb("<", link_type=1, snaplen=0)  # if0: ethernet, unlimited
    # if1: raw IPv4 (linktype 12), snaplen 64, binary timestamp res 2^-9
    out += _idb("<", link_type=12, snaplen=64, tsresol_byte=0x89)

    counter = 0
    for i in range(N_PACKETS_SECTION):
        data = _payload(0, i)
        if i % 5 == 1:
            # Packet captured on interface 1: truncated to 64 bytes.
            out += _epb("<", 1, counter >> 32, counter & 0xFFFFFFFF,
                        data[:64], packet_len=len(data))
        elif i % 7 == 3:
            # Simple packet blocks always belong to interface 0, whose
            # snap length here is zero (unlimited).
            out += _spb("<", len(data), data)
        elif i % 11 == 5:
            out += _obsolete("<", 0, counter >> 32, counter & 0xFFFFFFFF,
                             data)
        else:
            out += _epb("<", 0, counter >> 32, counter & 0xFFFFFFFF, data)
        counter += 1
        if i % 50 == 25:
            # Interleave an unknown, non-reserved block type.
            out += _unknown("<", 0x00004000, b"unknown-block-payload")

    # --- Section 1: big endian ---------------------------------------
    out += _shb(">")
    out += _idb(">", link_type=1, snaplen=100, tsresol_byte=0x06)
    out += _idb(">", link_type=113, snaplen=0, tsresol_byte=0x06)
    counter = 0
    for i in range(N_PACKETS_SECTION):
        data = _payload(1, i)
        if i % 6 == 2:
            out += _spb(">", len(data), data[: min(100, len(data))]
                        if len(data) > 100 else data)
        elif i % 4 == 1:
            out += _epb(">", 1, counter >> 32, counter & 0xFFFFFFFF, data)
        else:
            out += _epb(">", 0, counter >> 32, counter & 0xFFFFFFFF, data)
        counter += 1
        if i % 70 == 10:
            out += _unknown(">", 0x0000BEEF & 0xFFFFFFFF, b"more-unknown")

    return bytes(out)


@pytest.fixture
def captured_file(tmp_path):
    path = tmp_path / "capture.pcapng"
    data = build_complex_capture()
    path.write_bytes(data)
    return path


def _reference_packets(path):
    """Full-scan reference: metadata of every packet block."""
    result = []
    with open(str(path), "rb") as fp:
        section = -1
        for block in FileScanner(fp):
            if type(block).__name__ == "SectionHeader":
                section += 1
            if isinstance(block, PACKET_TYPES):
                result.append((section, block))
    return result


def _expected_tuple(section_ordinal, block):
    if isinstance(block, SimplePacket):
        high = low = timestamp = None
    else:
        high = block.timestamp_high
        low = block.timestamp_low
        timestamp = block.timestamp
    return (
        type(block),
        section_ordinal,
        block.interface_id,
        block.interface.link_type,
        high,
        low,
        timestamp,
        block.interface.timestamp_resolution,
        block.captured_len,
        block.packet_len,
        bytes(block.packet_data),
    )


def _actual_tuple(packet):
    type_by_magic = {
        EnhancedPacket.magic_number: EnhancedPacket,
        SimplePacket.magic_number: SimplePacket,
        ObsoletePacket.magic_number: ObsoletePacket,
    }
    return (
        type_by_magic[packet.block_type],
        packet.section,
        packet.interface_id,
        packet.link_type,
        packet.timestamp_high,
        packet.timestamp_low,
        packet.timestamp,
        packet.timestamp_resolution,
        packet.captured_len,
        packet.packet_len,
        bytes(packet.packet_data),
    )


# --------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------- #


def test_random_read_matches_full_scan(captured_file):
    reference = _reference_packets(captured_file)
    expected = [_expected_tuple(section, block) for section, block in reference]

    index = build_index(str(captured_file))
    assert index.packet_count == len(reference)

    with open_index(str(captured_file)) as packet_index:
        assert len(packet_index) == len(reference)
        with packet_index.open_reader() as reader:
            actual = [
                _actual_tuple(packet) for packet in reader.read_range()
            ]

    assert len(actual) == len(expected)
    for position, (got, want) in enumerate(zip(actual, expected)):
        assert got == want, "mismatch at packet {0}".format(position)


def test_random_index_access_each_packet(captured_file):
    reference = _reference_packets(captured_file)
    expected = [_expected_tuple(section, block) for section, block in reference]

    build_index(str(captured_file))
    with open_index(str(captured_file)) as packet_index:
        with packet_index.open_reader() as reader:
            for position in range(len(expected)):
                packet = reader.read_packet(position)
                assert _actual_tuple(packet) == expected[position]


def test_ranges_and_negative_indices(captured_file):
    reference = _reference_packets(captured_file)
    expected = [_expected_tuple(section, block) for section, block in reference]
    build_index(str(captured_file))

    with open_index(str(captured_file)) as packet_index:
        with packet_index.open_reader() as reader:
            tail = [_actual_tuple(p) for p in reader.read_range(-5, None)]
            assert tail == expected[-5:]

            middle = [_actual_tuple(p) for p in reader.read_range(10, 13)]
            assert middle == expected[10:13]

            single = [_actual_tuple(p) for p in reader.read_range(7, 8)]
            assert single == expected[7:8]

            empty = list(reader.read_range(100, 50))
            assert empty == []

            out_of_range = list(reader.read_range(len(expected), len(expected)))
            assert out_of_range == []

            with pytest.raises(IndexError):
                reader.read_packet(len(expected))
            with pytest.raises(IndexError):
                reader.read_packet(-len(expected) - 1)


def test_trailing_read_does_not_rescan(captured_file):
    """
    A read targeting packets at the very end of the file must transfer
    essentially only those blocks' bytes from disk -- no prefix scan.
    """
    build_index(str(captured_file))
    with open_index(str(captured_file), verify=False) as packet_index:
        total = os.path.getsize(str(captured_file))

        with open(str(captured_file), "rb") as fp:
            counter = CountingReader(fp)
            with packet_index.open_reader(counter) as reader:
                last = reader.read_packet(len(packet_index) - 1)

        # Exact accounting: type+length+body(+pad)+trailing length, i.e.
        # exactly the on-disk span of that one block, nothing before it.
        offset, block_length, _, _ = packet_index._record(
            len(packet_index) - 1
        )
        assert counter.bytes_read == block_length
        assert block_length < total * 0.05
        assert last.offset == offset

        with open(str(captured_file), "rb") as fp:
            counter = CountingReader(fp)
            with packet_index.open_reader(counter) as reader:
                window = list(
                    reader.read_range(len(packet_index) - 8, len(packet_index))
                )

        spans = sum(
            packet_index._record(index)[1]
            for index in range(len(packet_index) - 8, len(packet_index))
        )
        assert len(window) == 8
        assert counter.bytes_read == spans
        assert counter.bytes_read < total * 0.05


def test_read_volume_scales_with_range(captured_file):
    build_index(str(captured_file))
    with open_index(str(captured_file), verify=False) as packet_index:
        count = len(packet_index)

        def bytes_for(n_packets):
            with open(str(captured_file), "rb") as fp:
                counter = CountingReader(fp)
                with packet_index.open_reader(counter) as reader:
                    packets = list(reader.read_range(0, n_packets))
                assert len(packets) == n_packets
                return counter.bytes_read

        one = bytes_for(1)
        fifty = bytes_for(50)
        assert one < fifty
        # Both are far below a full scan regardless of requested position;
        # the 50-packet read still touches a tiny fraction of the file.
        total = os.path.getsize(str(captured_file))
        assert fifty < total * 0.2


def test_truncated_file_rejected(captured_file):
    build_index(str(captured_file))
    original = captured_file.read_bytes()
    captured_file.write_bytes(original[: len(original) // 2])

    with pytest.raises(StaleIndexError):
        open_index(str(captured_file))


def test_appended_file_rejected(captured_file):
    build_index(str(captured_file))
    with open(str(captured_file), "ab") as fp:
        fp.write(b"\x00" * 64)
    with pytest.raises(StaleIndexError):
        open_index(str(captured_file))



def test_same_length_rewrite_rejected(captured_file):
    build_index(str(captured_file))
    original = bytearray(captured_file.read_bytes())

    # Flip one byte inside the final packet's stored data: the block
    # structure stays intact and the file length is unchanged, so only a
    # whole-content fingerprint can detect the rewrite.
    with open_index(str(captured_file), verify=False) as packet_index:
        last_offset, last_length, _, _ = packet_index._record(
            packet_index.packet_count - 1
        )
    tamper_offset = last_offset + min(40, last_length - 8)
    original[tamper_offset] ^= 0xFF
    captured_file.write_bytes(bytes(original))

    with pytest.raises(StaleIndexError):
        open_index(str(captured_file))


def test_replaced_same_size_different_content_rejected(captured_file, tmp_path):
    index_path = str(captured_file) + ".pcngidx"
    build_index(str(captured_file), index_path)
    size = os.path.getsize(str(captured_file))

    # Unrelated bytes of the exact same length; only the fingerprint
    # distinguishes this from the original capture.
    other = tmp_path / "replacement.pcapng"
    other.write_bytes(b"\xAB" * size)
    with pytest.raises(StaleIndexError):
        open_index(str(other), index_path)


def test_index_does_not_store_payloads(captured_file):
    index_path = str(captured_file) + ".pcngidx"
    build_index(str(captured_file))
    blob = open(index_path, "rb").read()

    # Eight bytes copied out of a real packet payload must never appear
    # in the index itself.
    reference = _reference_packets(captured_file)
    middle = reference[len(reference) // 2][1]
    marker = bytes(middle.packet_data)[8:16]
    assert len(marker) == 8
    assert marker not in blob
    assert len(blob) < os.path.getsize(str(captured_file)) * 0.2


def test_index_file_size_format(captured_file):
    from pcapng.index import INDEX_MAGIC, _RECORD_SIZE

    index_path = str(captured_file) + ".pcngidx"
    packet_index = build_index(str(captured_file))
    blob = open(index_path, "rb").read()
    assert blob[:8] == INDEX_MAGIC
    header_len = struct.unpack("<I", blob[8:12])[0]
    records_area = len(blob) - 12 - header_len
    assert records_area == packet_index.packet_count * _RECORD_SIZE



def test_unknown_blocks_are_skipped(captured_file):
    reference = _reference_packets(captured_file)
    index = build_index(str(captured_file))
    # Unknown blocks are present in the file but not indexed as packets.
    assert index.packet_count == len(reference)


def test_real_capture_files(tmp_path):
    from pcapng.index import open_index as _open

    cases = [
        ("test006-fixed.ntar", ObsoletePacket),
        ("test007.ntar", SimplePacket),
        ("test010.ntar", SimplePacket),
    ]
    for source_name, expected_type in cases:
        source = os.path.join("test_data", source_name)
        target = tmp_path / source_name
        target.write_bytes(open(source, "rb").read())
        reference = _reference_packets(target)
        build_index(str(target))
        with _open(str(target)) as packet_index:
            with packet_index.open_reader() as reader:
                packets = list(reader.read_range())
        assert len(packets) == len(reference)
        for packet, (section, block) in zip(packets, reference):
            assert packet.block_type == expected_type.magic_number
            assert _actual_tuple(packet) == _expected_tuple(section, block)


def test_large_capture_end_location_is_constant_size(tmp_path):
    """
    On a capture with thousands of packets, locating and reading the last
    packets transfers a constant, sub-1% slice of the file rather than
    rescanning everything.
    """
    total_packets = 5000
    out = bytearray(_shb("<"))
    out += _idb("<", link_type=1, snaplen=0)
    for i in range(total_packets):
        payload = (bytes([i & 0xFF, (i >> 8) & 0xFF]) * 50)
        out += _epb("<", 0, i >> 32, i & 0xFFFFFFFF, payload)
    path = tmp_path / "large.pcapng"
    path.write_bytes(bytes(out))
    size = os.path.getsize(str(path))

    build_index(str(path))
    with open_index(str(path), verify=False) as packet_index:
        assert len(packet_index) == total_packets

        with open(str(path), "rb") as fp:
            counter = CountingReader(fp)
            with packet_index.open_reader(counter) as reader:
                last = reader.read_packet(-1)

        assert counter.bytes_read < size * 0.01
        assert last.captured_len == 100
        assert last.packet_len == 100

        with open(str(path), "rb") as fp:
            counter = CountingReader(fp)
            with packet_index.open_reader(counter) as reader:
                window = list(reader.read_range(total_packets - 10, None))

        spans = sum(
            packet_index._record(index)[1]
            for index in range(total_packets - 10, total_packets)
        )
        assert [packet.index for packet in window] == list(
            range(total_packets - 10, total_packets)
        )
        assert counter.bytes_read == spans < size * 0.01


def test_build_index_hashes_every_file_byte(tmp_path):
    """The fingerprint bound at build time is the SHA-256 of the full file."""
    path = tmp_path / "capture.pcapng"
    path.write_bytes(build_complex_capture())
    expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()

    index_path = str(path) + ".pcngidx"
    build_index(str(path), index_path)

    import json
    blob = open(index_path, "rb").read()
    header_len = struct.unpack("<I", blob[8:12])[0]
    header = json.loads(blob[12 : 12 + header_len])
    assert header["sha256"] == expected_digest
    assert header["file_size"] == len(path.read_bytes())
