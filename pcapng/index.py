"""
Sidecar index and random access for large pcapng files.

A full sequential scan just to reach packet number N in a multi-gigabyte
capture is expensive. This module provides:

* :func:`build_index` -- scan a pcapng file once and write a compact
  sidecar index recording the file offset of every packet block together
  with the section/interface context required to resume parsing at that
  offset (section byte order; per-interface link type, snap length and
  timestamp resolution). Packet payloads are never stored in the index.

* :func:`open_index` / :class:`PacketIndex` -- load a sidecar index and
  validate it against the capture using the file size and a full-file
  SHA-256 content fingerprint; a replaced or same-length rewritten file
  is rejected.

* :class:`IndexReader` -- read any contiguous range of packet indices
  without rescanning preceding packets; essentially only the requested
  blocks are transferred from disk.

* :class:`CountingReader` -- a file wrapper counting bytes returned by
  ``read()`` (seeks are free), useful to prove a random read did not fall
  back to a full scan.

Index on-disk format (little endian)::

    magic       8 bytes   b"PCNGIDX1"
    header_len  uint32    byte length of the JSON header
    header      JSON      {"version", "file_size", "sha256",
                           "packet_count", "sections": [{"endianness",
                           "interfaces": [{"link_type", "snaplen",
                           "ts_resolution"}]}]}
    records     N * 24 B  one record per packet in capture order:
                              offset       uint64 (of the block type word)
                              block_length uint32 (whole block, incl. hdr)
                              info         uint32 (bits 0-1 kind:
                                           1 EPB, 2 SPB, 3 obsolete
                                           Packet Block; bits 8-31 section
                                           ordinal)

Multiple sections with different byte orders, unknown blocks and multiple
interfaces are supported. Unknown blocks are skipped during indexing and
each packet record references the ordinal of its owning section.
"""

import hashlib
import io
import json
import mmap
import os
import struct

from pcapng import blocks as blocks_mod
from pcapng.exceptions import (
    CorruptedFile,
    PcapngLoadError,
    StaleIndexError,
    StreamEmpty,
)
from pcapng.scanner import FileScanner

INDEX_MAGIC = b"PCNGIDX1"
INDEX_VERSION = 1
INDEX_SUFFIX = ".pcngidx"
_HASH_CHUNK_SIZE = 1024 * 1024
_RECORD_STRUCT = struct.Struct("<QII")
_RECORD_SIZE = _RECORD_STRUCT.size

_KIND_ENHANCED = 1
_KIND_SIMPLE = 2
_KIND_OBSOLETE = 3
_KIND_MASK = 0xFF
_SECTION_SHIFT = 8

_PACKET_KINDS = {
    blocks_mod.EnhancedPacket: _KIND_ENHANCED,
    blocks_mod.SimplePacket: _KIND_SIMPLE,
    blocks_mod.ObsoletePacket: _KIND_OBSOLETE,
}


# --------------------------------------------------------------------- #
# File wrappers
# --------------------------------------------------------------------- #


class _HashingReader(object):
    """File wrapper hashing every read byte; used while building."""

    __slots__ = ["_fp", "_hasher", "bytes_read"]

    def __init__(self, fp, hasher):
        self._fp = fp
        self._hasher = hasher
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._fp.read(size)
        self._hasher.update(data)
        self.bytes_read += len(data)
        return data

    def tell(self):
        return self._fp.tell()

    def seek(self, pos, whence=io.SEEK_SET):
        return self._fp.seek(pos, whence)

    def close(self):
        return self._fp.close()


class CountingReader(object):
    """
    Wrap a binary file-like object counting bytes returned by
    :meth:`read`. :meth:`seek` does not add to the counter, so it measures
    data actually read from the underlying file rather than bytes skipped.
    """

    __slots__ = ["_fp", "bytes_read"]

    def __init__(self, fp):
        self._fp = fp
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._fp.read(size)
        self.bytes_read += len(data)
        return data

    def tell(self):
        return self._fp.tell()

    def seek(self, pos, whence=io.SEEK_SET):
        return self._fp.seek(pos, whence)

    def close(self):
        result = self._fp.close()
        self.bytes_read = 0
        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# --------------------------------------------------------------------- #
# Index construction
# --------------------------------------------------------------------- #


class _OffsetScanner(FileScanner):
    """FileScanner that also reports the start offset of each block."""

    def _read_next_block(self):
        offset = self.stream.tell()
        block_type = self._read_int(32, False)

        if block_type == 0x0A0D0D0A:
            block = self._read_section_header()
            self.current_section = block
            self.endianness = block.endianness
            block_length = self.stream.tell() - offset
            return offset, block_type, block_length, block

        if self.current_section is None:
            raise ValueError("File not starting with a proper section header")

        block = self._read_block(block_type)
        block_length = self.stream.tell() - offset
        return offset, block_type, block_length, block

    def iter_offset_blocks(self):
        while True:
            try:
                yield self._read_next_block()
            except StreamEmpty:
                return


def _interface_snapshot(interface_block):
    return {
        "link_type": interface_block.link_type,
        "snaplen": interface_block.snaplen,
        "ts_resolution": interface_block.timestamp_resolution,
    }


def _scan_capture(stream):
    """
    One sequential pass over the whole capture. Returns
    ``(sections, records)`` where ``sections`` is a list of
    ``{"endianness", "interfaces"}`` dicts and ``records`` is a list of
    ``(offset, block_length, kind, section_ordinal)`` tuples, one per
    packet block, in capture order.
    """
    sections = []
    section_ordinal = -1
    records = []

    for offset, block_type, block_length, block in (
        _OffsetScanner(stream).iter_offset_blocks()
    ):
        if block_type == 0x0A0D0D0A:
            section_ordinal += 1
            sections.append({"endianness": block.endianness, "interfaces": []})
        elif isinstance(block, blocks_mod.InterfaceDescription):
            sections[section_ordinal]["interfaces"].append(
                _interface_snapshot(block)
            )
        else:
            kind = _PACKET_KINDS.get(type(block))
            if kind is not None:
                records.append((offset, block_length, kind, section_ordinal))

    return sections, records


def _encode_record(offset, block_length, kind, section_ordinal):
    info = kind | (section_ordinal << _SECTION_SHIFT)
    return _RECORD_STRUCT.pack(offset, block_length, info)


def _decode_record(raw):
    offset, block_length, info = _RECORD_STRUCT.unpack(raw)
    kind = info & _KIND_MASK
    section_ordinal = info >> _SECTION_SHIFT
    return offset, block_length, kind, section_ordinal


# --------------------------------------------------------------------- #
# Minimal section/interface context for resuming parsing at an offset
# --------------------------------------------------------------------- #


class _ResumeInterface(object):
    """Stand-in for an InterfaceDescription block when resuming a read."""

    __slots__ = ["interface_id", "link_type", "snaplen", "timestamp_resolution"]

    def __init__(self, interface_id, snapshot):
        self.interface_id = interface_id
        self.link_type = snapshot["link_type"]
        self.snaplen = snapshot["snaplen"]
        self.timestamp_resolution = snapshot["ts_resolution"]


class _ResumeSection(object):
    """
    Stand-in for a SectionHeader carrying exactly the state required to
    construct packet block objects (byte order and interface registry).
    """

    __slots__ = ["endianness", "interfaces"]

    def __init__(self, endianness, interface_snapshots):
        self.endianness = endianness
        self.interfaces = {
            idx: _ResumeInterface(idx, snapshot)
            for idx, snapshot in enumerate(interface_snapshots)
        }

    def new_member(self, cls, **kwargs):
        block = cls(section=self, endianness=self.endianness, **kwargs)
        return block


class IndexedPacket(object):
    """
    A packet retrieved through random access.

    Attributes:
        index: zero-based global packet ordinal (packet blocks only).
        offset: absolute file offset of the block type word.
        block_type: pcapng block type magic (0x2 obsolete Packet,
            0x3 Simple Packet, 0x6 Enhanced Packet).
        section: ordinal of the owning section.
        interface_id: interface the packet was captured on (always 0 for
            Simple Packet Blocks).
        link_type: data link type of the capturing interface.
        timestamp_high/timestamp_low: raw 64-bit timestamp halves; both
            ``None`` for Simple Packet Blocks.
        timestamp: timestamp in seconds as a float (``None`` for SPBs).
        timestamp_resolution: resolution multiplier of the interface
            timestamp units.
        captured_len: number of bytes stored in the block.
        packet_len: original on-the-wire packet length.
        packet_data: captured packet bytes, read from the pcapng file.
    """

    __slots__ = [
        "index",
        "offset",
        "block_type",
        "section",
        "interface_id",
        "link_type",
        "timestamp_high",
        "timestamp_low",
        "timestamp",
        "timestamp_resolution",
        "captured_len",
        "packet_len",
        "packet_data",
    ]

    def __init__(self, **kwargs):
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))

    def __repr__(self):
        return (
            "IndexedPacket(index={0!r}, offset={1!r}, section={2!r}, "
            "interface_id={3!r}, captured_len={4!r}, packet_len={5!r})"
        ).format(
            self.index,
            self.offset,
            self.section,
            self.interface_id,
            self.captured_len,
            self.packet_len,
        )


# --------------------------------------------------------------------- #
# Sidecar file (de)serialization
# --------------------------------------------------------------------- #


def build_index(path, index_path=None, stream=None):
    """
    Build a sidecar index for the pcapng file at ``path``.

    The file is scanned exactly once from start to end; while scanning,
    every transferred byte is fed to a SHA-256 hasher, and the resulting
    digest together with the file size is bound into the index.

    :param path: path to the pcapng file.
    :param index_path: path for the sidecar index; defaults to
        ``path + INDEX_SUFFIX``.
    :param stream: optional open binary file object (mainly for tests);
        when given it must be positioned at the start of the file and is
        not closed by this function.
    :returns: the :class:`PacketIndex` built for the file.
    """
    if index_path is None:
        index_path = path + INDEX_SUFFIX

    opened = False
    if stream is None:
        stream = open(path, "rb")
        opened = True

    hasher = hashlib.sha256()
    hashing_stream = _HashingReader(stream, hasher)
    try:
        sections, records = _scan_capture(hashing_stream)
        file_size = stream.seek(0, io.SEEK_END)
        digest = hasher.hexdigest()
    finally:
        if opened:
            stream.close()

    header = {
        "version": INDEX_VERSION,
        "file_size": file_size,
        "sha256": digest,
        "packet_count": len(records),
        "sections": sections,
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    tmp_path = index_path + ".tmp"
    with open(tmp_path, "wb") as out:
        out.write(INDEX_MAGIC)
        out.write(struct.pack("<I", len(header_bytes)))
        out.write(header_bytes)
        for offset, block_length, kind, section_ordinal in records:
            out.write(
                _encode_record(offset, block_length, kind, section_ordinal)
            )
    os.replace(tmp_path, index_path)

    return PacketIndex(path, index_path, header)


def _read_index_file(index_path):
    with open(index_path, "rb") as fp:
        magic = fp.read(len(INDEX_MAGIC))
        if magic != INDEX_MAGIC:
            raise PcapngLoadError("Not a pcapng index file: {0!r}".format(index_path))
        (header_len,) = struct.unpack("<I", fp.read(4))
        if header_len <= 0 or header_len > 64 * 1024 * 1024:
            raise PcapngLoadError("Invalid header length in index file")
        header = json.loads(fp.read(header_len).decode("utf-8"))
        record_blob = fp.read()

    if len(record_blob) % _RECORD_SIZE != 0:
        raise PcapngLoadError("Corrupt index record area")

    records = [
        _decode_record(record_blob[i : i + _RECORD_SIZE])
        for i in range(0, len(record_blob), _RECORD_SIZE)
    ]
    if header.get("packet_count") != len(records):
        raise PcapngLoadError("Index packet count does not match records")
    if header.get("version") != INDEX_VERSION:
        raise PcapngLoadError(
            "Unsupported index version: {0!r}".format(header.get("version"))
        )
    return header, records


def _verify_fingerprint(path, file_size, digest):
    """Check file size and full-content SHA-256; raise StaleIndexError."""
    actual_size = os.path.getsize(path)
    if actual_size != file_size:
        raise StaleIndexError(
            "File size changed: index has {0} bytes, file now has {1} "
            "bytes; rebuild the index".format(file_size, actual_size)
        )
    hasher = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    if hasher.hexdigest() != digest:
        raise StaleIndexError(
            "Content fingerprint mismatch for {0!r}; the file was "
            "replaced or rewritten, rebuild the index".format(path)
        )


def open_index(path, index_path=None, verify=True):
    """
    Load and validate the sidecar index for the pcapng file at ``path``.

    :param verify: when True (default) validate file size and SHA-256
        content fingerprint before accepting the index. The fingerprint
        pass is a single sequential hash of the whole file and does not
        parse packets; once validated, random reads never rescan it.
    :raises StaleIndexError: if the capture was replaced or rewritten
        (including a same-length rewrite).
    """
    if index_path is None:
        index_path = path + INDEX_SUFFIX
    header, records = _read_index_file(index_path)
    if verify:
        _verify_fingerprint(
            path, header["file_size"], header["sha256"]
        )
    return PacketIndex(path, index_path, header, records)


_BLOCK_TYPE_BY_KIND = {
    _KIND_ENHANCED: blocks_mod.EnhancedPacket.magic_number,
    _KIND_SIMPLE: blocks_mod.SimplePacket.magic_number,
    _KIND_OBSOLETE: blocks_mod.ObsoletePacket.magic_number,
}
_BLOCK_CLASS_BY_KIND = {
    _KIND_ENHANCED: blocks_mod.EnhancedPacket,
    _KIND_SIMPLE: blocks_mod.SimplePacket,
    _KIND_OBSOLETE: blocks_mod.ObsoletePacket,
}
_STRUCT_U32 = struct.Struct("<I")


class PacketIndex(object):
    """
    A validated sidecar index bound to a pcapng file.

    Indexed packet records are memory-mapped from the sidecar file, so a
    multi-million-packet index costs a few dozen bytes of resident memory
    per accessed record instead of loading everything up front.
    """

    __slots__ = [
        "path",
        "index_path",
        "file_size",
        "packet_count",
        "_header",
        "_records",
        "_mm",
        "_index_fp",
        "_record_base",
        "_sections",
    ]

    def __init__(self, path, index_path, header, records=None):
        self.path = path
        self.index_path = index_path
        self._header = header
        self.file_size = header["file_size"]
        self.packet_count = header["packet_count"]
        self._sections = [
            _ResumeSection(section["endianness"], section["interfaces"])
            for section in header["sections"]
        ]
        self._mm = None
        self._index_fp = None
        self._record_base = 0
        self._records = None
        if records is not None:
            self._records = records
        else:
            self._open_mmap()

    def _open_mmap(self):
        self._index_fp = open(self.index_path, "rb")
        self._index_fp.seek(len(INDEX_MAGIC) + 4)
        (header_len,) = _STRUCT_U32.unpack(self._index_fp.read(4))
        self._index_fp.seek(len(INDEX_MAGIC) + 4 + header_len)
        self._record_base = self._index_fp.tell()
        try:
            self._mm = mmap.mmap(
                self._index_fp.fileno(), 0, access=mmap.ACCESS_READ
            )
        except (ValueError, OSError):  # pragma: no cover - platform fallback
            self._records = [
                _decode_record(
                    self._index_fp.read(_RECORD_SIZE)
                )
                for _ in range(self.packet_count)
            ]
            self._index_fp.close()
            self._index_fp = None

    def close(self):
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._index_fp is not None:
            self._index_fp.close()
            self._index_fp = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self):
        return self.packet_count

    def _record(self, packet_index):
        if packet_index < 0 or packet_index >= self.packet_count:
            raise IndexError(
                "Packet index {0} out of range (0..{1})".format(
                    packet_index, self.packet_count - 1
                )
            )
        if self._records is not None:
            return self._records[packet_index]
        start = self._record_base + packet_index * _RECORD_SIZE
        return _decode_record(self._mm[start : start + _RECORD_SIZE])

    def section_context(self, section_ordinal):
        return self._sections[section_ordinal]

    def open_reader(self, stream=None):
        """Open an :class:`IndexReader` over the bound pcapng file."""
        return IndexReader(self, stream=stream)


class IndexReader(object):
    """
    Random-access reader over a pcapng file using a validated index.

    Only the blocks requested are parsed and read; no earlier packets are
    scanned. Wrap the file object in :class:`CountingReader` to observe
    how many bytes were actually transferred.
    """

    __slots__ = ["index", "_stream", "_owned"]

    def __init__(self, index, stream=None):
        self.index = index
        self._owned = stream is None
        if stream is None:
            stream = open(index.path, "rb")
        self._stream = stream

    def close(self):
        if self._owned and self._stream is not None:
            self._stream.close()
        self._stream = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self):
        return self.index.packet_count

    def read_packet(self, packet_index):
        """Read and parse a single packet by global packet ordinal."""
        if packet_index < 0:
            packet_index += self.index.packet_count
        offset, block_length, kind, section_ordinal = self.index._record(
            packet_index
        )
        block_type, block = self._parse_block(
            offset, block_length, kind, section_ordinal
        )
        return self._to_packet(
            packet_index, offset, block_type, section_ordinal, block
        )

    def read_range(self, start=None, stop=None):
        """
        Yield packets with indices in the half-open range ``[start, stop)``.

        Defaults mirror slicing: ``read_range()`` yields everything,
        ``read_range(n)`` yields ``[n, end)``. Negative indices count from
        the end. The underlying stream is positioned at the first block
        once and advanced block by block, so reads stay strictly local to
        the requested interval.
        """
        start, stop = self._normalize_slice(start, stop)
        stream = self._stream
        for packet_index in range(start, stop):
            offset, block_length, kind, section_ordinal = self.index._record(
                packet_index
            )
            stream.seek(offset)
            block_type, block = self._parse_block_at(
                block_length, kind, section_ordinal
            )
            yield self._to_packet(
                packet_index, offset, block_type, section_ordinal, block
            )

    def _normalize_slice(self, start, stop):
        count = self.index.packet_count
        if start is None:
            start = 0
        if stop is None:
            stop = count
        if start < 0:
            start += count
        if stop < 0:
            stop += count
        start = max(0, min(start, count))
        stop = max(0, min(stop, count))
        if stop < start:
            stop = start
        return start, stop

    def _parse_block(self, offset, block_length, kind, section_ordinal):
        self._stream.seek(offset)
        return self._parse_block_at(block_length, kind, section_ordinal)

    def _parse_block_at(self, block_length, kind, section_ordinal):
        stream = self._stream
        section = self.index.section_context(section_ordinal)
        endianness = section.endianness

        # Block type (4) + block length (4), read with the section byte
        # order. These sanity checks guarantee a stale/relocated record
        # can never silently return the wrong packet.
        type_raw = _read_exact(stream, 4)
        (block_type,) = struct.unpack(endianness + "I", type_raw)
        expected_type = _BLOCK_TYPE_BY_KIND[kind]
        if block_type != expected_type:
            raise CorruptedFile(
                "Block type at indexed offset is 0x{0:08X}, expected "
                "0x{1:08X}; index does not match file".format(
                    block_type, expected_type
                )
            )
        (leading_length,) = struct.unpack(
            endianness + "I", _read_exact(stream, 4)
        )
        # Layout: type(4) length(4) body(...) length(4). The body is
        # padded up to a multiple of 4; some real-world files write a
        # non-multiple-of-4 length field (e.g. SPB in test007), and the
        # library tolerates that by relying on the padding. Compute the
        # actual on-disk span exactly like read_bytes_padded does and
        # require it to match the span observed while indexing.
        body_length = leading_length - 12
        padded_body_length = (
            body_length + (-body_length % 4)
        )
        on_disk_span = 8 + padded_body_length + 4
        if on_disk_span != block_length:
            raise CorruptedFile(
                "Block span mismatch at indexed offset: length field "
                "implies {0} bytes, index recorded {1}".format(
                    on_disk_span, block_length
                )
            )
        body = _read_exact(stream, body_length)
        if padded_body_length != body_length:
            _read_exact(stream, padded_body_length - body_length)
        (trailing_length,) = struct.unpack(
            endianness + "I", _read_exact(stream, 4)
        )
        if trailing_length != leading_length:
            raise CorruptedFile(
                "Trailing block length {0} != leading {1}".format(
                    trailing_length, leading_length
                )
            )

        cls = _BLOCK_CLASS_BY_KIND[kind]
        if kind == _KIND_SIMPLE:
            block = cls(section=section, raw=body, endianness=endianness)
        else:
            block = section.new_member(cls, raw=body)
        return block_type, block

    @staticmethod
    def _to_packet(packet_index, offset, block_type, section_ordinal, block):
        interface = block.interface
        timestamp_high = getattr(block, "timestamp_high", None)
        timestamp_low = getattr(block, "timestamp_low", None)
        timestamp = None
        if timestamp_high is not None and timestamp_low is not None:
            timestamp = block.timestamp
        return IndexedPacket(
            index=packet_index,
            offset=offset,
            block_type=block_type,
            section=section_ordinal,
            interface_id=block.interface_id,
            link_type=interface.link_type,
            timestamp_high=timestamp_high,
            timestamp_low=timestamp_low,
            timestamp=timestamp,
            timestamp_resolution=interface.timestamp_resolution,
            captured_len=block.captured_len,
            packet_len=block.packet_len,
            packet_data=block.packet_data,
        )


def _read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise CorruptedFile(
            "Short read: wanted {0} bytes, got {1}".format(size, len(data))
        )
    return data
