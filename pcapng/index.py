"""
Sidecar index for random access to packets in large pcapng files.

A full :class:`~pcapng.scanner.FileScanner` pass always starts at the
beginning of the file, which makes reading a single packet near the end
of a large capture prohibitively expensive.  This module builds a
*sidecar index* that records, for every packet block, its absolute file
offset together with the section / interface context needed to resume
parsing at that offset:

* the offset and byte order of the containing section;
* the exact on-disk bytes of the section header and of every interface
  description block preceding the packet.

The index never stores ``packet_data`` (nor any other packet payload);
on a random read the packet bytes are always fetched from the pcapng
file itself and checked against a per-block digest recorded while
indexing.

To detect a replaced or same-length-rewritten file, the index is bound
to the file size and to a content fingerprint computed over the file
head, tail, periodically sampled interior windows and every section
header.  A separate per-block digest is verified for every context
block and every packet returned by a random read, so a stale index can
never cause the wrong packet to be returned: an exception is raised
instead.

Typical usage::

    from pcapng.index import build_index_file, IndexedReader

    build_index_file("capture.pcapng")
    with IndexedReader.open_path("capture.pcapng") as reader:
        for packet in reader.read_range(1000, 1050):
            ...
        last = reader[-1]
"""

import hashlib
import io
import json
import struct

import pcapng.blocks as blocks
from pcapng._compat import namedtuple
from pcapng.constants.block_types import (
    BLK_ENHANCED_PACKET,
    BLK_INTERFACE,
    BLK_PACKET,
    BLK_PACKET_SIMPLE,
    BLK_RESERVED,
    BLK_RESERVED_CORRUPTED,
    BLK_SECTION_HEADER,
)
from pcapng.exceptions import (
    CorruptedFile,
    InvalidIndexError,
    StaleIndexError,
    TruncatedFile,
)
from pcapng.structs import (
    BYTE_ORDER_MAGIC,
    BYTE_ORDER_MAGIC_INVERSE,
    read_int,
)

INDEX_MAGIC = b"PXIDX001"
INDEX_SUFFIX = ".pxidx"

# Magic values identifying a packet-bearing block.
PACKET_BLOCK_TYPES = frozenset(
    (BLK_PACKET, BLK_PACKET_SIMPLE, BLK_ENHANCED_PACKET)
)

# ---------------------------------------------------------------------------
# Fingerprint parameters
#
# Files at or below this size are hashed in full: the cost is negligible.
# For larger files the fingerprint covers the head, the tail, interior
# windows sampled on a fixed grid, and every section header.  Per-block
# digests still guarantee integrity of every actually returned packet.
# ---------------------------------------------------------------------------
FULL_FINGERPRINT_MAX_SIZE = 4 * 1024 * 1024
HEAD_WINDOW_SIZE = 64 * 1024
TAIL_WINDOW_SIZE = 64 * 1024
SAMPLE_WINDOW_SIZE = 4096
MAX_INTERIOR_SAMPLES = 64
ANCHOR_WINDOW_SIZE = 128

_DIGEST_SIZE = 8
_FP_DIGEST_SIZE = 16

# Fixed-size on-disk record for one packet block (little-endian):
#   packet ordinal (u64), file offset (u64), block length (u64),
#   section id (i32), interface id (i32), block type (u32),
#   block digest (8 raw bytes)
_RECORD_STRUCT = struct.Struct("<QQQiiI8s")
_RECORD_SIZE = _RECORD_STRUCT.size


def _digest(data):
    return hashlib.blake2b(data, digest_size=_DIGEST_SIZE).digest()


def _merge_windows(windows):
    """Merge overlapping/adjacent ``(start, end)`` half-open windows."""
    windows = sorted((start, end) for start, end in windows if end > start)
    merged = []
    for start, end in windows:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end
    return [(start, end) for start, end in merged]


def fingerprint_windows(size, section_offsets=()):
    """
    Return the sorted list of ``(start, end)`` half-open byte windows that
    make up the content fingerprint for a file of the given size.

    :param size: total file size in bytes
    :param section_offsets: offsets of every section header block; those
        locations are additionally anchored in the fingerprint.
    """
    if size < 0:
        raise ValueError("size must be non-negative")
    if size <= FULL_FINGERPRINT_MAX_SIZE:
        return [(0, size)] if size else []

    windows = [
        (0, min(size, HEAD_WINDOW_SIZE)),
        (max(0, size - TAIL_WINDOW_SIZE), size),
    ]
    middle_start = HEAD_WINDOW_SIZE
    middle_end = size - TAIL_WINDOW_SIZE
    if middle_end > middle_start:
        middle_len = middle_end - middle_start
        step = max(SAMPLE_WINDOW_SIZE, middle_len // (MAX_INTERIOR_SAMPLES + 1))
        pos = middle_start
        while pos < middle_end:
            windows.append((pos, min(pos + SAMPLE_WINDOW_SIZE, middle_end)))
            pos += step
    for offset in section_offsets:
        windows.append(
            (
                max(0, offset - ANCHOR_WINDOW_SIZE // 2),
                min(size, offset + ANCHOR_WINDOW_SIZE),
            )
        )
    return _merge_windows(windows)


def _read_exact(fp, size):
    data = fp.read(size)
    if len(data) < size:
        raise TruncatedFile(
            "trying to read {0} bytes, only got {1}".format(size, len(data))
        )
    return data


def compute_fingerprint(fp, size, section_offsets=()):
    """
    Compute ``(windows, digest)`` for an open seekable binary stream.

    The stream position is restored to where it was before the call.
    """
    windows = fingerprint_windows(size, section_offsets)
    saved = fp.tell()
    try:
        h = hashlib.blake2b(digest_size=_FP_DIGEST_SIZE)
        h.update(struct.pack("<Q", size))
        for start, end in windows:
            fp.seek(start)
            remaining = end - start
            while remaining:
                chunk = fp.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise TruncatedFile("file ended inside fingerprint window")
                h.update(chunk)
                remaining -= len(chunk)
        return windows, h.digest()
    finally:
        fp.seek(saved)


def _read_shb_envelope(fp, offset):
    """
    Read the full bytes of a section header block at ``offset``.

    The byte order magic inside the block determines endianness, which
    makes this safe across sections with different byte orders.
    """
    fp.seek(offset)
    header = _read_exact(fp, 12)
    block_type = struct.unpack(">I", header[0:4])[0]
    if block_type != BLK_SECTION_HEADER:
        raise CorruptedFile(
            "expected section header at {0}, got block 0x{1:08X}".format(
                offset, block_type
            )
        )
    bom = struct.unpack(">I", header[8:12])[0]
    if bom == BYTE_ORDER_MAGIC:
        endianness = ">"
    elif bom == BYTE_ORDER_MAGIC_INVERSE:
        endianness = "<"
    else:
        raise CorruptedFile("wrong byte order magic: 0x{0:08X}".format(bom))
    block_length = struct.unpack(endianness + "I", header[4:8])[0]
    if block_length < 28:
        raise CorruptedFile("invalid section header length {0}".format(block_length))
    envelope, _trailing = _read_block_envelope(
        fp, offset, block_length, endianness
    )
    return endianness, envelope


def _padded_length(block_length):
    """On-disk distance to the next block (blocks are 4-byte aligned)."""
    return block_length + (-block_length % 4)


def _read_block_envelope(fp, offset, block_length, endianness):
    """
    Read a block envelope of declared ``block_length`` starting at
    ``offset``.

    The repeated trailing length is read right before the next (4-byte
    aligned) block.  Strictly, ``block_length`` is always a multiple of 4,
    but some real-world files use an unpadded odd length; in that case
    padding bytes still appear before the next block and the envelope
    returned is the declared (unpadded) bytes, while the caller advances
    by :func:`_padded_length`.
    """
    # The trailing length sits right before the next (4-byte aligned)
    # block.  read_block_data likewise reads payload_length = length-12
    # bytes plus padding before the trailing length, so for odd declared
    # lengths the trailing field is at the padded position.
    total = _padded_length(block_length)
    fp.seek(offset + total - 4)
    trailing = read_int(fp, 32, signed=False, endianness=endianness)
    if trailing != block_length:
        raise CorruptedFile(
            "mismatching block lengths: {0} and {1}".format(block_length, trailing)
        )
    fp.seek(offset)
    envelope = _read_exact(fp, block_length)
    if total != block_length:
        # Consume (ignore) the alignment padding so sequential scans
        # advance to the next block.
        fp.seek(offset + total)
    return envelope, total


def _read_member_envelope(fp, offset, endianness):
    """
    Read a section member block at ``offset``.

    :returns: ``(block_type, block_length, envelope)`` where ``block_length``
        is the declared block length (padding excluded for odd-length
        blocks) and ``envelope`` are exactly the declared block bytes.
    """
    fp.seek(offset)
    block_type = read_int(fp, 32, signed=False, endianness=endianness)
    block_length = read_int(fp, 32, signed=False, endianness=endianness)
    # Note: the length is not required to be a multiple of 4 here.  The
    # library tolerates blocks with non-padded odd lengths (some capture
    # files in the wild are written that way and still parse).
    if block_length < 12:
        raise CorruptedFile("invalid block length {0}".format(block_length))
    envelope, _total = _read_block_envelope(
        fp, offset, block_length, endianness
    )
    return block_type, block_length, envelope


def _interface_id_of(block_type, envelope, endianness):
    """Extract the interface id referenced by a packet block."""
    # After block type and length (8 bytes):
    #  EPB (6): u32 interface id
    #  obsolete Packet (2): u16 interface id
    #  SPB (3): no interface id field -> 0 (first interface, per spec)
    if block_type == BLK_ENHANCED_PACKET:
        return struct.unpack(endianness + "i", envelope[8:12])[0]
    if block_type == BLK_PACKET:
        return struct.unpack(endianness + "h", envelope[8:10])[0]
    return 0


def _payload_after_shb(envelope):
    # The SectionHeader schema expects payload as produced by
    # read_section_header: the version/section_length/options bytes,
    # i.e. envelope[12:-4] (the byte order magic is not part of them).
    return envelope[12:-4]


def _member_payload(envelope):
    # Block payload sits between the leading [type, length] and the
    # trailing repeated length.
    return envelope[8:-4]


class PacketRecord(
    namedtuple(
        "PacketRecord",
        [
            "ordinal",
            "offset",
            "length",
            "section_id",
            "interface_id",
            "block_type",
            "digest",
        ],
    )
):
    """One index entry for a packet block."""

    __slots__ = ()

    def to_bytes(self):
        return _RECORD_STRUCT.pack(
            self.ordinal,
            self.offset,
            self.length,
            self.section_id,
            self.interface_id,
            self.block_type,
            self.digest,
        )

    @classmethod
    def from_bytes(cls, data):
        if len(data) != _RECORD_SIZE:
            raise InvalidIndexError(
                "bad packet record size: {0} != {1}".format(len(data), _RECORD_SIZE)
            )
        return cls(*_RECORD_STRUCT.unpack(data))


def _is_reserved_corrupted(block_type):
    return any(lo <= block_type <= hi for lo, hi in BLK_RESERVED_CORRUPTED)


def build_index(stream):
    """
    Scan a seekable pcapng stream once and build a :class:`PcapngIndex`.

    Only packet block locations and the section/interface context needed
    to resume parsing are recorded; packet payloads are not stored.

    :param stream: a seekable binary file-like object positioned anywhere
        (its position is restored after scanning).
    """
    original_position = stream.tell()
    try:
        stream.seek(0, io.SEEK_END)
        size = stream.tell()
        stream.seek(0)

        sections = []
        records = []
        packet_ordinal = 0

        section = None
        endianness = None
        section_id = -1

        while True:
            offset = stream.tell()
            type_raw = stream.read(4)
            if len(type_raw) == 0:
                break
            if len(type_raw) < 4:
                raise TruncatedFile(
                    "truncated block type at offset {0}".format(offset)
                )

            # The section header magic is byte-order symmetric, so it can
            # be detected before we know the section endianness. Every
            # other block type is encoded in the section's own byte order.
            raw_type_native = struct.unpack(">I", type_raw)[0]

            if raw_type_native == BLK_SECTION_HEADER:
                endianness, envelope = _read_shb_envelope(stream, offset)
                section_id += 1
                section = blocks.SectionHeader(
                    raw=_payload_after_shb(envelope), endianness=endianness
                )
                sections.append(
                    {
                        "offset": offset,
                        "length": len(envelope),
                        "endianness": endianness,
                        "shb_digest": _digest(envelope).hex(),
                        "interfaces": [],
                    }
                )
                continue

            if section is None:
                raise CorruptedFile(
                    "file not starting with a proper section header "
                    "(got block 0x{0:08X} at offset {1})".format(
                        raw_type_native, offset
                    )
                )

            block_type = struct.unpack(endianness + "I", type_raw)[0]
            member_type, block_length, envelope = _read_member_envelope(
                stream, offset, endianness
            )
            if member_type != block_type:
                raise CorruptedFile(
                    "block type decoded with wrong endianness at offset "
                    "{0}".format(offset)
                )

            if member_type == BLK_RESERVED or _is_reserved_corrupted(member_type):
                raise CorruptedFile(
                    "reserved/corrupted block type 0x{0:08X} at offset "
                    "{1}".format(member_type, offset)
                )

            if member_type == BLK_INTERFACE:
                idb = section.new_member(
                    blocks.InterfaceDescription,
                    raw=_member_payload(envelope),
                )
                sections[-1]["interfaces"].append(
                    {
                        "offset": offset,
                        "length": block_length,
                        "interface_id": idb.interface_id,
                        "digest": _digest(envelope).hex(),
                    }
                )
                continue

            if member_type in PACKET_BLOCK_TYPES:
                records.append(
                    PacketRecord(
                        ordinal=packet_ordinal,
                        offset=offset,
                        length=block_length,
                        section_id=section_id,
                        interface_id=_interface_id_of(
                            member_type, envelope, endianness
                        ),
                        block_type=member_type,
                        digest=_digest(envelope),
                    )
                )
                packet_ordinal += 1
                continue

            # Any other known block (NRB, ISB, ...) or unknown block
            # carries no packets and needs no index entry. The scanner
            # would likewise accept it as an UnknownBlock when its type
            # is not recognized.

        windows, fingerprint = compute_fingerprint(
            stream, size, [entry["offset"] for entry in sections]
        )

        return PcapngIndex(
            size=size,
            fingerprint=fingerprint.hex(),
            windows=windows,
            sections=sections,
            records=records,
        )
    finally:
        stream.seek(original_position)

def build_index_file(path, index_path=None):
    """
    Build an index for the pcapng file at ``path`` and write the sidecar
    index.  Returns the index path (defaults to ``path + INDEX_SUFFIX``).
    """
    with open(path, "rb") as stream:
        index = build_index(stream)
    if index_path is None:
        index_path = path + INDEX_SUFFIX
    with open(index_path, "wb") as out:
        index.save(out)
    return index_path


class PcapngIndex(object):
    """
    In-memory representation of a pcapng sidecar index.

    Use :func:`build_index` / :func:`build_index_file` to create one and
    :meth:`save` / :meth:`load` to persist it.
    """

    __slots__ = ["size", "fingerprint", "windows", "sections", "records"]

    def __init__(self, size, fingerprint, windows, sections, records):
        self.size = size
        self.fingerprint = fingerprint
        self.windows = [tuple(window) for window in windows]
        self.sections = sections
        self.records = list(records)
        self._validate_records()

    def _validate_records(self):
        for expected, record in enumerate(self.records):
            if record.ordinal != expected:
                raise InvalidIndexError(
                    "packet ordinal gap: record {0} claims ordinal {1}".format(
                        expected, record.ordinal
                    )
                )

    @property
    def packet_count(self):
        return len(self.records)

    @property
    def section_offsets(self):
        return [section["offset"] for section in self.sections]

    def current_fingerprint(self, stream):
        windows, digest = compute_fingerprint(
            stream, self.size, self.section_offsets
        )
        if windows != self.windows:
            # Windows are deterministic given size + section offsets; a
            # mismatch means the index was produced by incompatible code.
            raise InvalidIndexError("index fingerprint windows do not match index")
        return digest

    def validate(self, stream):
        """
        Check that ``stream`` is still exactly the file this index was
        built for.  Raises :class:`StaleIndexError` if the file was
        replaced or rewritten (including a same-length rewrite).
        """
        stream.seek(0, io.SEEK_END)
        current_size = stream.tell()
        if current_size != self.size:
            raise StaleIndexError(
                "pcapng file size changed ({0} -> {1}); index is stale".format(
                    self.size, current_size
                )
            )
        current = self.current_fingerprint(stream)
        if current != bytes.fromhex(self.fingerprint):
            raise StaleIndexError(
                "pcapng content fingerprint mismatch; file was replaced or "
                "rewritten since the index was built"
            )

    def save(self, stream):
        """Serialize the index to a binary stream."""
        header = {
            "version": 1,
            "size": self.size,
            "fingerprint": self.fingerprint,
            "windows": [[start, end] for start, end in self.windows],
            "sections": self.sections,
        }
        stream.write(INDEX_MAGIC)
        stream.write(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        stream.write(b"\n")
        for record in self.records:
            stream.write(record.to_bytes())

    def save_path(self, path):
        with open(path, "wb") as stream:
            self.save(stream)

    @classmethod
    def load(cls, stream):
        """Load an index previously written with :meth:`save`."""
        magic = stream.read(len(INDEX_MAGIC))
        if magic != INDEX_MAGIC:
            raise InvalidIndexError("not a pcapng sidecar index (bad magic)")
        header_line = stream.readline()
        if not header_line.endswith(b"\n"):
            raise InvalidIndexError("truncated index header")
        try:
            header = json.loads(header_line[:-1].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise InvalidIndexError("malformed index header: {0}".format(exc))
        if header.get("version") != 1:
            raise InvalidIndexError(
                "unsupported index version: {0!r}".format(header.get("version"))
            )
        try:
            size = int(header["size"])
            fingerprint = str(header["fingerprint"])
            windows = [(int(start), int(end)) for start, end in header["windows"]]
            sections = header["sections"]
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidIndexError("malformed index header: {0}".format(exc))
        for section in sections:
            for key in ("offset", "length", "endianness", "shb_digest", "interfaces"):
                if key not in section:
                    raise InvalidIndexError("section entry missing {0!r}".format(key))
        try:
            bytes.fromhex(fingerprint)
        except ValueError as exc:
            raise InvalidIndexError("malformed fingerprint: {0}".format(exc))

        records = []
        while True:
            data = stream.read(_RECORD_SIZE)
            if not data:
                break
            records.append(PacketRecord.from_bytes(data))
        index = cls(
            size=size,
            fingerprint=fingerprint,
            windows=windows,
            sections=sections,
            records=records,
        )
        return index

    @classmethod
    def load_path(cls, path):
        with open(path, "rb") as stream:
            return cls.load(stream)


def load_index_file(path):
    """Convenience wrapper around :meth:`PcapngIndex.load_path`."""
    return PcapngIndex.load_path(path)


class _SectionContext(object):
    """
    Lazily reconstructed section: the parsed :class:`SectionHeader`
    together with every interface description block registered before a
    given packet offset.

    All reconstruction goes through the same code path the sequential
    scanner uses (``SectionHeader`` / ``new_member``), so packet blocks
    parsed from an indexed offset resolve timestamps, snap lengths and
    interfaces exactly as in a full scan.
    """

    __slots__ = ["section", "end_index", "interfaces_loaded"]

    def __init__(self, section, end_index):
        self.section = section
        self.end_index = end_index
        self.interfaces_loaded = 0

    def ensure_interfaces(self, reader, before_offset):
        interfaces = reader.index.sections[self.end_index]["interfaces"]
        while (
            self.interfaces_loaded < len(interfaces)
            and interfaces[self.interfaces_loaded]["offset"] < before_offset
        ):
            info = interfaces[self.interfaces_loaded]
            block_type, _block_length, envelope = _read_member_envelope(
                reader.stream, info["offset"], self.section.endianness
            )
            if block_type != BLK_INTERFACE:
                raise InvalidIndexError(
                    "indexed interface location is not an IDB at offset {0}".format(
                        info["offset"]
                    )
                )
            if _digest(envelope).hex() != info["digest"]:
                raise StaleIndexError(
                    "interface description block at offset {0} changed; "
                    "index is stale".format(info["offset"])
                )
            idb = self.section.new_member(
                blocks.InterfaceDescription,
                raw=_member_payload(envelope),
            )
            if idb.interface_id != info["interface_id"]:
                raise InvalidIndexError(
                    "interface id mismatch at offset {0}".format(info["offset"])
                )
            self.interfaces_loaded += 1


class CountingReader(object):
    """
    Wrapper around a seekable binary stream counting the number of bytes
    read through it (``seek()`` does not read).  Useful to prove a random
    access does not rescan the whole file.
    """

    __slots__ = ["stream", "bytes_read", "read_count"]

    def __init__(self, stream):
        self.stream = stream
        self.bytes_read = 0
        self.read_count = 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.bytes_read += len(data)
        self.read_count += 1
        return data

    def seek(self, offset, whence=io.SEEK_SET):
        return self.stream.seek(offset, whence)

    def tell(self):
        return self.stream.tell()

    @property
    def name(self):
        return getattr(self.stream, "name", None)

    def reset_counters(self):
        self.bytes_read = 0
        self.read_count = 0


class IndexedReader(object):
    """
    Random access reader for packets of an indexed pcapng file.

    Packets are numbered globally, starting at zero, across all sections.
    Reading a packet seeks directly to its recorded offset; the only
    additional reads are the (small, bounded) section/interface context
    blocks required to parse it, each verified by digest.

    :param index: a :class:`PcapngIndex` matching ``stream``
    :param stream: a seekable binary stream for the pcapng file
    :param validate: if true (default), immediately verify that the stream
        still matches the index fingerprint.
    """

    __slots__ = ["index", "stream", "_contexts", "_closed"]

    def __init__(self, index, stream, validate=True):
        self.index = index
        self.stream = stream
        self._contexts = {}
        self._closed = False
        if validate:
            self.index.validate(stream)

    @classmethod
    def open_path(cls, path, index_path=None, validate=True):
        stream = open(path, "rb")
        try:
            if index_path is None:
                index_path = path + INDEX_SUFFIX
            index = PcapngIndex.load_path(index_path)
            return cls(index, stream, validate=validate)
        except Exception:
            stream.close()
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __len__(self):
        return self.index.packet_count

    def _record_for(self, index):
        return self.index.records[index]

    def _load_context(self, record):
        section_id = record.section_id
        context = self._contexts.get(section_id)
        if context is None:
            info = self.index.sections[section_id]
            endianness, envelope = _read_shb_envelope(
                self.stream, info["offset"]
            )
            if _digest(envelope).hex() != info["shb_digest"]:
                raise StaleIndexError(
                    "section header at offset {0} changed; index is stale".format(
                        info["offset"]
                    )
                )
            section = blocks.SectionHeader(
                raw=_payload_after_shb(envelope), endianness=endianness
            )
            context = _SectionContext(section=section, end_index=section_id)
            self._contexts[section_id] = context
        context.ensure_interfaces(self, before_offset=record.offset)
        return context

    def read_packet(self, packet_index):
        """
        Read and parse a single packet block by its global ordinal.

        The on-disk block bytes are verified against the digest stored in
        the index before parsing, so a tampered/rewritten file causes
        :class:`StaleIndexError` instead of returning the wrong packet.
        """
        if self._closed:
            raise ValueError("I/O operation on a closed IndexedReader")
        record = self._record_for(packet_index)
        context = self._load_context(record)

        block_type, block_length, envelope = _read_member_envelope(
            self.stream, record.offset, context.section.endianness
        )
        if block_type != record.block_type:
            raise CorruptedFile(
                "block type at offset {0} does not match index "
                "(0x{1:08X} != 0x{2:08X})".format(
                    record.offset, block_type, record.block_type
                )
            )
        if block_length != record.length:
            raise StaleIndexError(
                "block length at offset {0} changed; index is stale".format(
                    record.offset
                )
            )
        if _digest(envelope) != record.digest:
            raise StaleIndexError(
                "packet block at offset {0} changed; index is stale".format(
                    record.offset
                )
            )

        payload = _member_payload(envelope)
        block_cls = blocks.KNOWN_BLOCKS.get(block_type)
        if block_cls is None:  # pragma: no cover - only packet types indexed
            raise CorruptedFile(
                "indexed block type 0x{0:08X} is not a known packet block".format(
                    block_type
                )
            )
        return context.section.new_member(
            block_cls, raw=payload
        )

    def read_range(self, start=None, stop=None, step=1):
        """
        Read a contiguous range of packets ``[start, stop)``.

        ``start``/``stop`` support the usual Python slice semantics for
        negative values and ``None``.  Only the requested packet blocks
        and their section/interface context are read from the file.
        """
        count = self.index.packet_count
        if start is None:
            start = 0
        if stop is None:
            stop = count
        if step is None:
            step = 1
        if step != 1:
            raise ValueError("read_range only supports contiguous ranges (step=1)")
        if start < 0:
            start += count
        if stop < 0:
            stop += count
        start = max(0, min(start, count))
        stop = max(0, min(stop, count))
        for packet_index in range(start, stop):
            yield self.read_packet(packet_index)

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step is not None and key.step != 1:
                raise IndexError("only contiguous slices are supported")
            return list(self.read_range(key.start, key.stop))
        count = self.index.packet_count
        if key < 0:
            key += count
        if not 0 <= key < count:
            raise IndexError("packet index out of range: {0}".format(key))
        return self.read_packet(key)

    def __iter__(self):
        return self.read_range()
