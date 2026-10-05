"""
Tools for merging several pcap-ng streams into a single timeline.

Each input stream is only required to be internally ordered by
non-decreasing packet time.  Packets are compared across inputs using
exact rational arithmetic (:py:class:`fractions.Fraction`), so packets
whose timestamps are distinct but collapse to the same floating point
value (eg. when mixing decimal and binary timestamp resolutions) are
still ordered correctly.

All timestamped packets are merged into a single output section: every
(source section, source interface) pair is mapped to an independent
output interface, preserving link type, snaplen, timestamp resolution
and packet length information.  Packets with identical timestamps are
ordered stably: first by input order, then by their original order
within that input.

:py:class:`~pcapng.blocks.SimplePacket` blocks carry no timestamp, so
they cannot be placed on the merged timeline without inventing a time
for them.  The caller must explicitly choose a policy: reject them, or
keep them in dedicated output sections (one per input section, each
holding a single interface), appended after the merged section.
"""

import heapq
from fractions import Fraction

import pcapng.blocks as blocks
from pcapng.exceptions import PcapngException
from pcapng.scanner import FileScanner

#: Reject SimplePacket blocks (they carry no timestamp)
SP_REJECT = "reject"

#: Keep SimplePacket blocks in dedicated output sections
SP_SEPARATE_SECTION = "section"

_SIMPLE_PACKET_POLICIES = (SP_REJECT, SP_SEPARATE_SECTION)


class MergeError(PcapngException):
    """Indicate a problem while merging pcap-ng streams"""

    pass


def timestamp_resolution_fraction(interface):
    """
    Return the exact timestamp resolution of an interface, as a
    :py:class:`fractions.Fraction` of a second.
    """
    if "if_tsresol" in interface.options:
        raw = interface.options["if_tsresol"]
        if len(raw) != 1:
            raise MergeError("if_tsresol option must be exactly one byte")
        byte = raw[0]
        base = 2 if byte & 0b10000000 else 10
        exponent = byte & 0b01111111
    else:
        # Default resolution is 10^-6, as with classic pcap
        base, exponent = 10, 6
    return Fraction(1, base ** exponent)


def packet_timestamp(packet, interface):
    """
    Return the exact timestamp of a packet block, as a
    :py:class:`fractions.Fraction` of a second since the epoch.
    """
    raw = (packet.timestamp_high << 32) | packet.timestamp_low
    return raw * timestamp_resolution_fraction(interface)


class _SectionMapping(object):
    """Mapping between one input section and the output section"""

    __slots__ = ["source", "interfaces", "spb_packets"]

    def __init__(self, source):
        self.source = source
        # source interface_id -> output InterfaceDescription
        self.interfaces = {}
        # buffered SimplePacket blocks: (packet_len, packet_data)
        self.spb_packets = []


class _InputState(object):
    """Iteration state for one input stream"""

    __slots__ = [
        "stream",
        "index",
        "iterator",
        "sections",
        "current_section",
        "last_timestamp",
        "packet_sequence",
        "pending",
        "pending_timestamp",
    ]

    def __init__(self, stream, index):
        if not stream.seekable():
            raise MergeError("input streams must be seekable")
        self.stream = stream
        self.index = index
        self.iterator = iter(FileScanner(stream))
        self.sections = []
        self.current_section = None
        self.last_timestamp = None
        self.packet_sequence = 0
        self.pending = None
        self.pending_timestamp = None


class Merger(object):
    """
    Merge several pcap-ng streams into a single output stream.

    :param output:
        a file-like object to which the merged data is written.

    :param simple_packet_policy:
        how to handle :py:class:`~pcapng.blocks.SimplePacket` blocks,
        which carry no timestamp.  Must be explicitly set to either
        ``SP_REJECT`` (raise :py:class:`MergeError` if one is found) or
        ``SP_SEPARATE_SECTION`` (keep them in dedicated output sections,
        one per input section, each holding a single interface).  There
        is no default, since placing them on the merged timeline would
        require fabricating a timestamp.
    """

    def __init__(self, output, simple_packet_policy):
        if simple_packet_policy not in _SIMPLE_PACKET_POLICIES:
            raise ValueError(
                "simple_packet_policy must be one of {0!r}".format(
                    _SIMPLE_PACKET_POLICIES
                )
            )
        self.output = output
        self.simple_packet_policy = simple_packet_policy
        self.out_shb = None

    def merge(self, inputs):
        """
        Merge the given input streams into the output stream.

        :param inputs:
            a sequence of seekable file-like objects, each containing a
            pcap-ng stream whose packets are internally ordered by
            non-decreasing timestamp.
        """
        states = [_InputState(stream, index) for index, stream in enumerate(inputs)]
        heap = []
        for state in states:
            self._advance(state)
            if state.pending is not None:
                self._push(heap, state)
        while heap:
            _, _, _, state = heapq.heappop(heap)
            packet, out_interface = state.pending
            self._write_packet(packet, out_interface)
            self._advance(state)
            if state.pending is not None:
                self._push(heap, state)
        for state in states:
            for mapping in state.sections:
                if mapping.spb_packets:
                    self._write_spb_section(mapping)

    @staticmethod
    def _push(heap, state):
        # The (timestamp, input index, sequence) key is unique: only one
        # pending packet per input may be in the heap at any time, so the
        # state object itself is never used for comparison.
        heapq.heappush(
            heap,
            (
                state.pending_timestamp,
                state.index,
                state.packet_sequence,
                state,
            ),
        )

    def _advance(self, state):
        """
        Read blocks from the input until the next timestamped packet is
        found, handling any other block as a side effect.
        """
        for block in state.iterator:
            if isinstance(block, blocks.SectionHeader):
                self._map_section(state, block)
            elif isinstance(block, blocks.InterfaceDescription):
                self._map_interface(state, block)
            elif isinstance(block, (blocks.EnhancedPacket, blocks.ObsoletePacket)):
                self._set_pending(state, block)
                return
            elif isinstance(block, blocks.SimplePacket):
                self._handle_simple_packet(state, block)
            elif isinstance(block, blocks.InterfaceStatistics):
                self._copy_interface_stats(state, block)
            elif isinstance(block, blocks.NameResolution):
                self._copy_name_resolution(state, block)
            # Anything else (eg. unknown blocks) cannot be safely
            # re-encoded and is dropped.
        state.pending = None
        state.pending_timestamp = None

    def _set_pending(self, state, packet):
        mapping = self._current_mapping(state, "packet")
        try:
            out_interface = mapping.interfaces[packet.interface_id]
        except KeyError:
            raise MergeError(
                "input {0}: packet references unknown interface {1}".format(
                    state.index, packet.interface_id
                )
            )
        timestamp = packet_timestamp(
            packet, packet.section.interfaces[packet.interface_id]
        )
        if state.last_timestamp is not None and timestamp < state.last_timestamp:
            raise MergeError(
                "input {0}: packets are not ordered by non-decreasing "
                "timestamp".format(state.index)
            )
        state.last_timestamp = timestamp
        state.packet_sequence += 1
        state.pending = (packet, out_interface)
        state.pending_timestamp = timestamp

    def _current_mapping(self, state, what):
        if state.current_section is None:
            raise MergeError(
                "input {0}: {1} found before any section header".format(
                    state.index, what
                )
            )
        return state.current_section

    def _map_section(self, state, shb):
        if self.out_shb is None:
            # All the timestamped blocks are merged into a single output
            # section, since a block always belongs to the most recent
            # section header and sections cannot be interleaved.
            self.out_shb = blocks.SectionHeader(
                endianness=shb.endianness,
                version_major=shb.version_major,
                version_minor=shb.version_minor,
                options=dict(shb.options),
            )
            self.out_shb._write(self.output)
        mapping = _SectionMapping(shb)
        state.sections.append(mapping)
        state.current_section = mapping

    def _map_interface(self, state, idb):
        mapping = self._current_mapping(state, "interface")
        out_idb = self._build_interface(idb)
        out_idb._write(self.output)
        mapping.interfaces[idb.interface_id] = out_idb

    def _build_interface(self, idb):
        return self.out_shb.new_member(
            blocks.InterfaceDescription,
            link_type=idb.link_type,
            reserved=idb.reserved,
            snaplen=idb.snaplen,
            options=dict(idb.options),
        )

    def _write_packet(self, packet, out_interface):
        if isinstance(packet, blocks.ObsoletePacket):
            # Upgrade obsolete packet blocks to enhanced ones
            options = dict(packet.options)
            options["epb_dropcount"] = packet.drops_count
            for name in ("flags", "hash"):
                try:
                    options["epb_" + name] = options.pop("pack_" + name)
                except KeyError:
                    pass
        else:
            options = dict(packet.options)
        out_packet = self.out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=out_interface.interface_id,
            timestamp_high=packet.timestamp_high,
            timestamp_low=packet.timestamp_low,
            packet_len=packet.packet_len,
            packet_data=packet.packet_data,
            options=options,
        )
        out_packet._write(self.output)

    def _handle_simple_packet(self, state, packet):
        if self.simple_packet_policy == SP_REJECT:
            raise MergeError(
                "input {0}: SimplePacket blocks carry no timestamp and "
                "cannot be merged (simple_packet_policy={1!r})".format(
                    state.index, self.simple_packet_policy
                )
            )
        mapping = self._current_mapping(state, "packet")
        # Buffer the block: its dedicated section can only be written
        # once the merged section is complete, as sections of the
        # output stream cannot be interleaved.
        mapping.spb_packets.append((packet.packet_len, packet.packet_data))

    def _write_spb_section(self, mapping):
        # SimplePacket blocks implicitly refer to the first interface of
        # their section, and cannot live in a multi-interface section:
        # give them a dedicated section holding a copy of that interface
        # (preserving link type, snaplen and timestamp resolution).
        src_shb = mapping.source
        out_shb = blocks.SectionHeader(
            endianness=src_shb.endianness,
            version_major=src_shb.version_major,
            version_minor=src_shb.version_minor,
            options=dict(src_shb.options),
        )
        out_shb._write(self.output)
        try:
            src_idb = src_shb.interfaces[0]
        except KeyError:
            raise MergeError("SimplePacket found in a section with no interfaces")
        out_idb = out_shb.new_member(
            blocks.InterfaceDescription,
            link_type=src_idb.link_type,
            reserved=src_idb.reserved,
            snaplen=src_idb.snaplen,
            options=dict(src_idb.options),
        )
        out_idb._write(self.output)
        for packet_len, packet_data in mapping.spb_packets:
            out_shb.new_member(
                blocks.SimplePacket,
                packet_len=packet_len,
                packet_data=packet_data,
            )._write(self.output)

    def _copy_interface_stats(self, state, isb):
        mapping = self._current_mapping(state, "statistics")
        try:
            out_idb = mapping.interfaces[isb.interface_id]
        except KeyError:
            raise MergeError(
                "input {0}: statistics reference unknown interface "
                "{1}".format(state.index, isb.interface_id)
            )
        self.out_shb.new_member(
            blocks.InterfaceStatistics,
            interface_id=out_idb.interface_id,
            timestamp_high=isb.timestamp_high,
            timestamp_low=isb.timestamp_low,
            options=dict(isb.options),
        )._write(self.output)

    def _copy_name_resolution(self, state, nrb):
        self._current_mapping(state, "name resolution")
        self.out_shb.new_member(
            blocks.NameResolution,
            records=list(nrb.records),
            options=dict(nrb.options),
        )._write(self.output)


def merge(inputs, output, simple_packet_policy):
    """
    Merge several pcap-ng streams into a single output stream.

    This is a convenience wrapper around :py:class:`Merger`; see its
    documentation for the parameters.
    """
    Merger(output, simple_packet_policy).merge(inputs)
