"""
Merge timestamped blocks from multiple pcap-ng streams into one timeline.
"""

import heapq
from enum import Enum

from pcapng import blocks
from pcapng.exceptions import PcapngMergeError
from pcapng.scanner import FileScanner
from pcapng.writer import FileWriter


class SimplePacketAction(Enum):
    """Action to take when a Simple Packet Block is encountered."""

    REJECT = "reject"
    KEEP_SEPARATE = "keep-separate"


def _copy_options(source, target):
    for name, values in source.iter_all_items():
        target.options[name] = values


def _seekable(stream):
    return all(hasattr(stream, name) for name in ("read", "seek", "tell"))


class _TimelineCursor(object):
    __slots__ = ["scanner", "section_number"]

    def __init__(self, stream):
        self.scanner = iter(FileScanner(stream))
        self.section_number = 0


class PcapngMerger(object):
    """
    Merge multiple seekable pcap-ng streams into one timestamped timeline.

    Every source section gets an independent interface mapping. Timestamped
    blocks are compared with exact rational times, so timestamps using decimal
    and binary resolutions cannot be reordered by floating-point rounding.

    :param streams: seekable binary input streams, in tie-breaking order
    :param simple_packets: required choice for blocks without timestamps
    :param endianness: endianness used by the merged output section
    """

    __slots__ = [
        "streams",
        "simple_packets",
        "endianness",
        "interface_map",
        "keep_simple_sections",
        "merged_section",
        "has_timeline_content",
    ]

    def __init__(
        self,
        streams,
        simple_packets,
        endianness="<",
    ):
        self.streams = list(streams)
        if not self.streams:
            raise ValueError("at least one input stream is required")
        if not all(_seekable(stream) for stream in self.streams):
            raise TypeError("input streams must be seekable binary streams")
        if not isinstance(simple_packets, SimplePacketAction):
            raise TypeError("simple_packets must be a SimplePacketAction")
        if endianness not in ("<", ">"):
            raise ValueError("endianness must be '<' or '>'")

        self.simple_packets = simple_packets
        self.endianness = endianness
        self.interface_map = {}
        self.keep_simple_sections = set()
        self.merged_section = None
        self.has_timeline_content = False

    def write(self, output):
        """Write merged pcap-ng data to ``output`` and return it."""
        positions = []
        try:
            for stream in self.streams:
                positions.append(stream.tell())

            self.merged_section = blocks.SectionHeader(endianness=self.endianness)
            self._scan_sources(self.merged_section)
            self._restore_positions(positions)

            writer = None
            if (
                self.has_timeline_content
                or self.simple_packets is SimplePacketAction.REJECT
            ):
                writer = FileWriter(output, self.merged_section)
                self._merge_timeline(writer)
            if self.simple_packets is SimplePacketAction.KEEP_SEPARATE:
                self._restore_positions(positions)
                self._write_simple_packet_sections(output)
        finally:
            for stream, position in zip(self.streams, positions):
                stream.seek(position)

        return output

    def _restore_positions(self, positions):
        for stream, position in zip(self.streams, positions):
            stream.seek(position)

    def _scan_sources(self, merged_section):
        for input_index, stream in enumerate(self.streams):
            section_number = 0
            last_timestamp = None

            for block in FileScanner(stream):
                if type(block) is blocks.SectionHeader:
                    section_number += 1
                    last_timestamp = None
                    continue

                source_key = (input_index, section_number)

                if type(block) is blocks.InterfaceDescription:
                    self._clone_interface(
                        merged_section,
                        source_key,
                        block,
                    )
                elif type(block) is blocks.SimplePacket:
                    self._handle_simple_packet(source_key, block)
                elif isinstance(block, blocks.BlockWithTimestampMixin):
                    self._validate_timestamped(source_key, block, last_timestamp)
                    last_timestamp = block.timestamp_exact
                    self.has_timeline_content = True
                elif type(block) is not blocks.NameResolution:
                    block_type = getattr(block, "magic_number", block.block_type)
                    raise PcapngMergeError(
                        "cannot merge block type 0x{0:08X}".format(
                            block_type
                        )
                    )
                else:
                    self.has_timeline_content = True

    def _clone_interface(self, merged_section, source_key, source_interface):
        interface_id = source_interface.interface_id
        map_key = (source_key, interface_id)
        if map_key in self.interface_map:
            raise PcapngMergeError("duplicate interface id in source section")

        target_interface = merged_section.new_member(
            blocks.InterfaceDescription,
            link_type=source_interface.link_type,
            snaplen=source_interface.snaplen,
        )
        _copy_options(source_interface.options, target_interface)
        self.interface_map[map_key] = target_interface.interface_id

    def _handle_simple_packet(self, source_key, block):
        if 0 not in block.section.interfaces:
            raise PcapngMergeError(
                "Simple Packet Block without an interface description"
            )
        if self.simple_packets is SimplePacketAction.REJECT:
            raise PcapngMergeError(
                "Simple Packet Block has no timestamp and cannot be placed "
                "in the merged timeline"
            )
        self.keep_simple_sections.add(source_key)

    def _validate_timestamped(self, source_key, block, last_timestamp):
        map_key = (source_key, block.interface_id)
        if map_key not in self.interface_map:
            raise PcapngMergeError(
                "block references unknown interface {0}".format(block.interface_id)
            )
        timestamp = block.timestamp_exact
        if last_timestamp is not None and timestamp < last_timestamp:
            raise PcapngMergeError("input timestamps must be non-decreasing")

    def _merge_timeline(self, writer):
        heads = []
        pending_metadata = [[] for _ in self.streams]
        trailing_metadata = [[] for _ in self.streams]
        sequences = [0 for _ in self.streams]
        cursors = [_TimelineCursor(stream) for stream in self.streams]

        for input_index in range(len(self.streams)):
            self._advance_head(
                input_index,
                heads,
                pending_metadata,
                trailing_metadata,
                sequences,
                cursors,
            )

        heapq.heapify(heads)

        while heads:
            timestamp, input_index, sequence, block = heapq.heappop(heads)
            for metadata in pending_metadata[input_index]:
                writer.write_block(metadata)
            pending_metadata[input_index] = []
            writer.write_block(block)

            self._advance_head(
                input_index,
                heads,
                pending_metadata,
                trailing_metadata,
                sequences,
                cursors,
            )

        for metadata_list in trailing_metadata:
            for metadata in metadata_list:
                writer.write_block(metadata)

    def _advance_head(
        self,
        input_index,
        heads,
        pending_metadata,
        trailing_metadata,
        sequences,
        cursors,
    ):
        cursor = cursors[input_index]
        for block in cursor.scanner:
            if type(block) is blocks.SectionHeader:
                cursor.section_number += 1
            elif type(block) is blocks.InterfaceDescription:
                continue
            elif type(block) is blocks.SimplePacket:
                continue
            elif type(block) is blocks.NameResolution:
                metadata = self._clone_name_resolution(block)
                pending_metadata[input_index].append(metadata)
                trailing_metadata[input_index].append(metadata)
            else:
                source_key = (input_index, cursor.section_number)
                converted = self._convert_timestamped(source_key, block)
                sequence = sequences[input_index]
                sequences[input_index] += 1
                while pending_metadata[input_index]:
                    trailing_metadata[input_index].remove(
                        pending_metadata[input_index].pop(0)
                    )
                heads.append(
                    (block.timestamp_exact, input_index, sequence, converted)
                )
                return

    def _convert_timestamped(self, source_key, block):
        target_interface_id = self.interface_map[
            (source_key, block.interface_id)
        ]

        if type(block) is blocks.InterfaceStatistics:
            return self.merged_section.new_member(
                blocks.InterfaceStatistics,
                interface_id=target_interface_id,
                timestamp_high=block.timestamp_high,
                timestamp_low=block.timestamp_low,
                options=self._option_items(block),
            )

        option_items = self._option_items(block)
        if type(block) is blocks.ObsoletePacket:
            if "pack_flags" in option_items:
                option_items["epb_flags"] = option_items.pop("pack_flags")
            if "pack_hash" in option_items:
                option_items["epb_hash"] = option_items.pop("pack_hash")
            option_items["epb_dropcount"] = block.drops_count

        return self.merged_section.new_member(
            blocks.EnhancedPacket,
            interface_id=target_interface_id,
            timestamp_high=block.timestamp_high,
            timestamp_low=block.timestamp_low,
            packet_len=block.packet_len,
            packet_data=block.packet_data,
            options=option_items,
        )

    def _clone_name_resolution(self, block):
        return self.merged_section.new_member(
            blocks.NameResolution,
            records=list(block.records),
            options=self._option_items(block),
        )

    @staticmethod
    def _option_items(block):
        return dict(block.options.iter_all_items())

    def _write_simple_packet_sections(self, output):
        for input_index, stream in enumerate(self.streams):
            section_number = 0
            section_writer = None
            first_interface = None
            side_section = None

            for block in FileScanner(stream):
                if type(block) is blocks.SectionHeader:
                    section_number += 1
                    side_section = blocks.SectionHeader(endianness=block.endianness)
                    _copy_options(block.options, side_section)
                    section_writer = None
                    first_interface = None
                elif (
                    type(block) is blocks.InterfaceDescription
                    and block.interface_id == 0
                    and (input_index, section_number) in self.keep_simple_sections
                ):
                    first_interface = side_section.new_member(
                        blocks.InterfaceDescription,
                        link_type=block.link_type,
                        snaplen=block.snaplen,
                    )
                    _copy_options(block.options, first_interface)
                    section_writer = FileWriter(output, side_section)
                elif (
                    type(block) is blocks.SimplePacket
                    and (input_index, section_number) in self.keep_simple_sections
                ):
                    simple = side_section.new_member(
                        blocks.SimplePacket,
                        packet_len=block.packet_len,
                        packet_data=block.packet_data,
                    )
                    section_writer.write_block(simple)


def merge_pcapng(
    output,
    streams,
    simple_packets,
    endianness="<",
):
    """Merge ``streams`` into ``output`` using :class:`PcapngMerger`."""
    return PcapngMerger(
        streams,
        simple_packets=simple_packets,
        endianness=endianness,
    ).write(output)
