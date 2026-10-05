"""
Tests for the pcapng metadata sanitizer
"""

import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import SanitizeConfigError
from pcapng.sanitizer import DROP, KEEP, REPLACE, SanitizeRules, Sanitizer
from pcapng.structs import write_bytes_padded, write_int

PACKET_BLOCKS = (blocks.EnhancedPacket, blocks.SimplePacket, blocks.ObsoletePacket)

UNKNOWN_BLOCK_TYPE = 0x00000BAD
UNKNOWN_OPTION_CODE = 999


def build_capture(endianness="<", unknown_option=False, unknown_block=False):
    """Build an in-memory capture rich in host-identifying metadata"""
    stream = io.BytesIO()

    shb = blocks.SectionHeader(
        endianness=endianness,
        options={
            "shb_hardware": "Dell Precision 5550",
            "shb_os": "Ubuntu 20.04.3 LTS",
            "shb_userappl": "dumpcap 3.4.0",
            "opt_comment": "captured on host WS-042",
        },
    )
    idb = shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={
            "if_name": "eth0",
            "if_description": "Corporate LAN adapter",
            "if_os": "Ubuntu 20.04",
            "if_hardware": "Intel I219-LM",
            "if_tsresol": b"\x06",
            "if_speed": 1000000000,
            "opt_comment": "interface comment",
        },
    )
    if unknown_option:
        idb.options.data[UNKNOWN_OPTION_CODE] = [b"\x01\x02\x03"]

    epb = shb.new_member(
        blocks.EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=123456,
        packet_data=b"\xde\xad\xbe\xef" * 4,
        options={"opt_comment": "packet comment"},
    )
    spb = shb.new_member(blocks.SimplePacket, packet_data=b"simple packet data")
    isb = shb.new_member(
        blocks.InterfaceStatistics,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=654321,
        options={"opt_comment": "stats comment", "isb_ifrecv": 42},
    )
    nrb = shb.new_member(
        blocks.NameResolution,
        records=[
            {"type": 1, "address": "192.168.1.1", "names": ["printer.corp.local"]},
        ],
        options={"ns_dnsname": "dns1.corp.local"},
    )

    writer = FileWriter(stream, shb)
    for blk in (epb, spb, isb, nrb):
        writer.write_block(blk)

    # A second section, to make sure multi-section files are handled
    shb2 = blocks.SectionHeader(
        endianness=endianness,
        options={"shb_os": "Windows 10", "opt_comment": "second section"},
    )
    shb2.new_member(
        blocks.InterfaceDescription,
        link_type=127,
        snaplen=262144,
        options={"if_name": "wlan0", "if_tsresol": b"\x09"},
    )
    epb2 = shb2.new_member(
        blocks.EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=1,
        packet_data=b"second section packet",
    )
    writer.write_block(shb2)
    writer.write_block(epb2)

    if unknown_block:
        payload = b"custom-metadata!"
        length = 12 + len(payload)
        length += (4 - length % 4) % 4
        write_int(UNKNOWN_BLOCK_TYPE, stream, 32, endianness=endianness)
        write_int(length, stream, 32, endianness=endianness)
        write_bytes_padded(stream, payload)
        write_int(length, stream, 32, endianness=endianness)

    stream.seek(0)
    return stream


def packet_payloads(stream):
    return [
        block.packet_data
        for block in FileScanner(stream)
        if isinstance(block, PACKET_BLOCKS)
    ]


def sanitize(capture, rules=None):
    out = io.BytesIO()
    report = Sanitizer(rules).sanitize_stream(capture, out)
    out.seek(0)
    return out, report


# --------------------------------------------------------------------
# Default behavior
# --------------------------------------------------------------------


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_default_rules_strip_host_metadata(endianness):
    out, report = sanitize(build_capture(endianness=endianness))
    scanned = list(FileScanner(out))

    shb = scanned[0]
    assert isinstance(shb, blocks.SectionHeader)
    assert "shb_hardware" not in shb.options
    assert "shb_os" not in shb.options
    assert "opt_comment" not in shb.options
    # Not host-identifying: kept by default
    assert shb.options["shb_userappl"] == "dumpcap 3.4.0"

    idb = shb.interfaces[0]
    assert "if_name" not in idb.options
    assert "if_description" not in idb.options
    assert "if_os" not in idb.options
    assert "if_hardware" not in idb.options
    assert "opt_comment" not in idb.options

    # Name resolution blocks are dropped entirely by default
    assert not any(isinstance(b, blocks.NameResolution) for b in scanned)
    assert report.dropped_blocks == {"NameResolution": 1}

    # Statistics blocks are kept, but their comments are stripped
    isb = [b for b in scanned if isinstance(b, blocks.InterfaceStatistics)]
    assert len(isb) == 1
    assert "opt_comment" not in isb[0].options
    assert isb[0].options["isb_ifrecv"] == 42

    # Packets are kept, but their comments are stripped
    epb = [b for b in scanned if isinstance(b, blocks.EnhancedPacket)]
    assert len(epb) == 2
    assert all("opt_comment" not in b.options for b in epb)

    # Everything dropped is accounted for in the report
    assert report.dropped_options[("SectionHeader", "shb_os")] == 2
    assert report.dropped_options[("SectionHeader", "opt_comment")] == 2
    assert report.dropped_options[("InterfaceDescription", "if_name")] == 2
    assert report.dropped_options[("EnhancedPacket", "opt_comment")] == 1
    assert report.dropped_options[("InterfaceStatistics", "opt_comment")] == 1
    assert report.blocks_read == report.blocks_written + 1  # only the NRB


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_default_rules_preserve_structure_and_payloads(endianness):
    capture = build_capture(endianness=endianness)
    expected_payloads = packet_payloads(io.BytesIO(capture.getvalue()))

    out, _ = sanitize(capture)
    scanned = list(FileScanner(out))

    # Packet payloads are identical, packet by packet
    assert packet_payloads(io.BytesIO(out.getvalue())) == expected_payloads

    # Structural information required to parse packets is preserved
    shb = scanned[0]
    idb = shb.interfaces[0]
    assert idb.link_type == 1
    assert idb.snaplen == 65535
    assert idb.options["if_tsresol"] == b"\x06"
    assert idb.timestamp_resolution == 1e-6
    assert idb.options["if_speed"] == 1000000000

    # Second section survived, with its own interface and resolution
    shb2 = [b for b in scanned if isinstance(b, blocks.SectionHeader)][1]
    idb2 = shb2.interfaces[0]
    assert idb2.link_type == 127
    assert idb2.snaplen == 262144
    assert idb2.options["if_tsresol"] == b"\x09"

    # Interface references are still valid
    isb = [b for b in scanned if isinstance(b, blocks.InterfaceStatistics)][0]
    assert isb.interface is idb
    epb = [b for b in scanned if isinstance(b, blocks.EnhancedPacket)]
    assert epb[0].interface is idb
    assert epb[1].interface is idb2


def test_empty_rules_keep_everything():
    capture = build_capture()
    original = list(FileScanner(io.BytesIO(capture.getvalue())))
    out, report = sanitize(capture, SanitizeRules(use_defaults=False))
    sanitized = list(FileScanner(out))

    assert len(original) == len(sanitized)
    for before, after in zip(original, sanitized):
        assert before == after
    assert report.dropped_blocks == {}
    assert report.dropped_options == {}
    assert report.blocks_read == report.blocks_written


# --------------------------------------------------------------------
# Configurable rules
# --------------------------------------------------------------------


def test_replace_option_with_constant():
    rules = SanitizeRules()
    rules.set_option_rule("section_header", "shb_userappl", (REPLACE, "sanitized"))
    out, report = sanitize(build_capture(), rules)

    shb = list(FileScanner(out))[0]
    assert shb.options["shb_userappl"] == "sanitized"
    # Only the first section header has a shb_userappl option
    assert report.replaced_options[("SectionHeader", "shb_userappl")] == 1


def test_replace_option_with_callable():
    rules = SanitizeRules()
    rules.set_option_rule(
        "interface_description", "if_name", lambda old: "iface-{0}".format(len(old))
    )
    out, report = sanitize(build_capture(), rules)

    scanned = list(FileScanner(out))
    names = [
        b.interfaces[0].options["if_name"]
        for b in scanned
        if isinstance(b, blocks.SectionHeader)
    ]
    assert names == ["iface-4", "iface-5"]
    assert report.replaced_options[("InterfaceDescription", "if_name")] == 2


def test_keep_rule_overrides_defaults():
    rules = SanitizeRules()
    rules.set_option_rule("section_header", "shb_os", KEEP)
    rules.drop_block("name_resolution", drop=False)
    out, _ = sanitize(build_capture(), rules)

    scanned = list(FileScanner(out))
    shb = scanned[0]
    assert shb.options["shb_os"] == "Ubuntu 20.04.3 LTS"
    nrb = [b for b in scanned if isinstance(b, blocks.NameResolution)]
    assert len(nrb) == 1
    assert nrb[0].records[0]["names"] == ["printer.corp.local"]


def test_drop_block_rule():
    rules = SanitizeRules()
    rules.drop_block("interface_statistics")
    out, report = sanitize(build_capture(), rules)

    scanned = list(FileScanner(out))
    assert not any(isinstance(b, blocks.InterfaceStatistics) for b in scanned)
    assert report.dropped_blocks["InterfaceStatistics"] == 1


# --------------------------------------------------------------------
# Unknown options / blocks
# --------------------------------------------------------------------


def test_unknown_option_kept_by_default_and_reported():
    out, report = sanitize(build_capture(unknown_option=True))

    scanned = list(FileScanner(out))
    idb = scanned[0].interfaces[0]
    assert idb.options.data[UNKNOWN_OPTION_CODE] == [b"\x01\x02\x03"]
    key = ("InterfaceDescription", UNKNOWN_OPTION_CODE, KEEP)
    assert report.unknown_options[key] == 1


def test_unknown_option_dropped_on_request():
    rules = SanitizeRules()
    rules.unknown_option_policy = DROP
    out, report = sanitize(build_capture(unknown_option=True), rules)

    scanned = list(FileScanner(out))
    idb = scanned[0].interfaces[0]
    assert UNKNOWN_OPTION_CODE not in idb.options.data
    key = ("InterfaceDescription", UNKNOWN_OPTION_CODE, DROP)
    assert report.unknown_options[key] == 1


def test_explicit_rule_for_unknown_option_code():
    rules = SanitizeRules()
    rules.set_option_rule("interface_description", UNKNOWN_OPTION_CODE, DROP)
    out, report = sanitize(build_capture(unknown_option=True), rules)

    scanned = list(FileScanner(out))
    idb = scanned[0].interfaces[0]
    assert UNKNOWN_OPTION_CODE not in idb.options.data
    # Explicitly ruled: not reported as unknown
    assert report.unknown_options == {}
    assert report.dropped_options[("InterfaceDescription", UNKNOWN_OPTION_CODE)] == 1


def test_unknown_block_kept_by_default_and_reported():
    out, report = sanitize(build_capture(unknown_block=True))

    unknown = [b for b in FileScanner(out) if isinstance(b, blocks.UnknownBlock)]
    assert len(unknown) == 1
    assert unknown[0].block_type == UNKNOWN_BLOCK_TYPE
    assert unknown[0].data.startswith(b"custom-metadata!")
    assert report.unknown_blocks == {(UNKNOWN_BLOCK_TYPE, KEEP): 1}


def test_unknown_block_dropped_on_request():
    rules = SanitizeRules()
    rules.unknown_block_policy = DROP
    out, report = sanitize(build_capture(unknown_block=True), rules)

    scanned = list(FileScanner(out))
    assert not any(isinstance(b, blocks.UnknownBlock) for b in scanned)
    assert report.unknown_blocks == {(UNKNOWN_BLOCK_TYPE, DROP): 1}
    # Packets still intact after dropping the unknown block
    assert len(packet_payloads(io.BytesIO(out.getvalue()))) == 3


# --------------------------------------------------------------------
# Invalid configurations
# --------------------------------------------------------------------


def test_rules_cannot_modify_protected_options():
    for option in ("if_tsresol", "if_fcslen"):
        rules = SanitizeRules()
        rules.set_option_rule("interface_description", option, DROP)
        with pytest.raises(SanitizeConfigError, match="required to parse"):
            Sanitizer(rules)


def test_rules_cannot_drop_protected_blocks():
    for block in (
        "section_header",
        "interface_description",
        "enhanced_packet",
        "simple_packet",
        "obsolete_packet",
    ):
        rules = SanitizeRules()
        rules.drop_block(block)
        with pytest.raises(SanitizeConfigError, match="required to parse"):
            Sanitizer(rules)


def test_rules_cannot_touch_endofopt():
    rules = SanitizeRules()
    rules.set_option_rule("section_header", 0, DROP)
    with pytest.raises(SanitizeConfigError, match="structural marker"):
        Sanitizer(rules)


def test_rules_reject_unknown_option_names():
    rules = SanitizeRules()
    rules.set_option_rule("section_header", "shb_hostname", DROP)
    with pytest.raises(SanitizeConfigError, match="Unknown option"):
        Sanitizer(rules)


def test_rules_reject_options_on_optionless_blocks():
    rules = SanitizeRules()
    rules.set_option_rule("simple_packet", "opt_comment", DROP)
    with pytest.raises(SanitizeConfigError, match="has no options"):
        Sanitizer(rules)


def test_rules_reject_invalid_actions_and_policies():
    with pytest.raises(SanitizeConfigError, match="Invalid rule"):
        SanitizeRules().set_option_rule("section_header", "shb_os", "shred")

    rules = SanitizeRules()
    rules.unknown_option_policy = "shred"
    with pytest.raises(SanitizeConfigError, match="unknown_option_policy"):
        Sanitizer(rules)

    rules = SanitizeRules()
    rules.unknown_block_policy = "shred"
    with pytest.raises(SanitizeConfigError, match="unknown_block_policy"):
        Sanitizer(rules)


def test_rejected_rules_leave_output_untouched():
    # When the rules are rejected, not a single byte may have been
    # written to the target stream.
    capture = build_capture()
    rules = SanitizeRules()
    rules.set_option_rule("interface_description", "if_tsresol", DROP)

    out = io.BytesIO()
    with pytest.raises(SanitizeConfigError):
        Sanitizer(rules).sanitize_stream(capture, out)
    assert out.getvalue() == b""


def test_failed_sanitization_leaves_no_partial_file():
    # A corrupt input must not leave a half-written output behind
    capture = build_capture()
    truncated = io.BytesIO(capture.getvalue()[:-10])

    out = io.BytesIO()
    with pytest.raises(Exception):
        Sanitizer().sanitize_stream(truncated, out)
    assert out.getvalue() == b""


# --------------------------------------------------------------------
# File-level API
# --------------------------------------------------------------------


def test_sanitize_file(tmp_path):
    capture = build_capture()
    inpath = str(tmp_path / "in.pcapng")
    outpath = str(tmp_path / "out.pcapng")
    with open(inpath, "wb") as fp:
        fp.write(capture.getvalue())

    report = Sanitizer().sanitize_file(inpath, outpath)
    assert report.blocks_written > 0

    with open(outpath, "rb") as fp:
        scanned = list(FileScanner(fp))
    assert not any(isinstance(b, blocks.NameResolution) for b in scanned)
    assert packet_payloads(io.BytesIO(capture.getvalue())) == [
        b.packet_data for b in scanned if isinstance(b, PACKET_BLOCKS)
    ]
