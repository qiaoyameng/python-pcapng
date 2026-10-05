"""
Configurable metadata sanitizer for pcap-ng capture files.

Capture files often leak information about the machine they were
recorded on, beyond the network payload itself: section comments,
interface names / descriptions, operating system strings and name
resolution records. This module provides a
:py:class:`Sanitizer` which rewrites a capture stream, removing or
replacing such metadata according to a configurable set of rules
(:py:class:`SanitizeRules`), while keeping the packet data and all
structural information required to parse it (link types, timestamp
resolutions, snap lengths, ...) intact.

Rules select, per block type and per option, whether the option is
kept, dropped or replaced. Unknown options and unknown blocks are
never silently guessed at: the caller chooses whether they are kept
as-is or dropped, and they are always listed in the returned
:py:class:`SanitizeReport`.

Example usage:

    .. code-block:: python

        from pcapng.sanitizer import Sanitizer, SanitizeRules

        rules = SanitizeRules()  # sensible defaults
        rules.unknown_option_policy = "drop"
        sanitizer = Sanitizer(rules)
        with open("in.pcapng", "rb") as fin, open("out.pcapng", "wb") as fout:
            report = sanitizer.sanitize_stream(fin, fout)
        print(report)

.. note::

    Packet data (``packet_data``) is never modified by the sanitizer.

.. note::

    Writing some legacy constructs (eg. obsolete Packet blocks) is
    forbidden by the library default strictness level. To sanitize
    captures containing them, relax it first with
    ``pcapng.strictness.set_strictness(Strictness.WARN)``. Either way,
    a failure never leaves a half-written output behind.
"""

import io

import pcapng.blocks as blocks
from pcapng.exceptions import SanitizeConfigError
from pcapng.scanner import FileScanner
from pcapng.structs import Options, write_bytes_padded, write_int

#: Rule action: remove the option from the block
DROP = "drop"

#: Rule action: keep the option as-is
KEEP = "keep"

#: Rule action: replace the option value with a new one
REPLACE = "replace"

_ACTIONS = (DROP, KEEP, REPLACE)

_POLICIES = (DROP, KEEP)

#: Registry of known block classes, addressable by name in rules
BLOCK_TYPES_BY_NAME = {
    "section_header": blocks.SectionHeader,
    "interface_description": blocks.InterfaceDescription,
    "enhanced_packet": blocks.EnhancedPacket,
    "simple_packet": blocks.SimplePacket,
    "obsolete_packet": blocks.ObsoletePacket,
    "name_resolution": blocks.NameResolution,
    "interface_statistics": blocks.InterfaceStatistics,
}

# Options that must never be removed or altered, because they are
# required to correctly interpret the packet data.
_PROTECTED_OPTIONS = {
    blocks.InterfaceDescription: frozenset(("if_tsresol", "if_fcslen")),
}

# Blocks that must never be dropped: they either carry the packet
# data itself, or information required to decode it.
_PROTECTED_BLOCKS = (
    blocks.SectionHeader,
    blocks.InterfaceDescription,
    blocks.EnhancedPacket,
    blocks.SimplePacket,
    blocks.ObsoletePacket,
)

#: Options dropped by the default rules, per block name
_DEFAULT_OPTION_DROPS = {
    "section_header": ("opt_comment", "shb_hardware", "shb_os"),
    "interface_description": (
        "opt_comment",
        "if_name",
        "if_description",
        "if_os",
        "if_hardware",
    ),
    "enhanced_packet": ("opt_comment",),
    "obsolete_packet": ("opt_comment",),
    "interface_statistics": ("opt_comment",),
}

#: Blocks dropped entirely by the default rules
_DEFAULT_DROPPED_BLOCKS = ("name_resolution",)


def _block_label(block_cls):
    return block_cls.__name__


def _normalize_block(block):
    """Resolve a block class, name or magic number to a block class"""
    if isinstance(block, type) and issubclass(block, blocks.Block):
        return block
    if isinstance(block, str):
        try:
            return BLOCK_TYPES_BY_NAME[block]
        except KeyError:
            raise SanitizeConfigError(
                "Unknown block type name: {0!r} (known: {1})".format(
                    block, ", ".join(sorted(BLOCK_TYPES_BY_NAME))
                )
            )
    if isinstance(block, int):
        for cls in BLOCK_TYPES_BY_NAME.values():
            if cls.magic_number == block:
                return cls
        raise SanitizeConfigError(
            "No known block type with magic number 0x{0:08X}".format(block)
        )
    raise SanitizeConfigError("Invalid block type specifier: {0!r}".format(block))


def _normalize_rule(rule):
    """Normalize a rule spec to an (action, value) tuple"""
    if rule in (DROP, KEEP):
        return (rule, None)
    if callable(rule):
        return (REPLACE, rule)
    if isinstance(rule, tuple) and len(rule) == 2 and rule[0] == REPLACE:
        return (REPLACE, rule[1])
    raise SanitizeConfigError(
        "Invalid rule {0!r}: expected '{1}', '{2}', "
        "('{3}', value) or a callable".format(rule, DROP, KEEP, REPLACE)
    )


def _options_schema_for(block_cls):
    """Return an Options instance describing the block's option schema"""
    for name, field, default in block_cls.schema:
        if name == "options":
            return Options(schema=field.options_schema, data={}, endianness="=")
    return None


class SanitizeRules(object):
    """
    Set of rules used by :py:class:`Sanitizer` to decide how each
    block and option of a capture file is to be treated.

    :param use_defaults:
        If ``True`` (default), start from the default rule set, which
        drops host-identifying metadata: section comments, hardware
        and OS descriptions, interface names / descriptions, all
        ``opt_comment`` options and the whole name resolution block.
        If ``False``, start from an empty rule set (everything is
        kept unless a rule says otherwise).
    """

    def __init__(self, use_defaults=True):
        #: Action for options with no schema entry: "keep" or "drop"
        self.unknown_option_policy = KEEP
        #: Action for unknown (unregistered) blocks: "keep" or "drop"
        self.unknown_block_policy = KEEP
        self._option_rules = {}  # {block_cls: {name_or_code: (action, value)}}
        self._drop_blocks = set()  # block classes to drop entirely
        if use_defaults:
            for block_name, option_names in _DEFAULT_OPTION_DROPS.items():
                for option_name in option_names:
                    self.set_option_rule(block_name, option_name, DROP)
            for block_name in _DEFAULT_DROPPED_BLOCKS:
                self.drop_block(block_name)

    def set_option_rule(self, block, option, rule):
        """
        Set the rule for a single option of a block type.

        :param block:
            Block type, either as a class from :py:mod:`pcapng.blocks`,
            a name from :py:data:`BLOCK_TYPES_BY_NAME` or a block
            magic number.
        :param option:
            Option name (eg. ``"shb_os"``) or numeric option code.
        :param rule:
            One of ``"drop"``, ``"keep"``, ``("replace", value)`` or
            a callable receiving the old (decoded) value and returning
            the new one.
        """
        block_cls = _normalize_block(block)
        normalized = _normalize_rule(rule)
        self._option_rules.setdefault(block_cls, {})[option] = normalized

    def drop_block(self, block, drop=True):
        """
        Select whether a whole block type should be dropped from the
        output. Blocks required to parse the packet data (section
        headers, interface descriptions, packet blocks) cannot be
        dropped; attempting to do so fails validation.
        """
        block_cls = _normalize_block(block)
        if drop:
            self._drop_blocks.add(block_cls)
        else:
            self._drop_blocks.discard(block_cls)

    @property
    def dropped_blocks(self):
        return frozenset(self._drop_blocks)

    def validate(self):
        """
        Check the rules for consistency and resolve option names to
        numeric codes.

        :raises SanitizeConfigError:
            if any rule is invalid, eg. it references an unknown
            option, or attempts to modify structural information
            required to parse the packet data.
        :return:
            A dict ``{block_cls: {option_code: (action, value)}}``
            with all option rules resolved.
        """
        errors = []

        if self.unknown_option_policy not in _POLICIES:
            errors.append(
                "unknown_option_policy must be one of {0}, got {1!r}".format(
                    _POLICIES, self.unknown_option_policy
                )
            )
        if self.unknown_block_policy not in _POLICIES:
            errors.append(
                "unknown_block_policy must be one of {0}, got {1!r}".format(
                    _POLICIES, self.unknown_block_policy
                )
            )

        for block_cls in sorted(self._drop_blocks, key=_block_label):
            if block_cls in _PROTECTED_BLOCKS:
                errors.append(
                    "Cannot drop block {0}: it is required to parse "
                    "the packet data".format(_block_label(block_cls))
                )

        resolved = {}
        for block_cls in sorted(self._option_rules, key=_block_label):
            rules = self._option_rules[block_cls]
            options_schema = _options_schema_for(block_cls)
            resolved[block_cls] = {}
            for option, (action, value) in sorted(rules.items(), key=repr):
                code = self._resolve_option(
                    block_cls, options_schema, option, errors
                )
                if code is None:
                    continue
                if code == 0:
                    errors.append(
                        "Cannot set a rule for opt_endofopt on block {0}: "
                        "it is a structural marker".format(_block_label(block_cls))
                    )
                    continue
                protected_names = _PROTECTED_OPTIONS.get(block_cls, ())
                protected_codes = set(
                    options_schema._field_names.get(name)
                    for name in protected_names
                )
                if code in protected_codes:
                    errors.append(
                        "Cannot modify option {0!r} of block {1}: it is "
                        "required to parse the packet data".format(
                            option, _block_label(block_cls)
                        )
                    )
                    continue
                resolved[block_cls][code] = (action, value)

        if errors:
            raise SanitizeConfigError(
                "Invalid sanitizer configuration:\n"
                + "\n".join("- " + e for e in errors)
            )
        return resolved

    @staticmethod
    def _resolve_option(block_cls, options_schema, option, errors):
        if options_schema is None:
            errors.append(
                "Block {0} has no options, cannot set option rules on "
                "it".format(_block_label(block_cls))
            )
            return None
        if isinstance(option, int):
            return option
        code = options_schema._field_names.get(option)
        if code is None:
            errors.append(
                "Unknown option {0!r} for block {1}".format(
                    option, _block_label(block_cls)
                )
            )
            return None
        return code


class SanitizeReport(object):
    """
    Report of what a :py:class:`Sanitizer` run did.

    All ``dropped_*`` / ``replaced_*`` / ``unknown_*`` attributes are
    dicts mapping a description key to the number of occurrences, so
    that nothing is silently discarded without being listed here.
    """

    def __init__(self):
        #: Total number of blocks read from the input
        self.blocks_read = 0
        #: Total number of blocks written to the output
        self.blocks_written = 0
        #: {block name: count} of blocks dropped entirely
        self.dropped_blocks = {}
        #: {(block name, option name): count} of dropped options
        self.dropped_options = {}
        #: {(block name, option name): count} of replaced options
        self.replaced_options = {}
        #: {(block name, option code, action): count} of options with
        #: no schema entry, handled via the unknown option policy
        self.unknown_options = {}
        #: {(block type, action): count} of unknown blocks,
        #: handled via the unknown block policy
        self.unknown_blocks = {}

    @staticmethod
    def _bump(counter, key):
        counter[key] = counter.get(key, 0) + 1

    def note_dropped_block(self, block_label):
        self._bump(self.dropped_blocks, block_label)

    def note_dropped_option(self, block_label, option_label):
        self._bump(self.dropped_options, (block_label, option_label))

    def note_replaced_option(self, block_label, option_label):
        self._bump(self.replaced_options, (block_label, option_label))

    def note_unknown_option(self, block_label, code, action):
        self._bump(self.unknown_options, (block_label, code, action))

    def note_unknown_block(self, block_type, action):
        self._bump(self.unknown_blocks, (block_type, action))

    def __repr__(self):
        return (
            "<{name} blocks_read={0.blocks_read} "
            "blocks_written={0.blocks_written} "
            "dropped_blocks={0.dropped_blocks} "
            "dropped_options={0.dropped_options} "
            "replaced_options={0.replaced_options} "
            "unknown_options={0.unknown_options} "
            "unknown_blocks={0.unknown_blocks}>"
        ).format(self, name=self.__class__.__name__)


class Sanitizer(object):
    """
    Sanitize pcap-ng capture streams according to a set of rules.

    The rules are validated when the sanitizer is created; if any
    rule is invalid (eg. it attempts to modify structural fields
    required to parse the packet data), :py:class:`SanitizeConfigError`
    is raised immediately, before any stream is touched.

    :param rules:
        a :py:class:`SanitizeRules` instance. If omitted, the
        default rules are used.
    """

    def __init__(self, rules=None):
        self.rules = rules if rules is not None else SanitizeRules()
        # Validate (and resolve) the rules upfront, so that an invalid
        # configuration fails before anything is written anywhere.
        self._resolved_option_rules = self.rules.validate()

    def sanitize_stream(self, instream, outstream):
        """
        Sanitize the pcap-ng data read from ``instream`` and write
        the result to ``outstream``.

        The output is fully assembled in memory first and only written
        to ``outstream`` once sanitization has succeeded, so a failure
        never leaves a half-written file behind.

        :return: a :py:class:`SanitizeReport`
        """
        report = SanitizeReport()
        buffer = io.BytesIO()
        endianness = "="
        for block in FileScanner(instream):
            report.blocks_read += 1
            if isinstance(block, blocks.SectionHeader):
                endianness = block.endianness
            if self._process_block(block, buffer, report, endianness):
                report.blocks_written += 1
        outstream.write(buffer.getvalue())
        return report

    def sanitize_file(self, inpath, outpath):
        """
        Sanitize the capture file at ``inpath`` and write the result
        to ``outpath``. The output file is only written once the
        whole input has been sanitized successfully.

        :return: a :py:class:`SanitizeReport`
        """
        buffer = io.BytesIO()
        with open(inpath, "rb") as fp:
            report = self.sanitize_stream(fp, buffer)
        with open(outpath, "wb") as fp:
            fp.write(buffer.getvalue())
        return report

    # -------------------- Internals --------------------

    def _process_block(self, block, out, report, endianness):
        """Process a single block. Returns True if it was written."""
        if isinstance(block, blocks.UnknownBlock):
            return self._process_unknown_block(block, out, report, endianness)

        block_cls = type(block)
        label = _block_label(block_cls)

        if block_cls in self.rules.dropped_blocks:
            report.note_dropped_block(label)
            return False

        self._sanitize_options(block, block_cls, label, report)
        block._write(out)
        return True

    def _process_unknown_block(self, block, out, report, endianness):
        action = self.rules.unknown_block_policy
        report.note_unknown_block(block.block_type, action)
        if action == DROP:
            return False
        # Keep the block verbatim, including its original padding
        data = block.data
        write_int(block.block_type, out, 32, endianness=endianness)
        write_int(12 + len(data), out, 32, endianness=endianness)
        write_bytes_padded(out, data)
        write_int(12 + len(data), out, 32, endianness=endianness)
        return True

    def _sanitize_options(self, block, block_cls, label, report):
        options = getattr(block, "options", None)
        if options is None:
            return

        rules = self._resolved_option_rules.get(block_cls, {})

        for code, (action, value) in rules.items():
            if code not in options.data:
                continue
            option_label = options._get_name_alias(code)
            if action == DROP:
                del options.data[code]
                report.note_dropped_option(label, option_label)
            elif action == REPLACE:
                if callable(value):
                    options.data[code] = [value(v) for v in options.data[code]]
                else:
                    options.data[code] = [value]
                report.note_replaced_option(label, option_label)
            # KEEP: nothing to do

        # Options with no schema entry and no explicit rule: never
        # guess their contents, apply the configured policy instead
        # and list them in the report.
        for code in list(options.data):
            if code in options.schema or code in rules:
                continue
            action = self.rules.unknown_option_policy
            report.note_unknown_option(label, code, action)
            if action == DROP:
                del options.data[code]
