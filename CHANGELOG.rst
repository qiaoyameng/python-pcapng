History
#######

Unreleased
==========

- Add a configurable metadata sanitizer (``pcapng.sanitizer``) to strip
  or replace host-identifying metadata (comments, OS / hardware
  descriptions, interface names, name resolution records) from capture
  files without touching the packet data.
- Fix writing of options with codes not present in the block schema
  (unknown options are now written back verbatim).

2.1.1
=====

- Fix deserialization of custom options

2.1.0
=====

- Use the explicit endianness everywhere when writing.

2.0.0
=====

- Write support

v0.1
====

- Support for "scanning" streams of pcap-ng data
- Support for decoding the "standard" pcap-ng blocks:

  - Section headers
  - Interface description
  - Enhanced packet
  - Simple packet (deprecated)
  - Packet (deprecated)
  - Name resolution
  - Interface statistics
