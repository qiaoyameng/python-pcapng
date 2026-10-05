History
#######

Unreleased
==========

- Add multi-input pcap-ng timeline merging with independent interface mappings
- Compare merged timestamps using exact rational time values
- Require an explicit rejection or separate-section policy for Simple Packet
  Blocks because they have no timestamps

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
