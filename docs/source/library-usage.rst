Library usage
#############

Use the :py:class:`~pcapng.scanner.FileScanner` class to iterate over blocks
in a pcap-ng archive file, like this:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Block types can be checked against blocks in :py:mod:`pcapng.blocks`.

Random access with a sidecar index
-----------------------------------

Scanning a very large capture from the beginning just to reach packet N is
wasteful. :mod:`pcapng.index` builds a compact sidecar index in one pass and
then reads any contiguous range of packets directly:

.. code-block:: python

    from pcapng import build_index, open_index, CountingReader

    # One full scan; writes "capture.pcapng.pcngidx" next to the capture.
    build_index("capture.pcapng")

    # Loading validates the index against the file size and a SHA-256
    # content fingerprint; a replaced or same-length rewritten capture is
    # rejected with StaleIndexError.
    with open_index("capture.pcapng") as index:
        with index.open_reader() as reader:
            packet = reader.read_packet(100000)          # random access
            for pkt in reader.read_range(500, 520):     # contiguous range
                ...

The index records each packet block's file offset together with the section
and interface context needed to resume parsing (byte order, link type, snap
length and timestamp resolution); packet payloads are never stored in it.
Files with multiple sections of different byte order, unknown blocks and
several interfaces per section are supported.

To prove a targeted read does not rescan the capture, wrap the file in a
:class:`~pcapng.index.CountingReader`; its ``bytes_read`` attribute counts
only bytes actually transferred (seeks are free) and for a small range stays
proportional to that range regardless of total file size:

.. code-block:: python

    with open_index("capture.pcapng", verify=False) as index:
        with open("capture.pcapng", "rb") as fp:
            counter = CountingReader(fp)
            with index.open_reader(counter) as reader:
                packet = reader.read_packet(len(index) - 1)
            print(counter.bytes_read)  # size of that one block, not the file
