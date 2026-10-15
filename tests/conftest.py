"""Shared helpers that build synthetic pcap fixtures entirely in code.

No binary blobs are committed: classic pcap framing is assembled with
``struct`` and packet payloads with scapy, so every test controls the exact
bytes the tool parses -- including deliberately truncated and malformed ones.
"""

import struct

import pytest
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from pcap_file_recovery.recovery import FileRecoveryTool

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def pcap_global_header(linktype: int = LINKTYPE_ETHERNET) -> bytes:
    """Classic libpcap global header (little-endian, v2.4)."""
    return struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, linktype)


def pcap_record(frame: bytes, incl_len: int | None = None, orig_len: int | None = None) -> bytes:
    """Per-packet record header + frame bytes; lengths can be forged."""
    incl = len(frame) if incl_len is None else incl_len
    orig = len(frame) if orig_len is None else orig_len
    return struct.pack("<IIII", 0, 0, incl, orig) + frame


def build_pcap(frames: list[bytes]) -> bytes:
    """A complete, well-formed classic pcap file containing the given frames."""
    return pcap_global_header() + b"".join(pcap_record(f) for f in frames)


def tcp_frame(payload: bytes, sport: int = 80, dport: int = 40000,
              src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    return bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload))


def http_response_frame(filename: str, body: bytes, dport: int = 40000) -> bytes:
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="' + filename.encode() + b'"\r\n'
        b"\r\n" + body
    )
    return tcp_frame(payload, sport=80, dport=dport)


def tcp_frame_seq(payload: bytes, seq: int, sport: int = 80, dport: int = 40000,
                  src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    """TCP frame carrying an explicit sequence number.

    Needed to build streams whose on-the-wire order differs from capture order,
    which is exactly the case a reassembler has to get right.
    """
    return bytes(
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq) / Raw(load=payload)
    )


def dns_query_frame(qname: str | bytes) -> bytes:
    return bytes(
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )


def icmp_frame(payload: bytes) -> bytes:
    return bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP() / Raw(load=payload))


@pytest.fixture
def run_tool(tmp_path):
    """Write pcap bytes to disk, run the tool on them, return (tool, output_dir, loaded_ok)."""

    def _run(pcap_bytes: bytes, **kwargs):
        pcap_path = tmp_path / "capture.pcap"
        pcap_path.write_bytes(pcap_bytes)
        out_dir = tmp_path / "recovered"
        tool = FileRecoveryTool(str(pcap_path), output_dir=str(out_dir), **kwargs)
        ok = tool.analyze_traffic()
        return tool, out_dir, ok

    return _run
