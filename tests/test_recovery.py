"""Integration tests: synthetic captures in, carved files out.

Every capture is built in code (see conftest.py) so the exact hostile bytes
under test are visible in the test itself.
"""

import struct

from conftest import (
    build_pcap,
    dns_query_frame,
    http_response_frame,
    icmp_frame,
    pcap_global_header,
    pcap_record,
    tcp_frame,
    tcp_frame_seq,
)
from pcap_file_recovery.recovery import reassemble_tcp

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"A" * 32 + b"IEND\xaeB`\x82"
PDF_BODY = b"%PDF-1.4 synthetic body for testing %%EOF"
RAR_END = b"\xc4\x3d\x7b\x00\x40\x07\x00"


# --- TCP reassembly: sequence order, not capture order ---------------------


def test_reassemble_tcp_orders_by_sequence_number():
    # Segments captured in reverse wire order. Concatenating in capture order
    # would yield the same length with the two segments transposed.
    assert reassemble_tcp([(20, b"world"), (0, b"hello ")]) == b"hello world"


def test_reassemble_tcp_drops_retransmissions():
    assert reassemble_tcp([(0, b"AAA"), (3, b"BBB"), (0, b"AAA")]) == b"AAABBB"


def test_reassemble_tcp_handles_sequence_wraparound():
    # First segment straddles the 32-bit boundary: 0xFFFFFFFE + 4 wraps to 0x2.
    segments = [(0xFFFFFFFE, b"HEAD"), (0x2, b"TAIL")]
    assert reassemble_tcp(segments) == b"HEADTAIL"


def test_reassemble_tcp_keeps_identical_seq_segments_in_arrival_order():
    # Captures that never set a sequence number all report seq 0; stable order
    # must preserve arrival order rather than dropping segments.
    assert reassemble_tcp([(0, b"one"), (0, b"two")]) == b"onetwo"


def test_out_of_order_stream_carves_exact_bytes(run_tool):
    head, tail = PNG_BYTES[:20], PNG_BYTES[20:]
    frames = [
        tcp_frame_seq(tail, 20),   # captured first, belongs later on the wire
        tcp_frame_seq(head, 0),    # captured second, belongs first
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    streamed = [p.read_bytes() for p in out_dir.iterdir() if p.name.startswith("tcp_stream_")]
    assert PNG_BYTES in streamed


def test_retransmission_does_not_duplicate_carved_bytes(run_tool):
    frames = [
        tcp_frame_seq(b"\x89PNG\r\n\x1a\n", 100),
        tcp_frame_seq(b"A" * 32, 108),
        tcp_frame_seq(b"IEND\xaeB`\x82", 140),
        tcp_frame_seq(b"A" * 32, 108),  # retransmission
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    streamed = [p.read_bytes() for p in out_dir.iterdir() if p.name.startswith("tcp_stream_")]
    assert streamed and streamed[0] == PNG_BYTES


# --- HTTP messages that span several segments -------------------------------


def test_http_response_split_across_segments(run_tool):
    body = b"body-arrived-in-a-later-segment" * 8
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    cut = len(response) // 2
    frames = [
        tcp_frame_seq(response[:cut], 1000),
        tcp_frame_seq(response[cut:], 1000 + cut),
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    recovered = [f for f in tool.recovered_files if f["source"] == "HTTP Response"]
    assert len(recovered) == 1
    assert (out_dir / recovered[0]["filename"]).read_bytes() == body


def test_http_headers_and_body_in_separate_segments(run_tool):
    # The exact original failure: the header-only packet was carved as a 0-byte
    # file, then the packets carrying the body were skipped because they had no
    # headers to anchor on, so the payload never reached disk.
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 22\r\n"
        b"\r\n"
    )
    frames = [
        tcp_frame_seq(headers, 2000),
        tcp_frame_seq(b"body-part-a", 2000 + len(headers)),
        tcp_frame_seq(b"body-part-b", 2000 + len(headers) + 11),
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    http = [f for f in tool.recovered_files if f["source"] == "HTTP Response"]
    assert len(http) == 1
    assert http[0]["size"] == 22
    assert (out_dir / http[0]["filename"]).read_bytes() == b"body-part-a" + b"body-part-b"


def test_http_response_ignores_trailing_bytes(run_tool):
    body = b"exactly-this-much"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body + b"GET /next HTTP/1.1\r\n\r\n"
    )
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame_seq(response, 9000)]))
    assert ok
    recovered = [f for f in tool.recovered_files if f["source"] == "HTTP Response"]
    assert len(recovered) == 1
    assert (out_dir / recovered[0]["filename"]).read_bytes() == body


# --- carve boundaries ------------------------------------------------------


def test_rar_carve_stops_at_end_of_archive_record(run_tool):
    rar = b"Rar!\x1a\x07\x00" + b"encrypted-payload" + RAR_END + b"TRAILING-NOT-PART-OF-IT"
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame(rar, sport=4444, dport=5555)]))
    assert ok
    rars = [p.read_bytes() for p in out_dir.iterdir() if p.suffix == ".rar"]
    assert rars, "no RAR was carved"
    assert rars[0] == b"Rar!\x1a\x07\x00" + b"encrypted-payload" + RAR_END


def test_bmp_carve_truncated_to_declared_length(run_tool):
    # 14-byte file header + 40-byte DIB header + pixel data.
    dib = b"\x00" * 40
    pixels = b"\x2a" * 40
    total = 14 + len(dib) + len(pixels)
    body = (
        b"BM"
        + total.to_bytes(4, "little")
        + b"\x00" * 4
        + (54).to_bytes(4, "little")
        + dib
        + pixels
    )
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame(body + b"JUNK", sport=4444, dport=5555)]))
    assert ok
    bmps = [p.read_bytes() for p in out_dir.iterdir() if p.suffix == ".bmp"]
    assert bmps, "no BMP was carved"
    assert bmps[0] == body


def test_bmp_carve_keeps_data_when_declared_length_is_absurd(run_tool):
    # A false-positive BM hit: the declared size exceeds what we carved, so it
    # must not be trusted to truncate the carve.
    carved = b"BM" + (0xFFFFFFFF).to_bytes(4, "little") + b"\x00" * 51
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame(carved, sport=4444, dport=5555)]))
    assert ok
    bmps = [p.read_bytes() for p in out_dir.iterdir() if p.suffix == ".bmp"]
    assert bmps and bmps[0] == carved


# --- happy path -----------------------------------------------------------


def test_http_response_carve_happy_path(run_tool):
    tool, out_dir, ok = run_tool(build_pcap([http_response_frame("report.pdf", PDF_BODY)]))
    assert ok
    assert (out_dir / "report.pdf").read_bytes() == PDF_BODY
    assert any(f["source"] == "HTTP Response" for f in tool.recovered_files)


def test_png_carved_from_split_tcp_stream(run_tool):
    half = len(PNG_BYTES) // 2
    frames = [
        tcp_frame(PNG_BYTES[:half], sport=4444, dport=5555),
        tcp_frame(PNG_BYTES[half:], sport=4444, dport=5555),
    ]
    tool, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    carved = [p.read_bytes() for p in out_dir.iterdir()]
    assert PNG_BYTES in carved  # reassembled across packets, not per-packet


def test_dns_exfiltration_hex_labels_decoded(run_tool):
    _, out_dir, ok = run_tool(build_pcap([dns_query_frame("48656c6c6f.attacker.example.")]))
    assert ok
    assert (out_dir / "dns_exfiltrated_data.bin").read_bytes() == b"Hello"


def test_icmp_covert_channel_payload_carved(run_tool):
    payload = b"SECRET-EXFIL-DATA"
    _, out_dir, ok = run_tool(build_pcap([icmp_frame(payload)]))
    assert ok
    assert (out_dir / "icmp_hidden_data.bin").read_bytes() == payload


def test_smtp_base64_attachment_decoded(run_tool):
    # Regression test: base64 was never imported in the original script, so
    # this path always died with a silently-swallowed NameError.
    smtp_payload = (
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"JVBERi0xLjQ=\r\n"
        b"--boundary--\r\n"
    )
    _, out_dir, ok = run_tool(build_pcap([tcp_frame(smtp_payload, sport=4321, dport=25)]))
    assert ok
    assert (out_dir / "invoice.pdf").read_bytes() == b"%PDF-1.4"


def test_ftp_data_stream_reassembled(run_tool):
    frames = [
        tcp_frame(b"chunk-one|", sport=20, dport=6000),
        tcp_frame(b"chunk-two", sport=20, dport=6000),
    ]
    _, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    assert (out_dir / "ftp_transfer_0.bin").read_bytes() == b"chunk-one|chunk-two"


# --- hostile filenames ----------------------------------------------------


def test_http_filename_path_traversal_is_contained(run_tool, tmp_path):
    hostile = "../../../pwned.txt"
    _, out_dir, ok = run_tool(build_pcap([http_response_frame(hostile, b"owned")]))
    assert ok
    # Nothing may escape the output directory...
    assert not (tmp_path / "pwned.txt").exists()
    assert not (tmp_path.parent / "pwned.txt").exists()
    # ...but the payload is still recovered, under a sanitized name.
    assert (out_dir / "pwned.txt").read_bytes() == b"owned"


def test_absolute_path_filename_is_contained(run_tool, tmp_path):
    _, out_dir, ok = run_tool(build_pcap([http_response_frame("/etc/passwd", b"root:x:0:0")]))
    assert ok
    assert (out_dir / "passwd").read_bytes() == b"root:x:0:0"
    # Only the input capture and the output directory may exist at the top level.
    assert {p.name for p in tmp_path.iterdir()} == {"capture.pcap", "recovered"}


def test_duplicate_filenames_do_not_clobber_earlier_carves(run_tool):
    frames = [
        http_response_frame("dup.txt", b"first", dport=40001),
        http_response_frame("dup.txt", b"second", dport=40002),
    ]
    _, out_dir, ok = run_tool(build_pcap(frames))
    assert ok
    contents = {(out_dir / "dup.txt").read_bytes(), (out_dir / "dup_1.txt").read_bytes()}
    assert contents == {b"first", b"second"}


def test_ftp_stor_filename_control_chars_not_echoed(run_tool, capsys):
    payload = b"STOR \x1b]0;pwned\x07innocent.txt\r\n"
    _, _, ok = run_tool(build_pcap([tcp_frame(payload, sport=4321, dport=21)]))
    assert ok
    out = capsys.readouterr().out
    assert "Found FTP upload:" in out
    assert "\x1b" not in out and "\x07" not in out


# --- malformed and truncated captures -------------------------------------


def test_empty_capture_reports_nothing(run_tool):
    tool, out_dir, ok = run_tool(pcap_global_header())
    assert ok
    assert tool.recovered_files == []
    assert list(out_dir.iterdir()) == []  # no summary, no stray files


def test_truncated_record_header_does_not_crash(run_tool):
    tool, _, ok = run_tool(pcap_global_header() + b"\x00" * 8)
    assert ok
    assert tool.recovered_files == []


def test_record_length_field_larger_than_data(run_tool):
    # incl_len claims 50 bytes, only 5 are present.
    blob = pcap_global_header() + struct.pack("<IIII", 0, 0, 50, 50) + b"short"
    tool, _, ok = run_tool(blob)
    assert ok
    assert tool.recovered_files == []


def test_huge_length_field_does_not_exhaust_memory(run_tool):
    # incl_len claims ~4GB; the file holds 4 bytes. Must not allocate 4GB.
    blob = pcap_global_header() + pcap_record(b"tiny", incl_len=0xFFFFFFF0, orig_len=0xFFFFFFF0)
    tool, _, ok = run_tool(blob)
    assert ok
    assert tool.recovered_files == []


def test_garbage_input_fails_cleanly(run_tool):
    tool, _, ok = run_tool(b"this is not a pcap file at all..........")
    assert ok is False
    assert tool.recovered_files == []


def test_truncated_global_header_fails_cleanly(run_tool):
    tool, _, ok = run_tool(pcap_global_header()[:12])
    assert ok is False
    assert tool.recovered_files == []


def test_non_utf8_dns_qname_does_not_crash(run_tool):
    _, _, ok = run_tool(build_pcap([dns_query_frame(b"\xff\xfe\xfd.example.")]))
    assert ok


def test_odd_length_hex_dns_label_is_skipped(run_tool):
    _, out_dir, ok = run_tool(build_pcap([dns_query_frame("48656c6c6.example.")]))
    assert ok
    assert not (out_dir / "dns_exfiltrated_data.bin").exists()


# --- resource exhaustion --------------------------------------------------


def test_max_files_cap_stops_carve_bomb(run_tool):
    frames = [http_response_frame(f"file{i}.txt", b"x" * 8, dport=41000 + i) for i in range(5)]
    tool, out_dir, ok = run_tool(build_pcap(frames), max_files=2)
    assert ok
    assert len(tool.recovered_files) == 2
    carved = [p for p in out_dir.iterdir() if p.name != "recovery_summary.txt"]
    assert len(carved) == 2


def test_signature_carve_is_size_capped(run_tool):
    # A PDF header with no %%EOF trailer must be capped, not carved unbounded.
    big = b"%PDF-1.7 " + b"B" * 4096
    tool, out_dir, ok = run_tool(build_pcap([tcp_frame(big, sport=4444, dport=5555)]))
    assert ok
    for f in tool.recovered_files:
        assert f["size"] <= tool.max_carve_size
