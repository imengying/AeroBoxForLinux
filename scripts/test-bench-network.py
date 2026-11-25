"""Validation of framing and reports; throughput itself is never a test gate."""
import importlib.util
import socket
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("network_bench", Path(__file__).with_name("bench-network.py"))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def test_truncated_and_corrupted_transfers_fail(self):
        for payload, message in [(b"", "truncated"), (b"x", "corruption")]:
            with self.subTest(payload=payload):
                left, right = socket.socketpair()
                with left, right:
                    right.sendall(payload)
                    right.shutdown(socket.SHUT_WR)
                    with self.assertRaisesRegex(RuntimeError, message):
                        bench.transfer(left, 1, False)

    def test_incomplete_report_is_not_a_valid_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.md"
            bench.report({"completed": False, "binaries": {"candidate": {}},
                          "cases": ["direct"], "samples": []}, path)
            self.assertIn("INCOMPLETE", path.read_text())

    def test_bad_socks_reply_closes_the_connection(self):
        from unittest.mock import patch
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            left = socket.create_connection(listener.getsockname())
            right, _ = listener.accept()
        with right:
            right.sendall(b"\x05\xff")
            with patch.object(bench.socket, "create_connection", return_value=left):
                with self.assertRaisesRegex(RuntimeError, "method rejected"):
                    bench.connect(1, 2)
            self.assertEqual(left.fileno(), -1)


if __name__ == "__main__":
    unittest.main()
