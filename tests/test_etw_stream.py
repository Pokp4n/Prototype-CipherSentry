"""Tests for read-only ETW JSONL streaming receiver."""
import io
import json
import unittest

from ciphersentry.etw_stream import consume_stream, parse_stream_line


class EtwStreamTests(unittest.TestCase):
    def event(self, **changes):
        value = {
            "schema": 1,
            "kind": "Write",
            "event_time_utc": "2026-11-17T03:40:01.1000000Z",
            "callback_time_utc": "2026-11-17T03:40:01.4500000Z",
            "reported_pid": 22208,
            "file_key": "0x0000000000000001",
            "file_object": "0x0000000000000002",
            "io_size": 25,
            "filename": r"C:\dev\CipherSentry\Experiments\writer-run-22208\test.txt",
            "details": "reader-prior-key-candidate",
        }
        value.update(changes)
        return value

    def test_valid_write_is_unverified_not_trusted(self):
        event = parse_stream_line(json.dumps(self.event()))
        self.assertEqual(event.reported_pid, 22208)
        self.assertEqual(event.process_attribution, "unverified_event_pid")
        self.assertAlmostEqual(event.callback_delay_ms, 350)

    def test_system_pid_is_unknown(self):
        event = parse_stream_line(json.dumps(self.event(reported_pid=4)))
        self.assertEqual(event.process_attribution, "unknown")

    def test_stream_scopes_and_reports_incrementally(self):
        items = [self.event(), self.event(reported_pid=4),
                 self.event(filename=r"C:\dev\CipherSentry\Experiments-old\private.txt"),
                 self.event(filename=None)]
        output = io.StringIO()
        result = consume_stream(io.StringIO("\n".join(json.dumps(x) for x in items) + "\n"),
                                r"C:\dev\CipherSentry\Experiments", output=output)
        self.assertEqual(result.write_events_received, 4)
        self.assertEqual(result.named_writes_in_root, 2)
        self.assertEqual(result.system_pid_writes_in_root, 1)
        self.assertEqual(result.non_system_pid_writes_in_root, 1)
        self.assertEqual(result.reader_prior_candidates_in_root, 2)
        self.assertIn("[LIVE observation 1]", output.getvalue())
        self.assertNotIn("private", output.getvalue())

    def test_rejects_wrong_schema_and_kind(self):
        for data in [self.event(schema=2), self.event(kind="ProcessStop")]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    parse_stream_line(json.dumps(data))

    def test_rejects_missing_extra_and_bad_types(self):
        missing = self.event()
        del missing["file_key"]
        for data in [missing, self.event(extra="unexpected"),
                     self.event(reported_pid=True), self.event(io_size="25")]:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    parse_stream_line(json.dumps(data))

    def test_rejects_duplicate_fields_and_oversize(self):
        with self.assertRaises(ValueError):
            parse_stream_line('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            parse_stream_line(" " * 65537)

    def test_fails_closed_on_invalid_second_record(self):
        good = json.dumps(self.event())
        with self.assertRaisesRegex(ValueError, "line 2"):
            consume_stream(io.StringIO(good + "\n" + "not json\n"),
                           r"C:\dev\CipherSentry\Experiments", output=io.StringIO())


if __name__ == "__main__":
    unittest.main()
