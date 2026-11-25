import json
import tempfile
import unittest
from pathlib import Path

from sentineltrace.api import (
    create_integrity_manifest,
    verify_integrity_manifest,
)


class IntegrityTests(unittest.TestCase):
    def test_manifest_verifies_unchanged_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "events.json").write_text('[{"event_id":"4624"}]')
            (folder / "investigation.json").write_text('{"id":"test"}')

            create_integrity_manifest(folder)
            result = verify_integrity_manifest(folder)

            self.assertTrue(result["verified"])
            self.assertEqual(result["artifact_count"], 2)
            self.assertTrue(all(
                value == "verified" for value in result["results"].values()
            ))

    def test_manifest_detects_modified_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            artifact = folder / "events.json"
            artifact.write_text('{"original":true}')

            create_integrity_manifest(folder)
            artifact.write_text('{"modified":true}')

            result = verify_integrity_manifest(folder)
            self.assertFalse(result["verified"])
            self.assertEqual(result["results"]["events.json"], "mismatch")

    def test_manifest_detects_missing_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            artifact = folder / "events.json"
            artifact.write_text('{"present":true}')

            create_integrity_manifest(folder)
            artifact.unlink()

            result = verify_integrity_manifest(folder)
            self.assertFalse(result["verified"])
            self.assertEqual(result["results"]["events.json"], "missing")


if __name__ == "__main__":
    unittest.main()
