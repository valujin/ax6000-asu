"""Client revision strings must reach the cohort policy without widening other fields."""

import unittest

from pydantic import ValidationError

from asu.build_request import BuildRequest


class BuildRequestRevisionTests(unittest.TestCase):
    def request(self, **changes):
        return BuildRequest(
            **{
                "version": "24.10-SNAPSHOT",
                "target": "mediatek/filogic",
                "profile": "xiaomi_redmi-router-ax6000-stock",
                **changes,
            }
        )

    def test_native_and_upstream_revisions_are_accepted(self):
        for revision in ("", "r26741-dcc4307205", "r0+33648-ec9ef10efc"):
            with self.subTest(revision=revision):
                self.assertEqual(
                    self.request(version_code=revision).version_code, revision
                )

    def test_revision_rejects_shell_path_and_control_characters(self):
        for revision in (
            "r1/path",
            "r1;id",
            "r1$(id)",
            "r1`id`",
            "r1|cat",
            "r1 name",
            "r1\n",
            "r1\r",
            "r1\x00",
            "r1\\path",
        ):
            with self.subTest(revision=revision):
                with self.assertRaises(ValidationError):
                    self.request(version_code=revision)

    def test_plus_remains_invalid_in_other_name_fields(self):
        for changes in (
            {"distro": "open+wrt"},
            {"version": "24.10+SNAPSHOT"},
            {"profile": "xiaomi+redmi"},
            {"packages": ["busy+box"]},
            {"packages_versions": {"busy+box": "1.0"}},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    self.request(**changes)


if __name__ == "__main__":
    unittest.main()
