"""Exercise the actual package removal hook with a mocked service manager."""

from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which("sh"), "requires a POSIX shell")
class PackageRemovalTests(unittest.TestCase):
    def commands(self, action):
        wrapper = '''
systemctl() { printf '%s\\n' "$*"; }
script=$1
shift
. "$script"
'''
        result = subprocess.run(
            ["sh", "-c", wrapper, "test", str(ROOT / "gui/src-tauri/linux/prerm"), action],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.splitlines()

    def test_rpm_upgrade_preserves_service(self):
        for remaining in ["1", "2"]:
            with self.subTest(remaining=remaining):
                self.assertEqual(self.commands(remaining), [])

    def test_debian_upgrade_and_failed_upgrade_preserve_service(self):
        for action in ["upgrade", "failed-upgrade"]:
            with self.subTest(action=action):
                self.assertEqual(self.commands(action), [])

    def test_actual_removal_stops_and_disables_service(self):
        for action in ["0", "remove", "deconfigure"]:
            with self.subTest(action=action):
                self.assertEqual(
                    self.commands(action),
                    ["stop mavi-vpn.service", "disable mavi-vpn.service"],
                )


if __name__ == "__main__":
    unittest.main()
