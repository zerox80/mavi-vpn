"""Exercise service rendering and the actual installer without host changes."""
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_cli_linux", ROOT / "install_cli_linux.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class LinuxInstallerTests(unittest.TestCase):
    def test_custom_destination_is_written_to_the_installed_service(self):
        for destination in ["/opt/mavi/mavi-vpn", "/opt/Mavi VPN/mavi-vpn"]:
            with self.subTest(destination=destination), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / "target/release/mavi-vpn"
                binary.parent.mkdir(parents=True)
                binary.touch()
                service = root / "linux/mavi-vpn.service"
                service.parent.mkdir()
                service.write_text((ROOT / "linux/mavi-vpn.service").read_text())
                calls, units = [], []

                def sudo(*args):
                    calls.append(args)
                    if args[-1] == "/etc/systemd/system/mavi-vpn.service":
                        units.append(Path(args[-2]).read_text())

                with patch.object(INSTALLER, "ROOT", root), \
                     patch.object(INSTALLER, "run"), \
                     patch.object(INSTALLER, "sudo", side_effect=sudo), \
                     patch.object(INSTALLER, "require_cmd"), \
                     patch.object(INSTALLER, "configure_ipc_group", return_value="desktop"), \
                     patch.object(INSTALLER.shutil, "which", return_value="/usr/bin/systemctl"), \
                     patch.object(INSTALLER, "ask", side_effect=[True, False, True]), \
                     patch("builtins.input", return_value=destination), \
                     contextlib.redirect_stdout(io.StringIO()):
                    INSTALLER.main()

                self.assertIn(("install", "-m", "755", str(binary), destination), calls)
                self.assertEqual(len(units), 1)
                self.assertIn(f'ExecStart="{destination}" daemon\n', units[0])
                self.assertNotIn("ExecStart=/usr/local/bin/mavi-vpn", units[0])
                self.assertIn(("systemctl", "start", "mavi-vpn"), calls)

    def test_service_path_escapes_systemd_special_characters(self):
        dest = Path('/opt/Mavi VPN/cash$100%')
        unit = INSTALLER.render_service_unit("[Service]\nExecStart=old daemon\n", dest)
        self.assertEqual(unit, '[Service]\nExecStart="/opt/Mavi VPN/cash$100%%" daemon\n')

    def test_invalid_executable_paths_cannot_inject_service_directives(self):
        for path in ["relative/mavi-vpn", "/opt/mavi\nUser=root", "/opt/mavi\r", "/opt/mavi\x00", '/opt/mavi"vpn', r"/opt/mavi\vpn"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                INSTALLER.render_service_unit("ExecStart=old\n", Path(path))

    @unittest.skipUnless(shutil.which("systemd-analyze"), "requires systemd-analyze")
    def test_systemd_accepts_the_rendered_executable_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "Mavi VPN $100%"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            unit = root / "mavi-test.service"
            unit.write_text(INSTALLER.render_service_unit("[Service]\nType=oneshot\nExecStart=old daemon\n", binary))
            result = subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
