"""Execute both uninstallers' host-route cleanup with mocked PowerShell cmdlets."""

import ast
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MOCK = ROOT / "windows/src/vpn_core/network/host_route/tests/routes_mock.ps1"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


@unittest.skipUnless(POWERSHELL, "requires PowerShell")
class UninstallerRouteTests(unittest.TestCase):
    def test_uninstallers_remove_only_recorded_host_routes(self):
        for name in ["uninstall_cli_windows.py", "uninstall_gui_windows.py"]:
            with self.subTest(script=name):
                tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
                function = next(node for node in tree.body
                                if isinstance(node, ast.FunctionDef) and node.name == "repair_network_state")
                script = next(node.value for node in ast.walk(function)
                              if isinstance(node, ast.Constant) and isinstance(node.value, str)
                              and "last_host_route.txt" in node.value)
                cleanup = script[script.index("$persisted ="):script.index("$persistedDnsPath")]
                setup = ("$targetPrefix='203.0.113.10/32'; $defaultPrefix='0.0.0.0/0'; "
                         "$nextHop='192.0.2.1'; $foreignNextHop='192.0.2.99'; "
                         "$existing=$false; $uninstaller=$true;")
                mock = MOCK.read_text().replace("# SETUP_SCRIPT", setup).replace("# CLEANUP_SCRIPT", cleanup)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "routes.ps1"
                    path.write_text(mock)
                    result = subprocess.run(
                        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                        env={**os.environ, "ProgramData": directory},
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("host route ownership checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
