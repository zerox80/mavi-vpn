"""Run only the uninstallers' DNS cleanup, with every OS operation mocked."""

import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MOCK = ROOT / "windows/src/vpn_core/network/adapter/tests/nrpt_mock.ps1"


@unittest.skipUnless(sys.platform == "win32", "requires Windows PowerShell")
class UninstallerDnsTests(unittest.TestCase):
    def test_uninstallers_preserve_foreign_dns_policies(self):
        for name in ["uninstall_cli_windows.py", "uninstall_gui_windows.py"]:
            with self.subTest(script=name):
                tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
                function = next(
                    node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "repair_network_state"
                )
                script = next(
                    node.value for node in ast.walk(function)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and "Get-DnsClientNrptRule" in node.value
                )
                # Exclude the unrelated route repair and service restart code.
                dns = script[script.index("$persistedDnsPath"):script.index("Clear-DnsClientCache")]
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "mock-cleanup.ps1"
                    path.write_text(MOCK.read_text().replace("# CLEANUP_SCRIPT", dns))
                    result = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertIn("ownership checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
