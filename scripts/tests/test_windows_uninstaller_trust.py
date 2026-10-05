"""Untrusted per-user registry entries must never select an elevated program."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gui_uninstall", ROOT / "uninstall_gui_windows.py")
UNINSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UNINSTALL)


class RegistryKey:
    def __init__(self, root, entry=False):
        self.root, self.entry = root, entry

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class RegistryTrustTests(unittest.TestCase):
    def find_with_registry(self, machine_path, user_path):
        opened = []

        def open_key(root, name):
            if isinstance(root, RegistryKey):
                return RegistryKey(root.root, True)
            opened.append(root)
            return RegistryKey(root)

        def enum_key(key, index):
            if index or (machine_path if key.root == "HKLM" else user_path) is None:
                raise OSError("no more keys")
            return "Mavi VPN"

        def query(key, name):
            self.assertEqual(name, "UninstallString")
            return (machine_path if key.root == "HKLM" else user_path), 1

        registry = types.SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", HKEY_CURRENT_USER="HKCU", OpenKey=open_key, EnumKey=enum_key, QueryValueEx=query)
        with patch.dict(sys.modules, winreg=registry):
            result = UNINSTALL.find_nsis_uninstaller()
        self.assertNotIn("HKCU", opened)
        return result

    def test_hkcu_only_payload_is_never_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "attacker.exe"
            payload.touch()
            self.assertIsNone(self.find_with_registry(None, str(payload)))

    def test_per_machine_uninstaller_still_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "uninstall.exe"
            executable.touch()
            self.assertEqual(self.find_with_registry(f'"{executable}"', None), str(executable))


if __name__ == "__main__":
    unittest.main()
