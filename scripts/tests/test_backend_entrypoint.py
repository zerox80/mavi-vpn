"""Exercise startup with mocked networking commands and an isolated /proc tree."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BackendEntrypointTests(unittest.TestCase):
    def run_entrypoint(self, ipv6_present, disable_ipv6, ipv6_nat_available,
                       route_output="8.8.8.8 via 192.0.2.1 dev eth0 src 192.0.2.2"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "bin"
            commands.mkdir()
            proc = root / "proc"
            (proc / "ipv4").mkdir(parents=True)
            if ipv6_present:
                (proc / "ipv6/conf/all").mkdir(parents=True)
                (proc / "ipv6/conf/all/forwarding").write_text("1\n")
                (proc / "ipv6/conf/eth0").mkdir()
                (proc / "ipv6/conf/eth0/accept_ra").write_text("2\n")
            log = root / "commands.log"
            for name in ["ip", "iptables", "ip6tables", "sysctl"]:
                path = commands / name
                path.write_text("""#!/bin/bash
echo "$(basename "$0") $*" >> "$TEST_COMMAND_LOG"
case "$(basename "$0") $*" in
    'ip route get '*) printf '%s\\n' "$TEST_ROUTE_OUTPUT" ;;
    'ip -6 addr show dev eth0 scope global') echo 'inet6 2001:db8::2/64 scope global' ;;
    'ip -6 route show default') echo 'default via fe80::1 dev eth0' ;;
    iptables*' -C '*) exit 1 ;;
    ip6tables*)
        if [ "$TEST_IPV6_NAT" != true ]; then exit 3; fi
        case "$*" in *' -C '*) exit 1 ;; esac ;;
esac
""")
                path.chmod(0o755)
            server = commands / "mavi-vpn"
            server.write_text('#!/bin/bash\necho "SERVER_STARTED IPv6=${VPN_DISABLE_IPV6:-false}"\n')
            server.chmod(0o755)
            script = (ROOT / "backend/entrypoint.sh").read_text()
            script = script.replace("/dev/net/tun", "/dev/null")
            script = script.replace("/proc/sys/net", str(proc))
            script = script.replace("/app/mavi-vpn", str(server))
            path = root / "entrypoint.sh"
            path.write_text(script)
            env = {**os.environ, "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}",
                   "VPN_AUTH_TOKEN": "test-token", "VPN_KEYCLOAK_ENABLED": "false",
                   "VPN_DISABLE_IPV6": str(disable_ipv6).lower(),
                   "VPN_MSS_CLAMPING": "false", "VPN_IPV6_WAIT": "1",
                   "TEST_COMMAND_LOG": str(log), "TEST_IPV6_NAT": str(ipv6_nat_available).lower(),
                   "TEST_ROUTE_OUTPUT": route_output}
            result = subprocess.run(["bash", str(path)], env=env, capture_output=True, text=True, timeout=10)
            return result, log.read_text()

    def test_kernel_without_ipv6_starts_ipv4_server(self):
        result, commands = self.run_entrypoint(False, False, False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SERVER_STARTED IPv6=true", result.stdout)
        self.assertNotIn("ip6tables -t nat -L", commands)

    def test_explicit_ipv4_mode_does_not_require_ipv6_nat(self):
        result, commands = self.run_entrypoint(True, True, False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SERVER_STARTED IPv6=true", result.stdout)
        self.assertNotIn("ip6tables -t nat -L", commands)

    def test_ipv6_mode_still_verifies_ipv6_nat(self):
        result, commands = self.run_entrypoint(True, False, True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SERVER_STARTED IPv6=false", result.stdout)
        self.assertIn("ip6tables -t nat -L", commands)

    def test_nat_uses_the_selected_device_for_gatewayless_and_reordered_routes(self):
        for route, device in [
            ("8.8.8.8 dev ppp0 src 192.0.2.2", "ppp0"),
            ("8.8.8.8 dev eth1 src 192.0.2.2 uid 1000\n    cache", "eth1"),
            ("8.8.8.8 via 192.0.2.1 src 192.0.2.2 dev eth2", "eth2"),
        ]:
            with self.subTest(route=route):
                result, commands = self.run_entrypoint(False, True, False, route)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"Detected default interface: {device}", result.stdout)
                self.assertIn(f"-o {device} -j MASQUERADE", commands)
                self.assertNotIn("-o 192.0.2.2", commands)


if __name__ == "__main__":
    unittest.main()
