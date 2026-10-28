# AmberKey Tests
# Built by Mourad.Soltani
import json
import subprocess
import sys
import unittest
from pathlib import Path

CLI = Path(__file__).parent.parent / "amberkey.py"

def run_cli(*args):
    cmd = [sys.executable, str(CLI)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result

class TestAmberKey(unittest.TestCase):
    def test_password_generates(self):
        res = run_cli("password", "-l", "16", "--json")
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data["secret"]), 16)
        self.assertGreater(data["entropy_bits"], 50)
        self.assertIn("strength", data)
        self.assertEqual(data["built_by"], "Mourad.Soltani")

    def test_passphrase(self):
        res = run_cli("passphrase", "-w", "5", "--json")
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data["secret"].split("-")), 5)
        self.assertGreater(data["entropy_bits"], 20)

    def test_hex(self):
        res = run_cli("hex", "-b", "16", "--json")
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(len(data["secret"]), 32)  # hex is 2 chars per byte
        self.assertEqual(data["entropy_bits"], 128)

    def test_analyze(self):
        res = run_cli("analyze", "TestSecret123!", "--json")
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("entropy_bits", data)
        self.assertEqual(data["type"], "analysis")

    def test_health_basic(self):
        res = run_cli("password", "-l", "8")
        self.assertEqual(res.returncode, 0)
        self.assertGreater(len(res.stdout.strip()), 0)

if __name__ == "__main__":
    unittest.main()
