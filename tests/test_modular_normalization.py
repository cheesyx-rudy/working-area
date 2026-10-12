import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
from domain import ProxyURI
from normalizer import semantic_key, deduplicate_semantic
from modules.registry import discover

class SemanticNormalizationTests(unittest.TestCase):
    def test_same_resolved_endpoint_and_same_profile_collapse(self):
        a = "vless://11111111-1111-4111-8111-111111111111@node-a.example:443?security=reality&type=tcp&sni=site.example&pbk=key&sid=01#A"
        b = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?security=reality&type=tcp&sni=site.example&pbk=key&sid=01#B"
        with patch("normalizer.socket.getaddrinfo", return_value=[(2,1,6,"",("203.0.113.10",0))]):
            self.assertEqual(semantic_key(a), semantic_key(b))

    def test_different_accounts_are_never_collapsed(self):
        a = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=tcp&sni=site.example&pbk=key&sid=01"
        b = "vless://22222222-2222-4222-8222-222222222222@example.com:443?security=reality&type=tcp&sni=site.example&pbk=key&sid=01"
        self.assertNotEqual(semantic_key(a), semantic_key(b))

    def test_different_transports_are_kept(self):
        a = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&sni=site.example"
        b = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=grpc&sni=site.example&serviceName=x"
        self.assertNotEqual(semantic_key(a), semantic_key(b))

    def test_plugin_autodiscovery(self):
        self.assertIn("telegram_site_check", discover())

if __name__ == "__main__": unittest.main()
