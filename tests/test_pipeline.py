import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import pipeline

class PipelineTests(unittest.TestCase):
    def test_yaml_has_xray_get_keepalive(self):
        cfg = pipeline.load_config(ROOT / "configs" / "strict.yaml")
        stages = {s["name"]: s for s in cfg["stages"]}
        self.assertEqual(stages["xray_probe"]["core"], "xray")
        self.assertEqual(stages["xray_probe"]["mode"], "proxy_get")
        self.assertEqual(stages["xray_probe"]["request_mode"], "keepalive")

    def test_cluster_key_groups_parameter_variants_same_endpoint(self):
        a = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=tcp&pbk=one&sni=a.example"
        b = "vless://22222222-2222-4222-8222-222222222222@example.com:443?security=reality&type=tcp&pbk=two&sni=b.example"
        self.assertEqual(pipeline.cluster_key(a), pipeline.cluster_key(b))

    def test_fragment_is_removed_from_identity(self):
        self.assertEqual(pipeline.ident("vless://user@example.com:443#one"), pipeline.ident("vless://user@example.com:443#two"))

if __name__ == "__main__":
    unittest.main()
