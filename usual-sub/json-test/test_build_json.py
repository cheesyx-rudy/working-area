import importlib.util, sys
from pathlib import Path
P=Path(__file__).with_name('build_json.py')
spec=importlib.util.spec_from_file_location('json_builder_test',P)
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)

def test_vless_reality():
    ob=m.convert('vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?encryption=none&security=reality&sni=example.org&fp=chrome&pbk=abc&sid=123&type=tcp#Test',1)
    assert ob['type']=='vless' and ob['uuid'].startswith('123e')
    assert ob['tls']['reality']['public_key']=='abc'

def test_trojan_ws():
    ob=m.convert('trojan://secret@example.com:443?security=tls&type=ws&host=cdn.example.org&path=%2Fws#Test',2)
    assert ob['type']=='trojan' and ob['transport']['type']=='ws'
    assert ob['transport']['headers']['Host']=='cdn.example.org'

def test_build_has_balancer():
    cfg, errors=m.build(['vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&sni=example.org#Test'])
    assert cfg['route']['final']=='auto-balance'
    assert any(x.get('type')=='urltest' and x.get('tag')=='auto-balance' for x in cfg['outbounds'])
