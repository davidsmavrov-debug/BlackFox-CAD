"""Check consent, persistent cache, download verification and repair."""

import argparse
import json
from pathlib import Path
import runpy
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("ingetrazo_source", type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.ingetrazo_source.resolve()))
from core import extensions

source = Path(__file__).resolve().parents[1] / "BlackFox_CAD_Exporter_v1_0_2.py"
plugin = runpy.run_path(str(source))["get_converter"].__globals__
manifest = json.loads(plugin["RELEASE_MANIFEST"])
expected = set()
for system, family in (("win32", "windows-msvc"), ("linux", "linux-gnu"),
                       ("darwin", "apple-darwin")):
    for cpu in ("x86_64", "aarch64"):
        target, filename, arch = plugin["_blackfox_platform"](system, cpu)
        assert target.startswith(cpu + "-") and target.endswith(family)
        assert filename == ("BlackFoxDWG.exe" if system == "win32" else "BlackFoxDWG")
        assert arch == cpu
        expected.add(target)
        assert plugin["_release_metadata"](target)[0] == manifest["version"]
assert set(manifest["assets"]) == expected

with TemporaryDirectory() as folder:
    root = Path(folder).resolve()
    plugins = root / "plugins"
    approvals = []

    def approve(_, url, target, size):
        approvals.append((url, target, size))
        return len(approvals) > 1

    with patch.object(extensions, "user_plugins_dir", return_value=plugins), \
         patch.dict(plugin, {"_confirm_converter_download": approve}):
        resolve = plugin["get_converter"]
        assert resolve() is None
        assert not (root / "extension-data").exists()
        exe = resolve()
        target, _, _ = plugin["_blackfox_platform"]()
        version, size, _ = plugin["_release_metadata"](target)
        assert exe.parent == root / "extension-data" / "blackfox_cad_exporter" / "bin" / version / target
        assert approvals[-1][0].endswith(f"/v{version}/blackfox-dwg-{target}.zip")
        assert approvals[-1][1:] == (target, size)
        original = exe.read_bytes()
        with patch.dict(plugin, {"_download_archive": lambda *_: (_ for _ in ()).throw(AssertionError("Unexpected download"))}):
            assert resolve() == exe and len(approvals) == 2
            exe.write_bytes(b"invalid")
            assert resolve().read_bytes() == original and len(approvals) == 2
        with patch.dict(plugin, {"RELEASE_MANIFEST_SHA256": "0" * 64}):
            try:
                resolve()
            except RuntimeError as error:
                assert "manifest failed SHA-256" in str(error)
            else:
                raise AssertionError("Invalid manifest accepted")

print("Six platform mappings, HTTPS download, consent, persistent reuse and repair PASS")
