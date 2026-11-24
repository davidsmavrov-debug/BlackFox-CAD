"""Test the real legacy HTTPS download and verified migration."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import argparse
import os, runpy, sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("ingetrazo_source", type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.ingetrazo_source.resolve()))
source = Path(__file__).resolve().parents[1] / "BlackFox_CAD_Exporter_v1_0_1.py"
with TemporaryDirectory() as tmp:
    os.environ["APPDATA"] = tmp
    os.environ["LOCALAPPDATA"] = tmp
    ns = runpy.run_path(str(source))["setup"].__globals__
    combinations = [(s, a) for s in ("win32", "linux", "darwin") for a in ("x86_64", "aarch64")]
    assert {ns["_blackfox_platform"](system, arch)[0] for system, arch in combinations} == set(ns["CHECKSUMS"])
    approvals = []
    def approve(parent, url, rid, size):
        approvals.append(url)
        return True
    with patch.dict(ns, {"_confirm_converter_download": approve}):
        installed = ns["get_converter"]()
        assert installed.exists() and ns["get_converter"]() == installed and len(approvals) == 1
        print("Published legacy archive downloaded via HTTPS, verified, installed and reused", flush=True)
    legacy = Path(tmp) / "old" / "BlackFoxDWG" / "v1.0.0" / installed.parent.name
    legacy.mkdir(parents=True)
    for artifact in installed.parent.iterdir():
        artifact.rename(legacy / artifact.name)
    ns["__file__"] = str(legacy.parents[2] / "plugin.py")
    with patch.dict(ns, {"_confirm_converter_download": lambda *a: (_ for _ in ()).throw(AssertionError("migration unexpectedly prompted"))}):
        assert ns["get_converter"]() == installed
    print("Verified legacy cache migrated without network; all six platform IDs matched", flush=True)
