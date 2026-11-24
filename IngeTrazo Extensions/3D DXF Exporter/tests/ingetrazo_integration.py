"""Exercise direct AcadRust exchange with native IngeTrazo objects."""
import argparse
import ast
import base64
import importlib.abc
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("ingetrazo_source", type=Path)
parser.add_argument("converter", type=Path)
parser.add_argument("--mesh-fixtures", type=Path)
args = parser.parse_args()
sys.path.insert(0, str(args.ingetrazo_source.resolve()))
os.environ["QT_QPA_PLATFORM"] = "offscreen"
from PySide6.QtWidgets import QApplication
from core.scene import Scene
from core._native import engine

app = QApplication([])
exe = args.converter.resolve()
plugin = runpy.run_path(str(Path(__file__).resolve().parents[1] / "BlackFox_CAD_Exporter_v1_0_2.py"))
records = [
    {"layer": "Check", "kind": "guide_line", "position": [3, 3, 4], "direction": [0, 1, 0]},
    {"layer": "Check", "kind": "aligned_dimension", "start": [0, 0, 0], "end": [5, 5, 20], "dimension_line": [20, 5, 20], "text": "Rise <>", "axis": "z"},
    {"layer": "Check", "kind": "leader", "anchor": [0, 0, 5], "label_position": [4, 2, 5], "text": "Leader", "height": 0.5},
    {"layer": "Check", "kind": "polyline", "vertices": [[0, 0, 8], [2, 0, 8], [2, 2, 8]], "closed": True},
    {"layer": "Check", "kind": "aligned_dimension", "start": [0, 0, 0], "end": [20, 0, 0], "dimension_line": [20, 5, 0], "text": "Track <>"},
    {"layer": "Check", "kind": "line", "start": [0, 0, 0], "end": [20, 0, 0]},
    {"layer": "Check", "kind": "point", "position": [2, 3, 4]},
    {"layer": "Check", "kind": "face", "corners": [[0, 0, 0], [1, 0, 0], [0, 1, 0]]},
    {"layer": "Check", "kind": "mesh", "vertices": [[0, 0, 1], [2, 0, 1], [0, 2, 1]], "faces": [[0, 1, 2]]},
    {"layer": "Check", "kind": "text", "position": [1, 1, 3], "text": "Native annotation", "height": 0.5, "rotation": 0.2},
]
with TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    folder = Path(tmp)
    model = folder / "model.json"
    model.write_text(json.dumps({"schema": 1, "units": 4, "entities": records, "layers": {"Check": {"visible": True, "locked": True, "rgb": [0, 255, 0]}}}), encoding="utf-8")
    for version, code in (("R13", b"AC1012"), ("R14", b"AC1014")):
        for extension, versions in (("dxf", "DXF_VERSIONS"), ("dwg", "DWG_VERSIONS")):
            assert version in plugin[versions]
            drawing = folder / f"legacy-{version}.{extension}"
            legacy_scene = Scene()
            plugin["_load_direct_model"](legacy_scene, {"schema": 1, "entities": [records[5]]}, 1.0)
            plugin["_write_direct_cad"](exe, legacy_scene, drawing, version)
            assert code in drawing.read_bytes()[:1024]
            payload, _ = plugin["_read_direct_cad"](exe, drawing)
            entities = payload["entities"] + [
                record for block in payload["blocks"].values() for record in block
            ]
            assert any(record["kind"] == "line" for record in entities), (version, extension, payload)
    print(engine(), "R13 and R14 DXF/DWG export and read-back PASS", flush=True)

    for extension in ("dxf", "dwg"):
        drawing = folder / f"native.{extension}"
        decoded = folder / "decoded.json"
        subprocess.run([exe, "encode", model, drawing, "R2018"], check=True)
        payload, _ = plugin["_read_direct_cad"](exe, drawing)
        assert payload["units"] == 4
        assert payload["omitted"] == {}, payload["omitted"]
        assert {item["kind"] for item in payload["entities"]} == {item["kind"] for item in records}
        scene = Scene()
        plugin["_load_direct_model"](scene, payload, 0.001)
        assert len(scene.groups) == 1 and len(scene.groups[0].mesh.faces) == 2
        assert scene.layer("Check").locked and scene.layer("Check").color == (0, 1, 0)
        assert len(scene.guides) == 2
        assert all(abs(guide.point.z() - 0.004) < 1e-8 for guide in scene.guides)
        assert sum(guide.is_line for guide in scene.guides) == 1
        labels = {label.text: label for label in scene.text_labels}
        assert set(labels) == {"Leader", "Native annotation"}
        assert abs(labels["Leader"].offset.x() - 0.004) < 1e-8
        dims = {dimension.text: dimension for dimension in scene.dimensions}
        assert set(dims) == {"Track <>", "Rise <>"} and dims["Rise <>"].axis == "z"
        labels["Native annotation"].text = "Edited in IngeTrazo"
        destination = folder / f"edited.{extension}"
        plugin["_write_direct_cad"](exe, scene, destination, "R2018")
        result, _ = plugin["_read_direct_cad"](exe, destination)
        assert result["units"] == 6 and not result["omitted"]
        assert result["layers"]["Check"]["rgb"] == [0, 255, 0]
        assert sum(record["kind"] == "face" for records in result["blocks"].values() for record in records) == 2
        assert next(record for record in result["entities"] if record["kind"] == "text")["text"] == "Edited in IngeTrazo"
        nested_input = {
            "schema": 1, "units": 6,
            "entities": [
                {"layer": "0", "kind": "instance", "block": "ASSEMBLY",
                 "transform": [[-2, 0, 0, 10], [0, 3, 0, 20], [0, 0, 1, 0], [0, 0, 0, 1]]},
                {"layer": "0", "kind": "instance", "block": "ASSEMBLY",
                 "transform": [[1, 0, 0, 20], [0, 1, 0, 40], [0, 0, 1, 0], [0, 0, 0, 1]]},
            ],
            "blocks": {
                "ASSEMBLY": [{"layer": "0", "kind": "instance", "block": "PART",
                              "transform": [[0, -1, 0, 2], [1, 0, 0, 3], [0, 0, 1, 4], [0, 0, 0, 1]]}],
                "PART": [{"layer": "Check", "kind": "line", "start": [0, 0, 0], "end": [1, 0, 0]}],
            },
        }
        model.write_text(json.dumps(nested_input), encoding="utf-8")
        subprocess.run([exe, "encode", model, drawing, "R2018"], check=True)
        subprocess.run([exe, "decode", drawing, decoded], check=True)
        hierarchy = json.loads(decoded.read_text(encoding="utf-8"))
        nested_scene = Scene()
        assert not plugin["_load_direct_model"](nested_scene, hierarchy, 1.0)
        one, two = nested_scene.groups
        assert one.mesh is two.mesh
        assert one.children[0].mesh is two.children[0].mesh
        assert abs(one.xform.column(0).x() - -2) < 1e-5
        assert abs(one.children[0].xform.column(3).y() - 3) < 1e-5
        plugin["_write_direct_cad"](exe, nested_scene, destination, "R2018")
        reloaded, _ = plugin["_read_direct_cad"](exe, destination)
        assert reloaded["entities"][0]["block"] == reloaded["entities"][1]["block"]
        assert len(reloaded["blocks"]) == 2
        # Restore the fixture for the other format.
        model.write_text(json.dumps({"schema": 1, "units": 4, "entities": records, "layers": {"Check": {"visible": True, "locked": True, "rgb": [0, 255, 0]}}}), encoding="utf-8")
        print(engine(), extension.upper(), "direct AcadRust/native scene exchange PASS", flush=True)

    if args.mesh_fixtures:
        # Reuse the independent fixture builder without loading the round-trip test dependencies.
        module = ast.parse(args.mesh_fixtures.read_text(encoding="utf-8"))
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef) and node.name == "exchange_fixtures")
        symbols = dict(struct=struct, base64=base64, json=json)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(args.mesh_fixtures), "exec"), symbols)
        for mesh in symbols["exchange_fixtures"](folder):
            payload, _ = plugin["_read_direct_cad"](exe, mesh)
            mesh_scene = Scene()
            plugin["_load_direct_model"](mesh_scene, payload, 1.0)
            assert any(group.mesh.faces for group in mesh_scene.groups), mesh
        print(engine(), "six AcadRust mesh imports PASS", flush=True)

    os.environ["APPDATA"] = str(folder)
    os.environ["LOCALAPPDATA"] = str(folder)
    from PySide6.QtCore import QSettings
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(folder))
    from views.main_window import MainWindow
    window = MainWindow(defer_extensions=True)
    proxy = SimpleNamespace(window=window)
    mode = plugin["_import_cad"].__globals__
    with patch.dict(mode, {"get_converter": lambda *args, **kwargs: exe,
                           "_report_direct_import": lambda *args, **kwargs: None}), \
         patch.object(window, "_dxf_options", return_value=(1.0, False)), \
         patch.object(plugin["QFileDialog"], "getOpenFileName", return_value=(str(drawing), "")), \
         patch.object(plugin["QMessageBox"], "critical", side_effect=AssertionError):
        plugin["_import_cad"](proxy)
        assert sum(group.name == "ASSEMBLY" for group in window.viewport.scene.groups) == 2
        assert window.viewport.history.undo()
        assert all(group.name != "ASSEMBLY" for group in window.viewport.scene.groups)
        assert window.viewport.history.redo()
        menu_export = folder / "menu.dwg"
        flags = {"faces": True, "edges": True, "annotations": True, "text": True}
        with patch.dict(mode, {"_save_dialog_with_options": lambda parent: (
            str(menu_export), "dwg", "R2018", flags,
        )}), patch.object(plugin["QMessageBox"], "information"):
            plugin["Export3DDXF"]().on_activate(window.viewport)
        assert menu_export.is_file()
        exported_model = plugin["_read_direct_cad"](exe, menu_export)[0]
        instances = [record for record in exported_model["entities"] if record["kind"] == "instance"]
        assert any(sum(item["block"] == block for item in instances) == 2
                   for block in exported_model["blocks"])
    print(engine(), "direct IngeTrazo import/export actions and undo/redo PASS", flush=True)
