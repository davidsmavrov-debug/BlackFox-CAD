"""Exercise the extension in a real IngeTrazo window with an isolated profile."""

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import argparse
import hashlib, json, os, runpy, shutil, subprocess, sys
from zipfile import ZipFile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("ingetrazo_source", type=Path)
parser.add_argument("converter", type=Path)
parser.add_argument("--archive", type=Path, help="Run with a packaged archive instead of a fixture ZIP")
parser.add_argument("--mesh-fixtures", type=Path, help="Optional standalone roundtrip.py for all mesh fixtures")
args = parser.parse_args()
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("INGETRAZO_RUST", "0")
sys.path.insert(0, str(args.ingetrazo_source.resolve()))
import ezdxf
from PySide6.QtCore import QSettings
from PySide6.QtGui import QVector3D
from PySide6.QtWidgets import QApplication, QMenu
from core._native import engine
from views.main_window import MainWindow

source = Path(__file__).resolve().parents[1] / "BlackFox_CAD_Exporter_v1_0_1.py"
with TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
    folder = Path(tmp)
    os.environ["APPDATA"] = str(folder)
    os.environ["LOCALAPPDATA"] = str(folder)
    app = QApplication([])
    app.setOrganizationName("BlackFoxCadQA")
    app.setApplicationName("BlackFoxCadQA")
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, tmp)
    window = MainWindow(defer_extensions=True)
    assert engine() == ("Rust" if os.environ["INGETRAZO_RUST"] == "1" else "Python")
    ns = runpy.run_path(str(source))["setup"].__globals__
    menu = QMenu(window)
    ns["setup"](SimpleNamespace(window=window, viewport=window.viewport, add_menu=lambda _: menu))
    assert [a.text() for a in menu.actions() if not a.isSeparator()] == [
        "Export 3D CAD", "Export 3D CAD (Selected Geometry)", "Import 3D CAD", "About…"
    ]
    window._tool_actions["guide_point"].trigger()
    guide = window._tools["guide_point"]
    assert guide.on_value(window.viewport, (1, 2, 3))
    guide.on_click(SimpleNamespace(viewport=window.viewport, world=QVector3D(4, 5, 6)))
    assert window.viewport.history.undo()
    assert window.viewport.history.redo()
    dxf = folder / "points.dxf"
    ns["export"](window.viewport.scene, str(dxf))
    positions = {tuple(p.dxf.location) for p in ezdxf.readfile(dxf).modelspace().query("POINT")}
    assert positions == {(1, 2, 3), (4, 5, 6)}, positions

    rid, filename, _ = ns["_blackfox_platform"]()
    package = args.archive or folder / "test.zip"
    if args.archive is None:
        with ZipFile(package, "w") as archive:
            archive.write(args.converter.resolve(), filename)
            for member in ns["CONVERTER_MEMBERS"]:
                archive.writestr(member, "local test fixture")
    data = package.read_bytes()
    def use_version(version):
        manifest = json.dumps({"schema": 1, "repository": ns["CONVERTER_REPOSITORY"],
            "abi": 2, "version": version, "assets": {
                rid: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}).encode()
        ns["RELEASE_MANIFEST"] = manifest
        ns["RELEASE_MANIFEST_SHA256"] = hashlib.sha256(manifest).hexdigest()

    use_version("1.1.0")
    with patch.dict(ns, {"_confirm_converter_download": lambda *args: False,
                         "_download_archive": lambda *args: (_ for _ in ()).throw(AssertionError("download without consent"))}):
        assert ns["get_converter"](window, require_import=True) is None
    real_pin = ns["RELEASE_MANIFEST_SHA256"]
    ns["RELEASE_MANIFEST_SHA256"] = "0" * 64
    try:
        ns["get_converter"](window, require_import=True)
    except RuntimeError as error:
        assert "manifest" in str(error).lower()
    else:
        raise AssertionError("Converter accepted corrupt manifest metadata")
    ns["RELEASE_MANIFEST_SHA256"] = real_pin
    times = []
    def download(url, destination, size):
        assert len(data) == size
        times.append(url)
        shutil.copyfile(package, destination)
    with patch.dict(ns, {"_confirm_converter_download": lambda *args: True,
                         "_download_archive": download}):
        converter = ns["get_converter"](window, require_import=True)
        assert "extension-data" in converter.parts
        assert ns["get_converter"](window, require_import=True) == converter and len(times) == 1
        converter.write_bytes(b"changed")
        assert ns["get_converter"](window, require_import=True) == converter and len(times) == 1
        use_version("1.1.1")
        updated = ns["get_converter"](window, require_import=True)
        assert updated != converter and converter.exists() and len(times) == 2
    use_version("1.1.2")
    with patch.dict(ns, {
        "_confirm_converter_download": lambda *args: True,
        "_download_archive": lambda url, destination, size: destination.write_bytes(b"incomplete"),
    }):
        try:
            ns["get_converter"](window, require_import=True)
        except RuntimeError as error:
            assert "verification" in str(error)
        else:
            raise AssertionError("Converter accepted an incomplete download")
    assert updated.is_file()
    assert not tuple((updated.parents[1].parent / "1.1.2" / rid).iterdir())
    use_version("1.1.1")
    dwg = folder / "points.dwg"
    ns["_export_dwg"](window.viewport.scene, dwg, False, None, "R2018", window)
    window._new_document(activate=True)
    window._dxf_options = lambda *args: (1.0, False)
    proxy = SimpleNamespace(window=window, viewport=window.viewport)
    with patch.object(ns["QFileDialog"], "getOpenFileName", return_value=(str(dwg), "")), \
         patch.object(ns["QMessageBox"], "warning"), \
         patch.object(ns["QMessageBox"], "critical", side_effect=AssertionError) as failure:
        ns["_import_cad"](proxy)
    assert not failure.called
    restored = folder / "restored.dxf"
    ns["export"](window.viewport.scene, str(restored))
    assert {tuple(p.dxf.location) for p in ezdxf.readfile(restored).modelspace().query("POINT")} == positions
    assert window.viewport.history.undo()
    assert window.viewport.history.redo()
    def import_file(path):
        with patch.object(ns["QFileDialog"], "getOpenFileName", return_value=(str(path), "")), \
             patch.object(ns["QMessageBox"], "warning"), \
             patch.object(ns["QMessageBox"], "critical") as failed:
            menu.actions()[2].trigger()
        assert not failed.called, failed.call_args

    import_file(dxf)
    restored = folder / "restored-after-repeat.dxf"
    ns["export"](window.viewport.scene, str(restored))
    assert len(ezdxf.readfile(restored).modelspace().query("POINT")) == 4

    drawing = ezdxf.new("R2018")
    drawing.units = 6
    drawing.layers.new("structure", dxfattribs={"color": 3})
    prototype = drawing.blocks.new("Part")
    prototype.add_line((0, 0, 0), (2, 0, 0))
    drawing.modelspace().add_blockref("Part", (5, 0, 0), dxfattribs={"layer": "structure"})
    drawing.modelspace().add_blockref("Part", (10, 0, 0), dxfattribs={"layer": "structure", "xscale": -1})
    structure = folder / "structure.dxf"
    drawing.saveas(structure)
    import_file(structure)
    groups = [g for g in window.viewport.scene.groups if g.name == "Part"]
    assert len(groups) == 2, [(g.name, g.layer) for g in window.viewport.scene.groups]
    assert groups[0].mesh is groups[1].mesh
    assert groups[0].xform.column(3).x() == 5
    assert groups[1].xform.column(3).x() == 10
    assert groups[1].xform.column(0).x() == -1

    assert all(g.layer == "structure" for g in groups)
    assert window.viewport.scene.layer("structure").color == (0.0, 1.0, 0.0)
    native = folder / "roundtrip.igz"
    window._do_save(native)
    assert native.is_file()
    window._new_document(activate=True)
    assert window._open_path_here(native, ".igz")
    reopened = [g for g in window.viewport.scene.groups if g.name == "Part"]
    assert len(reopened) == 2 and reopened[0].mesh is reopened[1].mesh

    assembly = drawing.blocks.new("Assembly")
    assembly.add_blockref("Part", (2, 3, 4), dxfattribs={"layer": "structure", "rotation": 30})
    drawing.modelspace().add_blockref("Assembly", (20, 0, 0))
    drawing.modelspace().add_blockref("Assembly", (40, 0, 0), dxfattribs={"xscale": -2, "yscale": 3})
    nested = folder / "assembly.dxf"
    drawing.modelspace().add_blockref("Part", (2, 3, 4), dxfattribs={
        "rotation": 15, "xscale": 2, "yscale": 3, "zscale": 0.5, "extrusion": (0, 1, 1),
        "layer": "structure",
    })
    drawing.saveas(nested)
    import_file(nested)
    roots = [g for g in window.viewport.scene.groups if g.name == "Assembly"]
    assert len(roots) == 2, [(g.name, g.layer) for g in window.viewport.scene.groups]
    assert roots[0].mesh is roots[1].mesh
    assert roots[0].children[0].mesh is roots[1].children[0].mesh
    origin = roots[0].children[0].xform.column(3)
    assert (origin.x(), origin.y(), origin.z(), origin.w()) == (2, 3, 4, 1)
    nested_out = folder / "assembly-roundtrip.dxf"
    ns["export"](window.viewport.scene, str(nested_out))
    exported = ezdxf.readfile(nested_out)
    root_refs = [e for e in exported.modelspace().query("INSERT") if e.dxf.insert.x in (20, 40)]
    assert len(root_refs) == 2 and root_refs[0].dxf.name == root_refs[1].dxf.name
    child_ref = exported.blocks[root_refs[0].dxf.name].query("INSERT").first
    assert child_ref.dxf.insert.isclose((2, 3, 4))
    assert abs(child_ref.dxf.rotation - 30) < 1e-4

    tilted_source = list(drawing.modelspace().query("INSERT"))[-1].matrix44()
    tilted = [entity for entity in exported.modelspace().query("INSERT")
              if abs(entity.dxf.extrusion.y) > 0.1]
    assert len(tilted) == 1
    for original, actual in zip(tilted_source.rows(), tilted[0].matrix44().rows()):
        assert all(abs(a - b) < 1e-5 for a, b in zip(original, actual)), (original, actual)

    mesh_folder = folder / "meshes"
    mesh_folder.mkdir()
    if args.mesh_fixtures:
        mesh_files = runpy.run_path(str(args.mesh_fixtures))["exchange_fixtures"](mesh_folder)
    else:
        obj = mesh_folder / "triangle.obj"
        obj.write_text("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n")
        mesh_files = (obj,)
    for mesh_file in mesh_files:
        before = len(window.viewport.scene.groups)
        import_file(mesh_file)
        assert len(window.viewport.scene.groups) > before, mesh_file.suffix
    binary_dxf = folder / "binary-points.dxf"
    subprocess.run([args.converter.resolve(), "convert", "--binary-dxf", dxf, binary_dxf],
                   check=True, capture_output=True)
    before = len(window.viewport.scene.guides)
    import_file(binary_dxf)
    assert len(window.viewport.scene.guides) == before + 2

    units_test = folder / "millimetres.dxf"
    drawing_mm = ezdxf.new("R2018")
    drawing_mm.units = 4
    drawing_mm.modelspace().add_line((0, 0, 0), (2000, 0, 0))
    drawing_mm.saveas(units_test)
    window._dxf_options = lambda *args: (None, False)
    import_file(units_test)
    unit_group = next(g for g in window.viewport.scene.groups if g.name == "millimetres")
    edge = next(iter(unit_group.mesh.edges))
    assert abs((edge.v0.position - edge.v1.position).length() - 2.0) < 1e-6
    broken = folder / "broken.dwg"
    broken.write_bytes(b"AC1032")
    with patch.object(ns["QFileDialog"], "getOpenFileName", return_value=(str(broken), "")), \
         patch.object(ns["QMessageBox"], "critical") as failed:
        before = window.viewport.scene.content_version
        ns["_import_cad"](proxy)
        assert failed.called and window.viewport.scene.content_version == before
    print(engine(), "DXF and DWG round-trip, native Points, repeated import, mirrored and tilted nested instances, DXF units, mesh imports, save/reopen, undo/redo, error handling, consent, cache, and updates PASS", flush=True)
