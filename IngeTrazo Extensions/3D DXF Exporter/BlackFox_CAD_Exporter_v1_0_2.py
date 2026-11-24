# SPDX-License-Identifier: GPL-3.0-or-later
"""BlackFox 3D CAD Exporter — IngeTrazo plugin, version 1.0.2.
Install as a .py file in Extensions > Open plugins folder; restart IngeTrazo.
Uses the verified native BlackFox converter for import and export.
"""
from __future__ import annotations

import traceback
import math
from collections import Counter, defaultdict
from PySide6.QtWidgets import QFileDialog, QMessageBox, QDialog, QVBoxLayout, QDialogButtonBox, QCheckBox, QLabel, QPushButton, QHBoxLayout, QWidget, QComboBox, QGroupBox
from PySide6.QtCore import QSettings


# BlackFox DWG: consent-based, SHA-256 verified Rust converter installer.
import hashlib
import os
import io
import json
import re
import sys
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

CONVERTER_REPOSITORY = "davidsmavrov-debug/blackfox-dwg-converter"
MAX_ARCHIVE = 128 * 1024 * 1024
# Set together by the release packaging script from the approved build artifacts.
RELEASE_MANIFEST = b'{"abi":3,"assets":{"aarch64-apple-darwin":{"sha256":"59c4ba2cfa4ea8bfd24e980931b547a18e7f465df9e4c349b88daa20d5cde714","size":3840756},"aarch64-pc-windows-msvc":{"sha256":"49536164e0945fa452fdbdae1e49142015f3572c60500426c6ba54c65c7fe32c","size":3907971},"aarch64-unknown-linux-gnu":{"sha256":"c6af97f21472d3d90716f3d06f9b62326ea0b138915d7ac2723ba91037355446","size":3889973},"x86_64-apple-darwin":{"sha256":"fe21711f7c9ca38d45b7549fd3429e4ed24095300e3060205d8aad842f248607","size":4145852},"x86_64-pc-windows-msvc":{"sha256":"e5e97d2f29fbb5e33033c32a353008aea3bce813923f2bc4dd1be28673e72a50","size":4378960},"x86_64-unknown-linux-gnu":{"sha256":"dafde4c495202dbe15fb5063dbde3722e6087f598f4d0f0382afd8b136951058","size":4200094}},"repository":"davidsmavrov-debug/blackfox-dwg-converter","schema":1,"version":"1.2.6"}'
RELEASE_MANIFEST_SHA256 = '3795a61d02b1f21c889748c687f90b7f859d4e473999eaf95be87f4fb224ede1'

CONVERTER_MEMBERS = ("LICENSE_AcadRust.txt", "THIRD_PARTY_NOTICES.md")


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_BLACKFOX_ARCH_NAMES = {
    "amd64": "x86_64", "x86_64": "x86_64",
    "arm64": "aarch64", "aarch64": "aarch64",
}
_BLACKFOX_SYSTEMS = {
    "win32": ("pc-windows-msvc", "BlackFoxDWG.exe"),
    "linux": ("unknown-linux-gnu", "BlackFoxDWG"),
    "darwin": ("apple-darwin", "BlackFoxDWG"),
}
_BLACKFOX_PE_MACHINES = {0x8664: "x86_64", 0xAA64: "aarch64"}


def _blackfox_native_machine(system):
    import ctypes
    import platform

    if system == "win32":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        native_query = getattr(kernel, "IsWow64Process2", None)
        if native_query is not None:
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            native_query.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort),
                ctypes.POINTER(ctypes.c_ushort),
            ]
            native_query.restype = ctypes.c_int
            process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
            if not native_query(kernel.GetCurrentProcess(), ctypes.byref(process_machine),
                                ctypes.byref(native_machine)):
                raise OSError(f"Cannot detect native Windows architecture (error {ctypes.get_last_error()}).")
            return _BLACKFOX_PE_MACHINES.get(native_machine.value, hex(native_machine.value))
    elif system == "darwin":
        import errno

        libc = ctypes.CDLL(None, use_errno=True)
        query = libc.sysctlbyname
        query.argtypes = [
            ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        query.restype = ctypes.c_int
        arm = ctypes.c_int()
        size = ctypes.c_size_t(ctypes.sizeof(arm))
        if query(b"hw.optional.arm64", ctypes.byref(arm), ctypes.byref(size), None, 0) == 0:
            if arm.value:
                return "aarch64"  # Also applies to an x86-64 process under Rosetta.
        elif ctypes.get_errno() != errno.ENOENT:
            raise OSError(f"Cannot detect native macOS architecture (error {ctypes.get_errno()}).")
    return platform.machine()


def _blackfox_platform(system=None, machine=None):
    system = sys.platform if system is None else system
    if system not in _BLACKFOX_SYSTEMS:
        raise RuntimeError(f"BlackFox CAD does not support operating system {system!r}.")
    machine = _blackfox_native_machine(system) if machine is None else machine
    arch = _BLACKFOX_ARCH_NAMES.get(machine.lower())
    if arch is None:
        raise RuntimeError(f"BlackFox CAD does not support CPU architecture {machine!r} on {system}.")
    suffix, name = _BLACKFOX_SYSTEMS[system]
    return f"{arch}-{suffix}", name, arch


def _blackfox_binary_architecture(path, system):
    """Inspect a native executable header without running the file."""
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) < 64:
            return None
        if system == "win32" and header[:2] == b"MZ":
            offset = int.from_bytes(header[60:64], "little")
            if offset < 64:
                return None
            stream.seek(offset)
            pe = stream.read(26)
            if (len(pe) == 26 and pe[:4] == b"PE\0\0"
                    and pe[24:26] == b"\x0b\x02"):
                flags = int.from_bytes(pe[22:24], "little")
                if flags & 0x0002 and not flags & 0x2000:  # Executable, not DLL.
                    return _BLACKFOX_PE_MACHINES.get(int.from_bytes(pe[4:6], "little"))
        elif system == "linux" and header[:6] == b"\x7fELF\x02\x01":
            kind = int.from_bytes(header[16:18], "little")
            if kind in (2, 3):  # ET_EXEC or position-independent ET_DYN.
                return {62: "x86_64", 183: "aarch64"}.get(int.from_bytes(header[18:20], "little"))
        elif system == "darwin" and header[:4] == b"\xcf\xfa\xed\xfe":
            if int.from_bytes(header[12:16], "little") == 2:  # MH_EXECUTE.
                return {0x01000007: "x86_64", 0x0100000C: "aarch64"}.get(
                    int.from_bytes(header[4:8], "little"))
    return None


def _release_metadata(rid):
    if hashlib.sha256(RELEASE_MANIFEST).hexdigest() != RELEASE_MANIFEST_SHA256:
        raise RuntimeError("BlackFox CAD release manifest failed SHA-256 verification.")
    manifest = json.loads(RELEASE_MANIFEST)
    version = manifest["version"]
    if (manifest["schema"] != 1 or manifest["repository"] != CONVERTER_REPOSITORY
            or manifest["abi"] != 3
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)):
        raise RuntimeError("Invalid BlackFox CAD release manifest.")
    asset = manifest["assets"].get(rid)
    if asset is None:
        raise RuntimeError(f"The BlackFox CAD converter is not available for {rid}.")
    size, digest = asset["size"], asset["sha256"]
    if (type(size) is not int or not 0 < size <= MAX_ARCHIVE
            or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise RuntimeError("Invalid BlackFox CAD release asset metadata.")
    return version, size, digest


def _verified_archive(path, size, digest):
    return (path.is_file() and path.stat().st_size == size
            and _sha256_file(path) == digest)


def _confirm_converter_download(parent, url, rid, size):
    message = QMessageBox(parent)
    message.setIcon(QMessageBox.Question)
    message.setWindowTitle("BlackFox DWG Converter — download permission")
    message.setText("This operation requires the BlackFox DWG converter.")
    message.setInformativeText(
        f"Platform: {rid}\nDownload size: {size / (1024 * 1024):.2f} MiB\n"
        f"Source: {url}\n\nChoose Download to allow the download. "
        "The converter will be verified and saved for future use."
    )
    download = message.addButton("Download", QMessageBox.AcceptRole)
    message.addButton("Cancel", QMessageBox.RejectRole)
    message.exec()
    return message.clickedButton() is download


def _download_archive(url, destination, size):
    from core.tls import https_context
    from urllib.parse import urlsplit

    class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            target = urlsplit(newurl)
            if (target.scheme != "https" or target.netloc not in
                    {"github.com", "release-assets.githubusercontent.com",
                     "objects.githubusercontent.com"}):
                raise RuntimeError("Unexpected converter download redirect.")
            return super().redirect_request(request, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=https_context()), ReleaseRedirect(),
    )
    request = urllib.request.Request(url, headers={"User-Agent": "BlackFox-CAD-Exporter/1.0.2"})
    with opener.open(request, timeout=60) as response, destination.open("wb") as output:
        remaining = size
        while remaining:
            chunk = response.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError("Incomplete BlackFox CAD converter download.")
            output.write(chunk)
            remaining -= len(chunk)
        if response.read(1):
            raise RuntimeError("BlackFox CAD converter download exceeds its expected size.")
        output.flush()
        os.fsync(output.fileno())


def _archive_members(path, filename, size, digest):
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("BlackFox CAD converter archive changed before extraction.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if (len(members) != 3 or {info.filename for info in members} != {filename, *CONVERTER_MEMBERS}
                or any(not 0 < info.file_size <= MAX_ARCHIVE for info in members)):
            raise RuntimeError("Unexpected BlackFox CAD converter archive contents.")
        return {info.filename: archive.read(info) for info in members}


def _atomic_write(destination, data, mode=0o644, validate=None):
    fd, name = tempfile.mkstemp(prefix=".blackfox_install_", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        if validate is not None:
            validate(temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def get_converter(parent=None):
    """Resolve and validate the converter before each execution."""
    from core.extensions import user_plugins_dir

    rid, filename, arch = _blackfox_platform()
    version, size, digest = _release_metadata(rid)
    archive_name = f"blackfox-dwg-{rid}.zip"
    user_data = user_plugins_dir().parent.resolve()
    directory = user_data / "extension-data" / "blackfox_cad_exporter" / "bin" / version / rid
    if directory.resolve() != directory:
        raise RuntimeError("The BlackFox CAD converter directory contains a redirect.")
    archive_path = directory / archive_name
    executable = directory / filename
    if not _verified_archive(archive_path, size, digest):
        legacy = Path(__file__).resolve().parent / "BlackFoxDWG" / f"v{version}" / rid / archive_name
        if _verified_archive(legacy, size, digest):
            data = legacy.read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError("The BlackFox CAD converter archive changed during migration.")
            directory.mkdir(parents=True, exist_ok=True)
            _atomic_write(archive_path, data)
        else:
            url = f"https://github.com/{CONVERTER_REPOSITORY}/releases/download/v{version}/{archive_name}"
            if not _confirm_converter_download(parent, url, rid, size):
                return None
            directory.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=".blackfox_download_", suffix=".zip", dir=directory)
            os.close(fd)
            temporary = Path(name)
            try:
                _download_archive(url, temporary, size)
                if not _verified_archive(temporary, size, digest):
                    raise RuntimeError("BlackFox CAD converter archive failed size or SHA-256 verification.")
                os.replace(temporary, archive_path)
            finally:
                temporary.unlink(missing_ok=True)

    def validate_executable(path):
        if _blackfox_binary_architecture(path, sys.platform) != arch:
            raise RuntimeError("BlackFox CAD converter executable does not match the native architecture.")

    members = _archive_members(archive_path, filename, size, digest)
    for member in (*CONVERTER_MEMBERS, filename):
        destination = directory / member
        data = members[member]
        if (destination.is_symlink() or not destination.is_file()
                or destination.stat().st_size != len(data)
                or _sha256_file(destination) != hashlib.sha256(data).hexdigest()):
            if member == filename:
                _atomic_write(destination, data, 0o755, validate_executable)
            else:
                _atomic_write(destination, data)
    validate_executable(executable)
    if sys.platform != "win32" and not os.access(executable, os.X_OK):
        executable.chmod(0o755)
    return executable


def xyz(v):
    p = getattr(v, "position", v)
    if callable(p):
        p = p()
    if all(hasattr(p, a) for a in ("x", "y", "z")):
        return (float(p.x()), float(p.y()), float(p.z()))
    return tuple(float(x) for x in p[:3])


def _rgb(value):
    """Convert a Qt QColor, #RRGGBB, or RGB triplet to 24-bit true color."""
    if value is None:
        return None
    if callable(value):
        try:
            value = value()
        except (TypeError, ValueError):
            return None
    if hasattr(value, "getRgb"):
        r, g, b = value.getRgb()[:3]
    elif hasattr(value, "red") and hasattr(value, "green") and hasattr(value, "blue"):
        r, g, b = value.red(), value.green(), value.blue()
        r, g, b = (v() if callable(v) else v for v in (r, g, b))
    elif isinstance(value, str):
        value = value.strip()
        if len(value) == 7 and value.startswith("#"):
            try:
                return int(value[1:], 16)
            except ValueError:
                return None
        return None
    elif isinstance(value, (tuple, list)) and len(value) >= 3:
        r, g, b = value[:3]
        if all(isinstance(v, (int, float)) and 0 <= v <= 1 for v in (r, g, b)):
            r, g, b = (round(v * 255) for v in (r, g, b))
    else:
        return None
    try:
        r, g, b = (int(v) for v in (r, g, b))
    except (TypeError, ValueError):
        return None
    if not all(0 <= v <= 255 for v in (r, g, b)):
        return None
    return (r << 16) | (g << 8) | b


def face_loops(face):
    outer = list(getattr(face, "loop", []) or [])
    holes = [list(h) for h in (getattr(face, "hole_loops", []) or [])]
    return [outer] + holes


def _curve_key(edge):
    for attr in ("curve_id", "curve"):
        value = getattr(edge, attr, None)
        if value is not None and not callable(value):
            try:
                hash(value)
                return value
            except TypeError:
                pass
    return None


def _curve_polylines(segments):
    """Walk each connected unbranched curve as an ordered polyline."""
    adjacency = defaultdict(list)
    for i, (a, b) in enumerate(segments):
        adjacency[a].append(i)
        adjacency[b].append(i)
    unused = set(range(len(segments)))
    while unused:
        first = next(iter(unused))
        component = {first}
        stack = [first]
        while stack:
            k = stack.pop()
            for point in segments[k]:
                for neighbor in adjacency[point]:
                    if neighbor not in component:
                        component.add(neighbor)
                        stack.append(neighbor)
        ends = [point for point in {p for k in component for p in segments[k]} if sum(i in component for i in adjacency[point]) == 1]
        if any(sum(i in component for i in adjacency[point]) > 2 for point in adjacency):
            raise ValueError("Branching curve cannot be exported as a single polyline")
        current = ends[0] if ends else segments[first][0]
        points = [current]
        remaining = set(component)
        while remaining:
            candidates = [i for i in adjacency[current] if i in remaining]
            if not candidates:
                raise ValueError("Disconnected curve chain")
            i = candidates[0]
            remaining.remove(i)
            a, b = segments[i]
            current = b if a == current else a
            points.append(current)
        closed = len(points) > 2 and points[0] == points[-1]
        if closed:
            points.pop()
        if len(points) < 2:
            raise ValueError("Degenerate curve")
        yield points, closed
        unused -= component


def placement_matrix(raw):
    """Normalize Qt matrices and legacy column-major flat arrays to rows."""
    if raw is None:
        return None
    if hasattr(raw, "copyDataTo"):
        values = list(raw.copyDataTo())
        return [[float(values[r * 4 + c]) for c in range(4)] for r in range(4)]
    if hasattr(raw, "tolist"):
        raw = raw.tolist()
    if len(raw) == 4 and all(hasattr(row, "__len__") and len(row) == 4 for row in raw):
        return [[float(v) for v in row] for row in raw]
    if len(raw) == 16:
        # Legacy raw flat arrays use OpenGL column order.
        return [[float(raw[c * 4 + r]) for c in range(4)] for r in range(4)]
    raise ValueError("Unrecognized component placement matrix")


def _selected_geometry(scene):
    """Resolve selected scene objects without changing the scene or mesh data.

    Unsupported selection representations fail closed: never export the whole
    model by accident when Selected Geometry was requested.
    """
    from types import SimpleNamespace

    selection = list(getattr(scene, "selection", []) or [])
    if not selection:
        raise ValueError("Nothing selected. Select geometry before exporting.")

    loose = scene.loose_mesh
    faces = list(getattr(loose, "faces", []) or [])
    edges = list(getattr(loose, "edges", []) or [])
    groups = list(getattr(scene, "groups", []) or [])
    guides = list(getattr(scene, "guides", []) or [])
    # GeoPoints are not individually selectable in the current IngeTrazo UI.

    def candidates(item):
        # Common selection wrappers may hold the actual geometry object.
        result = [item]
        for key in ("object", "entity", "item", "target", "ref", "face",
                    "edge", "group", "guide"):
            try:
                obj = getattr(item, key, None)
            except Exception:
                obj = None
            if obj is not None and not callable(obj):
                result.append(obj)
        if isinstance(item, (tuple, list)):
            result.extend(item)
        return result

    selected_ids = {id(obj) for item in selection for obj in candidates(item)}
    chosen_faces = [f for f in faces if id(f) in selected_ids]
    chosen_edges = [e for e in edges if id(e) in selected_ids]
    chosen_groups = [g for g in groups if id(g) in selected_ids]
    chosen_guides = [g for g in guides if id(g) in selected_ids]

    # Selected faces need their boundary edges, including shared ones.
    face_ids = {id(f) for f in chosen_faces}
    for edge in edges:
        if id(edge) in selected_ids or any(
            id(face) in face_ids for face in (getattr(edge, "faces", None) or [])
        ):
            if all(id(edge) != id(e) for e in chosen_edges):
                chosen_edges.append(edge)

    if not (chosen_faces or chosen_edges or chosen_groups or chosen_guides):
        kinds = ", ".join(sorted({type(x).__name__ for x in selection}))
        raise ValueError(
            "Selection type not yet recognized (" + kinds + "). "
            "No file was exported. Run the inspector with selected objects "
            "so we can support this representation safely."
        )

    return (SimpleNamespace(faces=chosen_faces, edges=chosen_edges),
            chosen_groups, chosen_guides)


def _cad_definition_key(group):
    return id(group.mesh), tuple(
        (_cad_definition_key(child), child.layer,
         tuple(tuple(row) for row in placement_matrix(child.xform)) if child.xform is not None else None)
        for child in group.children
    )


DXF_VERSIONS = ("R12", "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018")

_OPTION_FIELDS = (("faces", "Faces"), ("edges", "Edges"),
                  ("text", "Text"), ("annotations", "Annotations (Dimensions)"),
                   ("survey_points", "Survey Points"))


def _settings():
    # Dedicated namespace: does not interfere with IngeTrazo's own preferences.
    return QSettings("Mavrov Industries", "BlackFox 3D CAD Exporter")


def _saved_export_options():
    settings = _settings()
    return {key: str(settings.value("export/" + key, "true")).lower() in
            ("true", "1", "yes") for key, _ in _OPTION_FIELDS}


DWG_VERSIONS = DXF_VERSIONS


def _export_options_dialog(parent, state):
    """Edit pending settings; nothing persists until the Save dialog succeeds."""
    dialog = QDialog(parent)
    dialog.setWindowTitle("3D CAD Export Options")
    layout = QVBoxLayout(dialog)

    version_group = QGroupBox("AutoCAD version", dialog)
    version_layout = QVBoxLayout(version_group)
    version_box = QComboBox(version_group)
    version_layout.addWidget(version_box)
    layout.addWidget(version_group)

    export_group = QGroupBox("Export", dialog)
    export_layout = QVBoxLayout(export_group)
    checks = {}
    for key, title in _OPTION_FIELDS:
        cb = QCheckBox(title, export_group)
        cb.setChecked(state["filters"][key])
        export_layout.addWidget(cb)
        checks[key] = cb
    layout.addWidget(export_group)

    versions = DXF_VERSIONS if state["format"] == "dxf" else DWG_VERSIONS
    for version in reversed(versions):
        version_box.addItem(version, version)
    current = state["versions"][state["format"]]
    index = version_box.findData(current)
    version_box.setCurrentIndex(index if index >= 0 else version_box.findData("R2018"))

    # R12 does not support our text and annotation export path.
    def update_r12_options(_index=None):
        is_r12 = version_box.currentData() == "R12"
        for key in ("text", "annotations"):
            checks[key].setEnabled(not is_r12)
            if is_r12:
                checks[key].setChecked(False)
            else:
                checks[key].setChecked(state["filters"][key])

    version_box.currentIndexChanged.connect(update_r12_options)
    update_r12_options()
    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=dialog)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    if dialog.exec() != QDialog.Accepted:
        return
    state["versions"][state["format"]] = version_box.currentData()
    for key, checkbox in checks.items():
        if not (version_box.currentData() == "R12"
                and key in ("text", "annotations")):
            state["filters"][key] = checkbox.isChecked()


def _save_dialog_with_options(parent):
    """Unified format picker; returns (filename, format, version, filters)."""
    from pathlib import Path

    settings = _settings()
    state = {
        "format": str(settings.value("export/format", "dxf")),
        "versions": {
            "dxf": str(settings.value("export/dxf_version", "R2010")),
            "dwg": str(settings.value("export/dwg_version", "R2018")),
        },
        "filters": _saved_export_options(),
    }
    if state["format"] not in ("dxf", "dwg"):
        state["format"] = "dxf"
    file_filters = "AutoCAD DXF (*.dxf);;AutoCAD DWG (*.dwg)"
    dialog = QFileDialog(parent, "Export 3D CAD", "", file_filters)
    dialog.setAcceptMode(QFileDialog.AcceptSave)
    dialog.setOption(QFileDialog.DontUseNativeDialog, True)
    dialog.selectNameFilter("AutoCAD DWG (*.dwg)" if state["format"] == "dwg"
                            else "AutoCAD DXF (*.dxf)")
    dialog.setDefaultSuffix(state["format"])

    def on_format_changed(selected_filter):
        state["format"] = "dwg" if "*.dwg" in selected_filter else "dxf"
        dialog.setDefaultSuffix(state["format"])

    dialog.filterSelected.connect(on_format_changed)
    options_button = QPushButton("Options…", dialog)
    options_button.clicked.connect(lambda: _export_options_dialog(dialog, state))
    button_box = dialog.findChild(QDialogButtonBox)
    if button_box is not None:
        button_box.addButton(options_button, QDialogButtonBox.ActionRole)
    else:
        dialog.layout().addWidget(options_button)

    if dialog.exec() != QDialog.Accepted:
        return None
    names = dialog.selectedFiles()
    if not names:
        return None
    filename = names[0]
    # Respect the selected file type, even when the user typed another extension.
    suffix = "." + state["format"]
    if Path(filename).suffix.lower() in (".dxf", ".dwg"):
        filename = str(Path(filename).with_suffix(suffix))
    elif not filename.lower().endswith(suffix):
        filename += suffix

    # Save choices only after the file picker is accepted.
    if state["format"] in ("dxf", "dwg"):
        settings.setValue("export/format", state["format"])
        settings.setValue("export/dxf_version", state["versions"]["dxf"])
        settings.setValue("export/dwg_version", state["versions"]["dwg"])
        for key, value in state["filters"].items():
            settings.setValue("export/" + key, value)
        settings.sync()
    return filename, state["format"], state["versions"][state["format"]], dict(state["filters"])


class Export3DDXF:
    selected_only = False
    name = "Export 3D CAD"
    shortcut = None
    description = "Export the active model to DXF or DWG."
    uses_snap = False

    def on_activate(self, viewport):
        selection = _save_dialog_with_options(viewport.window())
        if not selection:
            return
        filename, file_format, dxf_version, options = selection
        try:
            converter = get_converter(viewport.window())
            if converter is None:
                return
            diagnostics = _write_direct_cad(
                converter, viewport.scene, filename, dxf_version,
                selected_only=self.selected_only, options=options,
            )
            _report_direct_import(viewport.window(), Path(filename), {}, diagnostics,
                                  operation="Export")
            QMessageBox.information(viewport.window(), "Export 3D CAD",
                                    f"Saved {file_format.upper()} ({dxf_version}):\n{filename}")
        except Exception as exc:
            QMessageBox.critical(
                viewport.window(), "Export 3D CAD — failed",
                f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()[-3500:]}"
            )

    def on_deactivate(self, viewport):
        pass


class ExportSelected3DDXF(Export3DDXF):
    name = "Export 3D CAD (Selected Geometry)"
    description = "Export only selected geometry to DXF or DWG."
    selected_only = True


_DIRECT_POSITION_FIELDS = {
    "line": ("start", "end"), "point": ("position",), "guide_line": ("position",),
    "text": ("position",), "aligned_dimension": ("start", "end", "dimension_line"),
    "leader": ("anchor", "label_position"),
}
_DIRECT_VERTEX_FIELDS = {"polyline": "vertices", "face": "corners", "mesh": "vertices", "brep_mesh": "vertices"}


def _direct_bounds(drawing):
    from formats.recenter import Bounds

    bounds = Bounds()
    for record in drawing["entities"]:
        kind = record["kind"]
        for key in _DIRECT_POSITION_FIELDS.get(kind, ()):
            bounds.add(*record[key])
        key = _DIRECT_VERTEX_FIELDS.get(kind)
        if key:
            for point in record[key]:
                bounds.add(*point)
        if kind == "instance":
            bounds.add(*(row[3] for row in record["transform"][:3]))
    return bounds


def _recenter_direct_drawing(drawing, scale, bounds):
    from formats.recenter import survey_offset

    offset = survey_offset([value * scale for value in bounds.lo],
                           [value * scale for value in bounds.hi])
    # Also protect a small drawing far from its origin when units are changed
    # in the dialog. Test its original coordinates before narrowing to float32.
    if offset is None and bounds.offset() is not None:
        offset = tuple(value * scale for value in bounds.offset())
    if offset is None:
        return drawing, None
    shift = tuple(value / scale for value in offset)

    def move(position):
        return [value - delta for value, delta in zip(position, shift)]

    entities = []
    for original in drawing["entities"]:
        record = original.copy()
        kind = record["kind"]
        for key in _DIRECT_POSITION_FIELDS.get(kind, ()):
            record[key] = move(record[key])
        key = _DIRECT_VERTEX_FIELDS.get(kind)
        if key:
            record[key] = [move(vertex) for vertex in record[key]]
        if kind == "instance":
            rows = [row.copy() for row in record["transform"]]
            for index, delta in enumerate(shift):
                rows[index][3] -= delta
            record["transform"] = rows
        entities.append(record)
    return {**drawing, "entities": entities}, offset


def _load_direct_model(scene, drawing, scale):
    """Map the Rust exchange records into editable native objects."""
    from PySide6.QtGui import QVector3D
    from core.dimension import Dimension
    from core.group import Group
    from core.guide import Guide
    from core.layers import Layer
    from core.textlabel import TextLabel

    if drawing["schema"] != 1 or not math.isfinite(scale) or scale <= 0:
        raise ValueError("Invalid BlackFox CAD exchange schema or unit scale.")
    groups = {}
    approximations = Counter()

    def point(position):
        if len(position) != 3 or not all(math.isfinite(value) for value in position):
            raise ValueError("Invalid point in BlackFox CAD exchange.")
        return QVector3D(*(coordinate * scale for coordinate in position))

    layer_properties = drawing.get("layers", {})

    def tag_for(layer):
        if layer in ("", "0"):
            return None
        if scene.layer(layer) is None:
            properties = layer_properties.get(layer, {})
            rgb = properties.get("rgb")
            color = tuple(channel / 255.0 for channel in rgb) if rgb is not None else None
            scene.layers.append(Layer(layer, visible=properties.get("visible", True),
                                      locked=properties.get("locked", False), color=color))
        return layer

    def add_edge(mesh, start, end, tag, curve=None):
        try:
            edge = mesh.add_edge(start, end)
        except ValueError as error:
            if str(error) != "degenerate edge: endpoints weld to one vertex":
                raise
            approximations["Degenerate CAD edges skipped"] += 1
            return
        edge.layer = tag
        edge.curve = curve

    def add_geometry(mesh, record, tag):
        kind = record["kind"]
        if kind == "line":
            add_edge(mesh, point(record["start"]), point(record["end"]), tag)
        elif kind == "polyline":
            vertices = [point(vertex) for vertex in record["vertices"]]
            if len(vertices) < 2:
                return
            curve_id = mesh.next_curve_id()
            if record["closed"]:
                vertices.append(vertices[0])
            for start, end in zip(vertices, vertices[1:]):
                add_edge(mesh, start, end, tag, curve_id)
        elif kind == "face":
            mesh.add_face([point(corner) for corner in record["corners"]])
        elif kind in {"mesh", "brep_mesh"}:
            vertices = [point(vertex) for vertex in record["vertices"]]
            faces = record["faces"]
            holes = record.get("holes", [[]] * len(faces))
            for face, boundaries in zip(faces, holes, strict=True):
                loops = [face, *boundaries]
                if any(len(loop) < 3 or any(not 0 <= vertex < len(vertices) for vertex in loop)
                       for loop in loops):
                    raise ValueError("Invalid mesh topology in BlackFox CAD exchange.")
                outer, *inner = [[vertices[vertex] for vertex in loop] for loop in loops]
                mesh.add_face(outer, inner)
        else:
            raise ValueError(f"Unsupported BlackFox CAD exchange record {kind!r}.")

    blocks = drawing.get("blocks", {})
    prototypes = {}
    omitted = Counter(drawing.get("omitted", {}))

    def instance(record, ancestors):
        from PySide6.QtGui import QMatrix4x4

        name = record["block"]
        if name in ancestors or len(ancestors) >= 128:
            omitted["Cyclic or overly deep block reference"] += 1
            return None
        tag = tag_for(record["layer"])
        definition = blocks[name]
        if name not in prototypes:
            prototype = Group(name=name).mesh
            for child in definition:
                if child["kind"] in {"line", "polyline", "face", "mesh", "brep_mesh"}:
                    add_geometry(prototype, child, tag_for(child["layer"]))
            prototypes[name] = prototype
        group = Group(prototypes[name], name=name)
        group.layer = tag
        rows = [list(row) for row in record["transform"]]
        for row in rows[:3]:
            row[3] *= scale
        group.xform = QMatrix4x4(*(value for row in rows for value in row))
        children = []
        for child in definition:
            if child["kind"] == "instance":
                placed = instance(child, (*ancestors, name))
                if placed is not None:
                    children.append(placed)
            elif child["kind"] not in {"line", "polyline", "face", "mesh", "brep_mesh"}:
                omitted[f"Block-owned {child['kind']}"] += 1
        group.adopt(children)
        return group

    for record in drawing["entities"]:
        kind = record["kind"]
        layer = record["layer"]
        tag = tag_for(layer)
        if kind == "brep_mesh":
            from formats.fuse import soften_smooth_edges
            group = Group(name=tag or "CAD solid or surface")
            group.layer = tag
            add_geometry(group.mesh, record, None)
            soften_smooth_edges(group.mesh)
            scene.groups.append(group)
            continue
        if kind == "instance":
            placed = instance(record, ())
            if placed is not None:
                scene.groups.append(placed)
            continue
        if kind in {"point", "guide_line"}:
            direction = QVector3D(*record["direction"]) if kind == "guide_line" else None
            scene.guides.append(Guide(point(record["position"]), direction=direction, layer=tag))
            continue
        if kind == "aligned_dimension":
            start, end = point(record["start"]), point(record["end"])
            offset = point(record["dimension_line"]) - end
            measurement_axis = record.get("axis")
            axes = {"x": QVector3D(1, 0, 0), "y": QVector3D(0, 1, 0), "z": QVector3D(0, 0, 1)}
            delta = axes[measurement_axis] if measurement_axis else end - start
            if delta.lengthSquared() > 0:
                axis = delta.normalized()
                offset -= axis * QVector3D.dotProduct(offset, axis)
            dimension = Dimension(start, end, offset, layer=tag, text=record["text"] or None,
                                  axis=measurement_axis)
            dimension.bind(scene)
            scene.dimensions.append(dimension)
            continue
        if kind == "leader":
            anchor = point(record["anchor"])
            scene.text_labels.append(TextLabel(
                anchor, point(record["label_position"]) - anchor, record["text"], layer=tag,
            ))
            continue
        if kind == "text":
            scene.text_labels.append(TextLabel(
                point(record["position"]), QVector3D(), record["text"], layer=tag,
            ))
            continue
        if layer not in groups:
            group = Group(name=tag or "CAD geometry")
            group.layer = tag
            groups[layer] = group
        add_geometry(groups[layer].mesh, record, tag)
    scene.groups.extend(groups.values())
    omitted.update(approximations)
    return omitted


def _direct_model_from_scene(scene, *, selected_only=False, options=None):
    """Serialize supported native scene objects in the host's metre units."""
    records = []
    blocks = {}
    definition_names = {}
    options = options or {"faces": True, "edges": True, "annotations": True, "text": True}
    if selected_only:
        loose, groups, guides = _selected_geometry(scene)
    else:
        loose, groups, guides = scene.loose_mesh, scene.groups, scene.guides

    def put(kind, layer, **fields):
        records.append({"kind": kind, "layer": layer or "0", **fields})

    def geometry(mesh, tag):
        local = []
        curves = defaultdict(list)
        for edge in (mesh.edges if options["edges"] else ()):
            if options["faces"] and getattr(edge, "faces", None):
                continue
            layer = edge.layer or tag or "0"
            curve = _curve_key(edge)
            start, end = xyz(edge.v0), xyz(edge.v1)
            if curve is None:
                local.append(dict(kind="line", layer=layer, start=start, end=end))
            else:
                curves[(curve, layer)].append((start, end))
        for (_, layer), segments in curves.items():
            for vertices, closed in _curve_polylines(segments):
                local.append(dict(kind="polyline", layer=layer, vertices=vertices, closed=closed))
        for face in (mesh.faces if options["faces"] else ()):
            corners, *holes = face_loops(face)
            if holes:
                from formats.meshexport import export_triangles
                triangles = list(export_triangles(face))
                if not triangles:
                    raise ValueError("Could not triangulate CAD face with openings.")
                layer = getattr(face, "layer", None) or tag or "0"
                local.extend(dict(kind="face", layer=layer, corners=[xyz(v) for v in triangle])
                             for triangle in triangles)
                continue
            vertices = [xyz(vertex) for vertex in corners]
            if len(vertices) <= 4:
                local.append(dict(kind="face", layer=getattr(face, "layer", None) or tag or "0",
                                  corners=vertices))
            else:
                local.append(dict(kind="mesh", layer=getattr(face, "layer", None) or tag or "0",
                                  vertices=vertices, faces=[list(range(len(vertices)))]))

        return local

    def instance(group):
        key = _cad_definition_key(group)
        name = definition_names.get(key)
        if name is None:
            name = f"BLACKFOX_{len(definition_names) + 1:04d}"
            definition_names[key] = name
            blocks[name] = geometry(group.mesh, None) + [instance(child) for child in group.children]
        transform = placement_matrix(group.xform)
        if transform is None:
            transform = [[float(i == j) for j in range(4)] for i in range(4)]
        return dict(kind="instance", block=name, layer=group.layer or "0", transform=transform)

    records.extend(geometry(loose, None))
    records.extend(instance(group) for group in groups)
    for guide in guides:
        if guide.direction is None:
            put("point", guide.layer, position=xyz(guide.point))
        else:
            put("guide_line", guide.layer, position=xyz(guide.point), direction=xyz(guide.direction))
    for dimension in (scene.dimensions if options["annotations"] and not selected_only else ()):
        put("aligned_dimension", dimension.layer, start=xyz(dimension.a), end=xyz(dimension.b),
            dimension_line=xyz(dimension.b + dimension.offset), text=dimension.text or "",
            axis=dimension.axis)
    for label in (scene.text_labels if options["text"] and not selected_only else ()):
        if label.offset.lengthSquared():
            put("leader", label.layer, anchor=xyz(label.anchor), label_position=xyz(label.position()),
                text=label.text, height=0.2)
        else:
            put("text", label.layer, position=xyz(label.anchor), text=label.text, height=0.2, rotation=0)
    layer_properties = {}
    for layer in scene.layers:
        color = _rgb(layer.color)
        channels = None if color is None else [(color >> shift) & 255 for shift in (16, 8, 0)]
        layer_properties[layer.name] = {
            "visible": layer.visible, "locked": layer.locked, "rgb": channels,
        }
    return {"schema": 1, "units": 6, "entities": records, "blocks": blocks,
            "layers": layer_properties}


def _run_direct_converter(converter, *arguments):
    result = subprocess.run(
        [str(converter), *(str(argument) for argument in arguments)],
        capture_output=True, encoding="utf-8", errors="replace", timeout=180,
        check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        error = details.splitlines()[-1] if details else f"Converter exited with code {result.returncode}"
        raise RuntimeError(error)
    return result.stderr.strip()


def _read_direct_cad(converter, source):
    with tempfile.TemporaryDirectory(prefix="blackfox-cad-decode-") as folder:
        exchange = Path(folder) / "model.json"
        diagnostics = _run_direct_converter(converter, "decode", source, exchange)
        with exchange.open(encoding="utf-8") as stream:
            return json.load(stream), diagnostics


def _write_direct_cad(converter, scene, destination, version, **selection):
    with tempfile.TemporaryDirectory(prefix="blackfox-cad-encode-") as folder:
        exchange = Path(folder) / "model.json"
        payload = _direct_model_from_scene(scene, **selection)
        with exchange.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, allow_nan=False)
        return _run_direct_converter(converter, "encode", exchange, destination, version)


def _report_direct_import(window, source, report, diagnostics, *, operation="Import"):
    if not report and not diagnostics:
        return
    summary = ", ".join(f"{kind} ({count})" for kind, count in sorted(report.items()))
    message = QMessageBox(QMessageBox.Warning, f"{operation} 3D CAD",
                          f"{operation} completed with limitations for {source.name}.", parent=window)
    message.setInformativeText(summary or "The converter returned import diagnostics.")
    if diagnostics:
        message.setDetailedText(diagnostics)
    message.exec()


# BlackFox artwork supplied by the project owner. Embed it for single-file installs.
_PROGRESS_ICON_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAYAAAA+s9J6AAAACXBIWXMAAAsTAAALEwEAmpwYAAABOWlDQ1BQaG90b3Nob3Ag"
    "SUNDIHByb2ZpbGUAAHjarZCxSwJhAEff5yFFBjlcYbUYtDgEYQ1Fg2VgS4NKwykVdF9iodZx95URttXQdrjVFOHY0lJtDU1R"
    "0CA0RP9AQ0NDToENCidBQ9CbHm/5wQ98vUVZcnxBKG0pO70QDxuZbLjrFcEgGhGm16RjzSWTi/xK4xkBUB8rypLD3+hZzzkS"
    "+AJWpWUrEMtAoKwsBWID0M2CpUBUAN02MlkQLqDnW14DdLPlN4BuL6XnQTwCs/kONzu8vQugySj/jsrtKYBEHIxMNvzzK69p"
    "A6BNgK/mte1zmPoEzfWaeQLXRxB68droGfQdwtWT3LF329NDwIO416S/2l0INIKx/tTw5MhHxI2GZqoJf6q88l6w9v3Hl6eV"
    "i83bg/rd23iz+Q3eQVN95kZ9OAAAACBjSFJNAACHCgAAjA0AAP1LAACBPwAAfXYAAOmMAAA85QAAGc2w3/UXAABNHElEQVR4"
    "2uyddXjVV7rv1z1zzz3n3umUEkLcgLgBxV0S4glxd3d3J+4uO57suBFX4oIFCVCsUAq1YSrTTnum06l97x/J3hMgeAJMWHme"
    "z9MnTcj+2ee31nrXu95FABAKhfL6oBeBQqESUihUQgqFQiWkUKiEFAqFSkihUAkpFAqVkEKhElIoFCohhUIlpFAoVEIKhUpI"
    "oVCohBQKlZBCoVAJKRQqIYVCoRJSKFRCCoVCJaRQqIQUCoVKSKFQCSkUCpWQQqESUigUKiGFQiWkUChUQgqFSkihUKiEFAqV"
    "kEKhUAkpFCohhUKhElIoVEIKhUIlpFCohBQKhUpIoVAJKRQKlZBCoRJSKBQqIYVCJaRQKFRCCoVKSKFQqIQUCpWQQqFQCSkU"
    "KiGFQqESUihUQgqFQiWkUKiEFAqFSkihUAkpFAqVkEKhElIoFCohhUIlpFAor1NCX1/frSkpKetra2tJYWEh6e3tJeXl5WRi"
    "YoJkZeWQmJg4UltbR7q6ukhnZycZHh4mubm5hMlkku7ubpKYmEgyMjJIe3s7iY+PJ+Xl5SQ3N5/09w+SqamTpLS0jPT29pLu"
    "7m4SH59Ajrd1kJOnzpCe3n6SkZFFent7SVNTEykqKiJjYxOEyawh9fWNZGBgiDQ1tZDMzExy8uRJ0tDQRAoLGaSzs4vk5TFI"
    "ZkYuGRsbJyeGhsjA4BCpqKgiVVVVJDc3lxQVFREmk0mqqmpIbV0jKa+qINXV1WRsbIyMjY2R9vZ2UlNbR5pb20hzSxtJTcsg"
    "HR0dpL29nfT19ZHmlg7SPzBCBk+MkL6BflJcUkKqq6vJ0NAQGRufIO0dHaSrq4d0dfaR8bEpMjIyQk6ePEUmJ6fJ2NgEGRoa"
    "IQMDJ8jo6CiZvXiZ9PcNkYaGJtLd3U0GBk6Qqalp0tzcTPLz80lnVydpa+sgtTVNpKnxOOnr6yNtbW2kq6uL1Dc0ktq6BlJd"
    "U0fq6htIW1sb6e/vJ1NTU6S6upqUlJWShsZmUlI6d37FxcWktLSU1NbWksoqJuns6iUDA4NkZmaGVFZUk4z0HFJdXUva29vJ"
    "uXMXyJkzZ0lhYSEpLy8nbW0dJD09k5SXVZDBwSGSnp5BamtrSXd3NymvqCQnhkbI2Pgk6entJykpqaS6upoMDw+TrKxs0t8/"
    "SIaGRkhaWgYpKCggTCaTtLS0kLq6OhIeHk6am5tJXl4eCQ4OJk1NTaS/v58cP36cFBeXEG9vX5KUlEJ6enpJXV0d6e7uJtXV"
    "1SQnJ4fk5eW9FxgYKLriJfTw8HDfu3fvHR8fH8eioqL/Gh4ephJSCV+bhAMDA6SpqYn4+vqqKisrn7WysopY8RJmZWVJ7N27"
    "91NRUVGoqanNpqQk69TX15FTp05RCamEr0zC/v4B0t7eRvLz83eZmJj0ycjIQEZGBgkJCcYrXsLe3t7/sLe3L5OVlcWmTZuw"
    "bds22NnZ1zY3N2/Ozy8k8fGJVEIq4bJJ6OvrTzIyskhjYxO/v79/8o4dO3/atGkTNm7cCFVV1Ss9PT2CK17CO3fukKqqKg05"
    "OXls374TO3fuxtat27Fv34F/WlnZlPj7B+5uaWklfX19VEIq4ZJJ2NHRQSorq4ijo7Oci4tbtKKi0pdbt27Hzp27sXPnbsjJ"
    "bYSHh0d8b2/Pyg/MDA0NkY6OzncOH1b8bNu2HdizZx/27TuA/fsPYt++Azhw4BBcXFwbS0tLNw8ODpLx8XEqIZXwhSVsbW0l"
    "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"
    "iVy9eo3cvPkhuXbtOrl0aZacP3+ezMzMkIGBAXL8+HHS0tLyjo6OTqe4uBjk5ec2Ct2wQQz8/ILPJN7j4OPjx7p1G9h5pVJS"
    "Uti5c+eHlZWV4u3t7aSnp4fMzMyQ2dlZcvnyJXLt2txx3rz5Ibl69Sq5eHGWTE5OkdbWVtLQ0ECuXr1Gjh9vpxJSCd9cCa9d"
    "u07u3r1L7t27R+7cuUM++ug2uX17jlu3bpHbt2+R27dvs/dH//jjj8ndu3fJF198QSYmJlbt3r37Dh8fH/j4+MHFxf1SArLg"
    "4uIGLy8fBAQEIC0t/Y/W1laZL774gty9e5d8/PHH5KOPPmIfI+s454517vs7d+6wz+n27Y9Ia2sblZBK+GZLyHqIn5fPPvuM"
    "1NbW7hAREfl29erVSyIgC05OTnBwcCA2Ntbxiy++eEC25+M2lZBKuHIlvH37NpmeniYxMTEH161b97fVq1eDh4fnpeTj4eEB"
    "JycnODk54ebm5jkyMvJIi0clpBJSCRdIODIyQkpKSkh4ePgOeXn5qxwcHC/dAoqIiHzv7u5uXlFRQXp6eqiEVEIq4dMkzM/P"
    "J5mZmSQ8PFxIUlLyizVr1jx3i8jDwwMuLi4ICgr+08PD40hWVhZhMBhUQirhypXQ09OL5OTkvbSEw8PD8yvzE8ixY8eIg4OD"
    "0po1a35au3btc7eC77zzDrS0tAKPHTtGYmJiSF5eHuns7HxpCZuaWoiFhSWprmZSCamEr1/CwsIiUlZWRkZHR8nMzMwDUcXn"
    "5aOPPiJXr14lZ8+eJadOnSJTU3MT/QUFBVrc3Nw/cXBwPHWukNUCvvvuu3Bzc4tubW0lx48fJ52dnWRwcJCcOXPmhY+PxfT0"
    "SVJVVUWamppIenoGlZBK+PolLC0tZYfwWVMPL8rC6YB79+6RTz75hNy/f58wGAwNfn7+v3JwcDy2a8oKwqxater3oKCg0Pv3"
    "75PPP/+cfPrpp+STTz4h9+7dI3fv3n3pY7x79y7585//TDo7O0lqahqVkEr4Zkh469at+XnBj5ac27dvk88++4x0dHRsXb9+"
    "/TePE3Ht2rXg5OT8PT093ebzzz9flmNZOL/Z0dFBJaQSvh0S3rp1i3z44Yfk7t27JCQkRImLi+uHhdMXPDw8WLNmDd59913Y"
    "2tp6sY7j1q1bVEIqIZVwKSW8ceMGSUhIIAEBAXs3bdp0d9WqVeDi4sLq1ashJCT0k4eHh0NcXBz54IMP2IEXKiGVkEq4xBJG"
    "RUWRoqIiUlNTI7xly5ZeLi6uX8XExD5ISko62N7eTsLCwqiEVEIq4XJLmJeXR9rb24mTk9O2TZs2pRobG+tWVlaSpqYmKiGV"
    "kEKhUAkpFCohhUKhElIoVEIKhUIlpFCohBQKhUpIoVAJKRQKlZBCoRJSKBQqIYVCJaRQKFRCCoVKSKFQqIQUCpWQQqFQCSkU"
    "KiGFQqESUihUQgqFQiWkUKiEFAqFSkihUAkpFAq9CBQKlZBCoRJSKBQqIYVCJaRQKFRCCoVKSKFQqIQUCpWQQqFQCSkUKiGF"
    "QnmF/P8BAKNh4uISX0TmAAAAAElFTkSuQmCC"
)


def _cad_import_progress(window, title):
    from base64 import b64decode
    from PySide6.QtGui import QIcon, QPixmap

    dialog, update = window._import_progress(title)
    logo = QPixmap()
    if logo.loadFromData(b64decode(_PROGRESS_ICON_PNG), "PNG"):
        dialog.setWindowIcon(QIcon(logo))
    return dialog, update


def _begin_cad_destination(window, open_document):
    # The welcome screen covers a real blank document. Reuse it just as
    # IngeTrazo's own File > Open does.
    was_empty = bool(window._empty_on)
    if was_empty:
        window._leave_empty_area()
    created = window._new_document() if open_document and not window._doc_is_blank() else None
    return created, was_empty


def _restore_cad_destination(window, created, was_empty):
    if created is not None:
        window.close_document(created, ask=False)
    if was_empty and len(window._documents) == 1 and window._doc_is_blank():
        window._show_empty_area()


def _import_cad_direct(window, source, converter, *, open_document=False):
    drawing, diagnostics = _read_direct_cad(converter, source)
    if not drawing["entities"]:
        kinds = ", ".join(sorted(drawing.get("omitted", {})))
        raise ValueError("No supported model-space geometry in this drawing."
                         + (f" Skipped types: {kinds}." if kinds else ""))
    unit_scales = {1: 0.0254, 2: 0.3048, 4: 0.001, 5: 0.01, 6: 1.0}
    bounds = _direct_bounds(drawing)
    suggested = unit_scales.get(drawing["units"])
    if suggested is None and drawing["units"] == 0 and bounds.offset() is not None:
        suggested = 1.0
    options = window._dxf_options(source, suggested)
    if options is None:
        return
    scale, make_faces = options
    if scale is None:
        scale = suggested or 1.0
    drawing, offset = _recenter_direct_drawing(drawing, scale, bounds)
    document, was_empty = _begin_cad_destination(window, open_document)
    progress, update = _cad_import_progress(window, f"Importing {source.name}…")
    report = Counter()

    def load(scene):
        start = len(scene.groups)
        update(0.2, "Creating native objects…")
        report.update(_load_direct_model(scene, drawing, scale))
        if make_faces:
            from core.make_faces import faces_from_linework
            shared_meshes = {id(group.mesh): group.mesh for group in scene.groups[start:]}
            for mesh in shared_meshes.values():
                faces_from_linework(mesh)

    command = window._run_import(load, progress, "Import 3D CAD failed")
    if command is None:
        _restore_cad_destination(window, document, was_empty)
        return
    window._prepare_import_display(command, update)
    progress.close()
    window._on_zoom_extents()
    window.viewport.update()
    window.statusBar().showMessage(f"Imported {source.name}" + window._survey_note(offset), 12000)
    _report_direct_import(window, source, report, diagnostics)


def _import_cad(app, *, open_document=False):
    title = "Open 3D CAD" if open_document else "Import 3D CAD"
    filename, _ = QFileDialog.getOpenFileName(
        app.window, title, "",
        "CAD and mesh files (*.dxf *.dwg *.obj *.stl *.dae *.fbx *.gltf *.glb)",
    )
    if not filename:
        return
    source = Path(filename)
    try:
        converter = get_converter(app.window)
        if converter is not None:
            _import_cad_direct(app.window, source, converter, open_document=open_document)
    except Exception as exc:
        QMessageBox.critical(app.window, title, str(exc))


def _show_about(parent):
    """About dialog with BlackFox project and support links."""
    dialog = QDialog(parent)
    dialog.setWindowTitle("About BlackFox 3D CAD Exporter")
    dialog.setMinimumWidth(460)
    layout = QVBoxLayout(dialog)
    label = QLabel(dialog)
    label.setWordWrap(True)
    label.setTextFormat(__import__("PySide6.QtCore", fromlist=["Qt"]).Qt.RichText)
    label.setOpenExternalLinks(True)
    label.setText("""
        <h2>BlackFox 3D CAD Exporter</h2>
        <p><b>Version 1.0.2</b> &middot; 24 November 2026</p>
        <p>A free and open-source extension for exporting 3D geometry,
        dimensions, text and numbered survey points from IngeTrazo to DXF and DWG.</p>
        <p>Imports DXF, DWG and mesh files. Use IngeTrazo's native Guide Point tool
        to place guide points for CAD export.</p>
        <p><b>Project creator:</b> David Mavrov<br>
        <b>Development assistance:</b> ChatGPT (OpenAI)<br>
        <b>Additional ideas:</b> Gemini (Google), including suggesting AcadRust.</p>
        <p><b>License:</b> GNU General Public License v3.0 or later
        (GPL-3.0-or-later).<br>
        You may use, study, modify, share and sell this software under
        the terms of the license. Distributed derivative versions must
        respect the applicable GPL requirements.</p>
        <p><b>Third-party software:</b><br>
        IngeTrazo &mdash; GPL-3.0-or-later<br>
        AcadRust by Hakan AK &mdash; Mozilla Public License 2.0 (MPL-2.0);
        used by the separately downloaded Rust DWG converter.<br>
        See LICENSE_AcadRust.txt and THIRD_PARTY_NOTICES.md in the converter folder.<br>
        PySide6 / Qt for Python &mdash; LGPLv3, GPLv3 or commercial licensing</p>
        <p><b>DWG converter source:</b> <a href="https://github.com/davidsmavrov-debug/blackfox-dwg-converter">BlackFox Rust converter</a><br>
        <b>AcadRust author:</b> <a href="https://github.com/hakanaktt/acadrust">Hakan AK</a><br>
        <b>Source code and license:</b> <a href="https://github.com/davidsmavrov-debug/BlackFox-CAD">BlackFox-CAD on GitHub</a><br>
        <b>Support us at:</b> <a href="https://ko-fi.com/davidmavrov">https://ko-fi.com/davidmavrov</a></p>
        <p><small>Independent community extension; not an official IngeTrazo
        product. Provided without warranty, to the extent permitted by law.
        See the GPL license text for the full terms.</small></p>
    """)
    layout.addWidget(label)
    buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=dialog)
    buttons.rejected.connect(dialog.reject)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.exec()


def setup(app):
    """Official extension submenu API; no duplicate top-level Tool entries."""
    sub = app.add_menu("3D CAD Exporter")
    sub.addAction("Open 3D CAD", lambda: _import_cad(app, open_document=True))
    sub.addAction("Import 3D CAD", lambda: _import_cad(app))
    sub.addAction("Export 3D CAD", lambda: Export3DDXF().on_activate(app.viewport))
    sub.addAction("Export 3D CAD (Selected Geometry)", lambda: ExportSelected3DDXF().on_activate(app.viewport))
    sub.addSeparator()
    sub.addAction("About…", lambda: _show_about(app.window))
