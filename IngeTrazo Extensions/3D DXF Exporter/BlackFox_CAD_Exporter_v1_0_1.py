# SPDX-License-Identifier: GPL-3.0-or-later
"""BlackFox 3D CAD Exporter — IngeTrazo plugin, version 1.0.1.
Install as a .py file in Extensions > Open plugins folder; restart IngeTrazo.
Requires ezdxf in IngeTrazo's Python environment.
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
LEGACY_VERSION = "1.0.0"
MAX_ARCHIVE = 128 * 1024 * 1024
# Set together by the release packaging script from the approved build artifacts.
RELEASE_MANIFEST = b""
RELEASE_MANIFEST_SHA256 = ""

# SHA-256 of the *published ZIP archives*, independently verified at packaging.
CHECKSUMS = {
    "aarch64-apple-darwin": "bf4fb2a4c11125b4a174e3ba42cf5badc79f5c5a812a58d41ec29f4243261cdc",
    "aarch64-pc-windows-msvc": "fe8cd5d306a36650523b732d449c77c75185263d9b44b044578f16c0ce50a3a5",
    "aarch64-unknown-linux-gnu": "3c22f84fc85a3862ac5848f731b72c10071f554e21fe37ec2a000b14b93c81db",
    "x86_64-apple-darwin": "1f94a0170e2b99b092eec8de437e3d8079f0875a6c79bcf52479eab25b22ea8b",
    "x86_64-pc-windows-msvc": "4396ee2c027f87345fa53368149c8600f00c722aa57fff44494d9c2d7a1c915d",
    "x86_64-unknown-linux-gnu": "86f1319d53a4e99cf1e7e90b592bd6bce4484c435ce14bfa537e7a1e48305fad",
}

ARCHIVE_SIZES = {
    "aarch64-apple-darwin": 2420214,
    "aarch64-pc-windows-msvc": 2408800,
    "aarch64-unknown-linux-gnu": 2469199,
    "x86_64-apple-darwin": 2627657,
    "x86_64-pc-windows-msvc": 2664774,
    "x86_64-unknown-linux-gnu": 2693282,
}

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


def _release_metadata(rid, require_import):
    if RELEASE_MANIFEST:
        if hashlib.sha256(RELEASE_MANIFEST).hexdigest() != RELEASE_MANIFEST_SHA256:
            raise RuntimeError("BlackFox CAD release manifest failed SHA-256 verification.")
        manifest = json.loads(RELEASE_MANIFEST)
        version = manifest["version"]
        if (manifest["schema"] != 1 or manifest["repository"] != CONVERTER_REPOSITORY
                or manifest["abi"] != 2
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
                or version == LEGACY_VERSION):
            raise RuntimeError("Invalid BlackFox CAD release manifest.")
        asset = manifest["assets"].get(rid)
        if asset is not None:
            size, digest = asset["size"], asset["sha256"]
            if (type(size) is not int or not 0 < size <= MAX_ARCHIVE
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise RuntimeError("Invalid BlackFox CAD release asset metadata.")
            return version, size, digest
    if require_import:
        raise RuntimeError(f"The BlackFox CAD import converter is not available for {rid}.")
    return LEGACY_VERSION, ARCHIVE_SIZES[rid], CHECKSUMS[rid]


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
    request = urllib.request.Request(url, headers={"User-Agent": "BlackFox-CAD-Exporter/1.0.1"})
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


def get_converter(parent=None, *, require_import=False):
    """Resolve and validate the converter before each execution."""
    from core.extensions import user_plugins_dir

    rid, filename, arch = _blackfox_platform()
    version, size, digest = _release_metadata(rid, require_import)
    archive_name = f"blackfox-dwg-{rid}.zip"
    plugins = user_plugins_dir().resolve()
    directory = plugins.parent / "extension-data" / "blackfox_cad_exporter" / "bin" / version / rid
    if directory.resolve() != directory:
        raise RuntimeError("The BlackFox CAD converter directory contains a redirect.")
    archive_path = directory / archive_name
    executable = directory / filename
    if not _verified_archive(archive_path, size, digest):
        legacy = Path(__file__).resolve().parent / "BlackFoxDWG" / f"v{version}" / rid / archive_name
        if version == LEGACY_VERSION and _verified_archive(legacy, size, digest):
            data = legacy.read_bytes()
            if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError("The legacy BlackFox CAD converter archive changed during migration.")
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


def dxf_layer_name(name):
    """Map IngeTrazo default layer to the mandatory DXF layer 0."""
    return "0" if name == "Layer 0" else name


def layers(scene):
    result = ["0"]
    for layer in getattr(scene, "layers", []):
        name = layer if isinstance(layer, str) else getattr(layer, "name", None)
        name = dxf_layer_name(str(name)) if name is not None else None
        if name and name not in result:
            result.append(name)
    return result


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


def _layer_color(scene, layer):
    """Read actual source layer color; do not invent palette colors."""
    for attr in ("color", "colour", "display_color", "displayColor"):
        result = _rgb(getattr(layer, attr, None))
        if result is not None:
            return result
    name = layer if isinstance(layer, str) else getattr(layer, "name", None)
    for attr in ("layer_colors", "layer_colours"):
        mapping = getattr(scene, attr, None)
        if isinstance(mapping, dict) and name in mapping:
            result = _rgb(mapping[name])
            if result is not None:
                return result
    return None


def _write_layer_colors(doc, scene):
    for source in getattr(scene, "layers", []):
        name = source if isinstance(source, str) else getattr(source, "name", None)
        target_name = dxf_layer_name(str(name)) if name is not None else None
        if not target_name or target_name not in doc.layers:
            continue
        color = _layer_color(scene, source)
        if color is None:
            continue
        target = doc.layers.get(target_name)
        target.dxf.true_color = color


def safe_layer(value, known):
    if not isinstance(value, str):
        value = getattr(value, "name", None)
    value = dxf_layer_name(value)
    return value if value in known else "0"


def face_loops(face):
    outer = list(getattr(face, "loop", []) or [])
    holes = [list(h) for h in (getattr(face, "hole_loops", []) or [])]
    return [outer] + holes


def _edge_layer_map(mesh, known):
    mapping = {}
    for edge in list(getattr(mesh, "edges", []) or []):
        layer = safe_layer(getattr(edge, "layer", None), known)
        a, b = xyz(edge.v0), xyz(edge.v1)
        mapping[frozenset((a, b))] = layer
    return mapping


def _face_layer(face, loop, edge_layers, known, default_layer):
    layer = safe_layer(getattr(face, "layer", None), known)
    if layer != "0":
        return layer
    candidates = []
    for i in range(len(loop)):
        key = frozenset((xyz(loop[i]), xyz(loop[(i + 1) % len(loop)])))
        value = edge_layers.get(key, "0")
        if value != "0":
            candidates.append(value)
    return Counter(candidates).most_common(1)[0][0] if candidates else default_layer


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


def _export_curves(space, edges, known, default_layer, counts):
    """Chain edges carrying the same curve ID; leave independent edges as LINE."""
    created = []
    chains = defaultdict(list)
    for edge in edges:
        if getattr(edge, "faces", None):
            continue
        key = _curve_key(edge)
        layer = safe_layer(getattr(edge, "layer", None), known)
        if layer == "0":
            layer = default_layer
        if key is None:
            created.append(space.add_line(xyz(edge.v0), xyz(edge.v1), dxfattribs={"layer": layer}))
            counts["lines"] += 1
        else:
            chains[(key, layer)].append((xyz(edge.v0), xyz(edge.v1)))
    for (_, layer), segments in chains.items():
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
            created.append(space.add_polyline3d(points, close=closed, dxfattribs={"layer": layer}))
            counts["polylines"] += 1
            unused -= component
    return created


def _surface_components(face_data):
    """Partition faces into surface islands using shared boundary edges.

    Matching by *edges*, not just vertices, avoids joining objects which
    touch at a single point. Layers are separated before this function.
    """
    adjacency = defaultdict(list)
    for index, (_, boundary) in enumerate(face_data):
        for i in range(len(boundary)):
            edge = frozenset((boundary[i], boundary[(i + 1) % len(boundary)]))
            adjacency[edge].append(index)
    neighbors = [set() for _ in face_data]
    for indices in adjacency.values():
        for index in indices:
            neighbors[index].update(other for other in indices if other != index)
    unseen = set(range(len(face_data)))
    while unseen:
        first = min(unseen)
        unseen.remove(first)
        pending = [first]
        component = [first]
        while pending:
            for neighbor in neighbors[pending.pop()] & unseen:
                unseen.remove(neighbor)
                pending.append(neighbor)
                component.append(neighbor)
        yield component


def write_mesh(space, mesh, known, default_layer, counts, options=None):
    options = options or {"faces": True, "edges": True}
    """v0.6: SketchUp-style DXF POLYFACE meshes for disconnected face islands.

    This deliberately changes ONLY face representation. Existing curve
    handling, group BLOCKs and component INSERTs remain unchanged.
    """
    from ezdxf.math.triangulation import mapbox_earcut_3d

    created = []
    faces = list(getattr(mesh, "faces", []) or [])
    edges = list(getattr(mesh, "edges", []) or [])
    edge_layers = _edge_layer_map(mesh, known)
    by_layer = defaultdict(list)

    for face in faces:
        loops = face_loops(face)
        outer = loops[0] if loops else []
        if len(outer) < 3:
            continue
        layer = _face_layer(face, outer, edge_layers, known, default_layer)
        exterior = [xyz(v) for v in outer]
        holes = [[xyz(v) for v in loop] for loop in loops[1:] if len(loop) >= 3]
        if len(exterior) <= 4 and not holes:
            polygons = [exterior]
        else:
            polygons = [list(tri) for tri in mapbox_earcut_3d(exterior, holes)]
            if not polygons:
                raise ValueError("Triangulation failed for a polygon face")
            counts["triangulated_polygons"] += 1
        # Keep the original face boundary for connectivity. All triangles
        # from one n-gon must remain in the same mesh island.
        by_layer[layer].append((polygons, exterior))

    if not options["faces"]:
        by_layer.clear()

    for layer, face_data in by_layer.items():
        for component in _surface_components(face_data):
            polyface = space.add_polyface(dxfattribs={"layer": layer})
            # Polyface VERTEX face records have max four corners.
            polyface.append_faces(
                polygon
                for index in component
                for polygon in face_data[index][0]
            )
            created.append(polyface)
            counts["mesh_objects"] += 1
            counts["faces"] += sum(len(face_data[index][0]) for index in component)

    # Mesh boundary edges, including shared edges: one LINE per unique edge.
    # Free-standing curve edges remain handled by _export_curves below.
    unique = set()
    for edge in (edges if options["edges"] else []):
        if not getattr(edge, "faces", None):
            continue
        a, b = xyz(edge.v0), xyz(edge.v1)
        if a == b:
            continue
        layer = safe_layer(getattr(edge, "layer", None), known)
        if layer == "0":
            layer = default_layer
        key = (layer, frozenset((a, b)))
        if key in unique:
            continue
        unique.add(key)
        created.append(space.add_line(a, b, dxfattribs={"layer": layer}))
        counts["mesh_edges"] += 1

    if options["edges"]:
        created.extend(_export_curves(space, edges, known, default_layer, counts))
    return created


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


def insert_placement(matrix):
    if matrix is None:
        return (0, 0, 0), 0.0, (1, 1, 1)
    # IngeTrazo placement matrices use homogeneous column vectors.
    # Avoid Matrix44.transform(): it hid translations in v0.1.
    column_position = tuple(matrix[r][3] for r in range(3))
    row_position = tuple(matrix[3][c] for c in range(3))
    if any(abs(v) > 1e-8 for v in column_position):
        position = column_position
    elif any(abs(v) > 1e-8 for v in row_position):
        position = row_position
    else:
        position = (0, 0, 0)
    sx = math.hypot(matrix[0][0], matrix[1][0])
    sy = math.hypot(matrix[0][1], matrix[1][1])
    sz = math.sqrt(sum(matrix[r][2] ** 2 for r in range(3)))
    if min(sx, sy, sz) < 1e-10:
        raise ValueError("Degenerate component transform")
    # A reflected XY transform requires a negative Y scale.
    determinant_xy = matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0]
    if determinant_xy < 0:
        sy = -sy
    angle = math.degrees(math.atan2(matrix[1][0], matrix[0][0]))
    # This first release supports planar Z-axis rotations (benchmark case).
    if any(abs(matrix[r][2]) > 1e-6 for r in (0, 1)) or any(abs(matrix[2][c]) > 1e-6 for c in (0, 1)):
        raise ValueError("3D tilted component rotation requires a future exporter update")
    return position, angle, (sx, sy, sz)


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


def _export_annotations(doc, model, scene, known, counts, selected_only=False, options=None):
    """Export native dimensions and text without altering source annotations."""
    from ezdxf.math import UCS, Vec3

    options = options or {"annotations": True, "text": True}
    dimensions = list(getattr(scene, "dimensions", []) or []) if options["annotations"] else []
    labels = list(getattr(scene, "text_labels", []) or []) if options["text"] else []
    if selected_only:
        # Never include unselected annotations in Selected Geometry mode.
        selected = list(getattr(scene, "selection", []) or [])
        ids = {id(obj) for item in selected for obj in
               [item] + [getattr(item, key, None) for key in
                         ("object", "entity", "item", "target", "ref", "dimension", "text_label")]}
        dimensions = [d for d in dimensions if id(d) in ids]
        labels = [t for t in labels if id(t) in ids]

    style = getattr(scene, "dimension_style", {}) or {}
    decimals = max(0, min(8, int(style.get("decimals", 2))))
    units = str(style.get("units", "m"))
    suffix = (" " + units) if style.get("show_unit", True) and units else ""
    for dim in dimensions:
        a, b = Vec3(xyz(dim.a)), Vec3(xyz(dim.b))
        delta = b - a
        if delta.magnitude < 1e-9:
            continue
        ux = delta.normalize()
        offset = Vec3(xyz(getattr(dim, "offset", (0, 0, 0))))
        perpendicular = offset - ux * offset.dot(ux)
        if perpendicular.magnitude < 1e-9:
            ref = Vec3(0, 0, 1) if abs(ux.z) < .9 else Vec3(0, 1, 0)
            perpendicular = ref - ux * ref.dot(ux)
        uy = perpendicular.normalize()
        # Keep the v0.8.2 dimension plane and extension-line geometry.
        # Rotate its local X/Y axes together by 180 degrees. This retains
        # the plane normal, but reverses the side used for dimension text
        # and turns the text direction around without mirroring it.
        normal = ux.cross(uy)
        if abs(normal.z) > 0.5 and normal.z < 0:
            ux = -ux
        ux = -ux
        uy = -uy
        # The offset direction is kept fixed; compute local x coordinates
        # from the actual endpoint rather than assuming +X.
        distance = offset.dot(uy)
        length_on_x = delta.dot(ux)
        ucs = UCS(origin=a, ux=ux, uy=uy)
        override_text = getattr(dim, "text", None)
        if override_text is None:
            measured = delta.magnitude
            # Source coordinates are in metres; preserve source units display.
            if units == "mm":
                measured *= 1000
            elif units == "cm":
                measured *= 100
            override_text = f"{measured:.{decimals}f}{suffix}"
        layer = safe_layer(getattr(dim, "layer", None), known)
        result = model.add_linear_dim(
            base=(0, distance), p1=(0, 0), p2=(length_on_x, 0),
            angle=0, text=str(override_text),
            dxfattribs={"layer": layer},
            override={"dimtxt": 0.12, "dimgap": 0.025,
                      "dimasz": 0.06, "dimexo": 0.02, "dimexe": 0.03,
                      "dimscale": 1.0, "dimfxlon": 0, "dimtad": 1},
        )
        result.render(ucs=ucs)
        counts["dimensions"] += 1

    for label in labels:
        anchor = Vec3(xyz(label.anchor))
        offset = Vec3(xyz(getattr(label, "offset", (0, 0, 0))))
        text = str(getattr(label, "text", "") or "")
        if not text:
            continue
        layer = safe_layer(getattr(label, "layer", None), known)
        # IngeTrazo TextLabel offset locates the displayed text relative to anchor.
        position = anchor + offset
        entity = model.add_mtext(text.replace("\n", r"\P"),
                                 dxfattribs={"layer": layer, "char_height": 0.15})
        entity.set_location(position)
        # IngeTrazo uses an anchor and a displaced label. Preserve that
        # connection as an actual DXF leader with a visible arrowhead.
        if offset.magnitude > 1e-7:
            # A short landing under the label, instead of ending in its centre.
            landing = position - offset.normalize() * 0.10
            model.add_leader(
                [anchor, landing],
                dimstyle="Standard",
                dxfattribs={"layer": layer, "has_arrowhead": 1},
                override={"dimasz": 0.10, "dimscale": 1.0},
            )
        counts["texts"] += 1


def _cad_definition_key(group):
    return id(group.mesh), tuple(
        (_cad_definition_key(child), child.layer,
         tuple(tuple(row) for row in placement_matrix(child.xform)) if child.xform is not None else None)
        for child in group.children
    )


def _cad_insert_matrix(matrix):
    from ezdxf.math import Matrix44, Vec3

    rows = placement_matrix(matrix)
    x, y, z = (Vec3(rows[0][i], rows[1][i], rows[2][i]) for i in range(3))
    sx, sy, sz = (axis.magnitude for axis in (x, y, z))
    if min(sx, sy, sz) < 1e-10:
        raise ValueError("CAD block instance has a degenerate transform.")
    x, y, z = x / sx, y / sy, z / sz
    if max(abs(x.dot(y)), abs(x.dot(z)), abs(y.dot(z))) > 1e-5:
        raise ValueError("A sheared CAD block instance cannot be represented by a DXF INSERT.")
    # Qt stores transforms in float32. Remove rounding drift before constructing
    # the strictly orthogonal double-precision coordinate system of an INSERT.
    corrected_x = (x - z * x.dot(z)).normalize()
    corrected_y = z.cross(corrected_x)
    if y.dot(corrected_y) < 0:
        corrected_y = -corrected_y
    return Matrix44([
        *(corrected_x * sx), 0,
        *(corrected_y * sy), 0,
        *(z * sz), 0,
        rows[0][3], rows[1][3], rows[2][3], 1,
    ])


def _write_cad_component(space, group, doc, definitions, known, counts, options):
    layer = safe_layer(group.layer, known)
    signature = _cad_definition_key(group)
    name = definitions.get(signature)
    if name is None:
        name = f"BLACKFOX_CAD_{len(definitions) + 1:04d}"
        definitions[signature] = name
        block = doc.blocks.new(name)
        counts["blocks"] += 1
        write_mesh(block, group.mesh, known, "0", counts, options)
        for child in group.children:
            _write_cad_component(block, child, doc, definitions, known, counts, options)
    insert = space.add_blockref(name, (0, 0, 0), dxfattribs={"layer": layer})
    if group.xform is not None:
        insert.transform(_cad_insert_matrix(group.xform))
    counts["inserts"] += 1


def export(scene, filename, selected_only=False, options=None, dxf_version="R2010"):
    options = options or {"faces": True, "edges": True, "text": True, "annotations": True}
    import ezdxf
    from core.group import iter_placements

    if dxf_version not in DXF_VERSIONS:
        raise ValueError(f"Unsupported DXF version: {dxf_version}")
    # R12 cannot encode our native dimension/MTEXT/leader entities.
    # Enforce compatibility even if export() is called outside the Options UI.
    options = dict(options)
    if dxf_version == "R12":
        options["annotations"] = False
        options["text"] = False
    doc = ezdxf.new(dxf_version)
    known = layers(scene)
    for name in known:
        if name != "0":
            doc.layers.new(name)
    counts = dict(faces=0, mesh_objects=0, mesh_edges=0, lines=0, polylines=0, triangulated_polygons=0, inserts=0, blocks=0, groups=0, dimensions=0, texts=0)
    if dxf_version != "R12":
        _write_layer_colors(doc, scene)
    model = doc.modelspace()
    if selected_only:
        loose, export_groups, export_guides = _selected_geometry(scene)
        export_geo_points = []  # Selected Geometry never includes survey points.
    else:
        loose = scene.loose_mesh
        export_groups = list(getattr(scene, "groups", []) or [])
        export_guides = list(getattr(scene, "guides", []) or [])
        export_geo_points = list(getattr(scene, "geo_points", []) or [])
    write_mesh(model, loose, known, "0", counts, options)

    definitions = {}
    cad_definitions = {}
    for group in export_groups:
        if (getattr(group, "ext", None) or {}).get("blackfox_cad_block"):
            _write_cad_component(model, group, doc, cad_definitions, known, counts, options)
            continue
        mesh = getattr(group, "mesh", None)
        if mesh is None:
            continue
        group_layer = safe_layer(getattr(group, "layer", None), known)
        is_component = bool(group.is_component())
        placements = list(iter_placements(group))
        if not placements:
            placements = [(group, None)]

        if not is_component:
            # Ordinary IngeTrazo group: unique BLOCK + INSERT, matching SketchUp.
            # Group mesh vertices are already in world coordinates in the
            # benchmark, so an origin INSERT preserves their existing positions.
            block_name = "INGETRAZO_GROUP_%04d" % (counts["groups"] + 1)
            block = doc.blocks.new(block_name)
            write_mesh(block, mesh, known, group_layer, counts, options)
            model.add_blockref(block_name, (0, 0, 0),
                               dxfattribs={"layer": group_layer})
            counts["blocks"] += 1
            counts["inserts"] += 1
            counts["groups"] += 1
            continue

        key = id(mesh)
        if key not in definitions:
            block_name = "INGETRAZO_%04d" % (len(definitions) + 1)
            block = doc.blocks.new(block_name)
            write_mesh(block, mesh, known, group_layer, counts, options)
            definitions[key] = block_name
            counts["blocks"] += 1
        block_name = definitions[key]
        for item in placements:
            raw_matrix = item[1] if isinstance(item, (tuple, list)) and len(item) >= 2 else None
            if raw_matrix is None:
                for attr in ("transform", "matrix", "placement", "transform_matrix"):
                    candidate = getattr(item[0] if isinstance(item, (tuple, list)) else group, attr, None)
                    if candidate is not None and not callable(candidate):
                        raw_matrix = candidate
                        break
            position, angle, scales = insert_placement(placement_matrix(raw_matrix))
            model.add_blockref(block_name, position, dxfattribs={
                "layer": group_layer,
                "rotation": angle,
                "xscale": scales[0],
                "yscale": scales[1],
                "zscale": scales[2],
            })
            counts["inserts"] += 1

    # v0.6.3 additive: native construction guide points -> DXF POINT.
    counts["points"] = 0
    for guide in export_guides:
        if getattr(guide, "direction", None) is not None:
            continue  # Never export guide lines or their tails as points.
        point = getattr(guide, "point", None)
        if point is None:
            continue
        model.add_point(xyz(point), dxfattribs={
            "layer": safe_layer(getattr(guide, "layer", "Guides"), known)
        })
        counts["points"] += 1

    # Survey points are GeoPoint objects, not construction guides or mesh vertices.
    # Export the stored local XYZ directly; do not apply the UTM datum twice.
    counts["survey_points"] = 0
    counts["survey_labels"] = 0
    if options.get("survey_points", True) and export_geo_points:
        survey_layer = "INGETRAZO_SURVEY_POINTS"
        if survey_layer not in doc.layers:
            doc.layers.new(survey_layer)
        appid = "INGETRAZO_SURVEY"
        if appid not in doc.appids:
            doc.appids.new(appid)
        for survey_point in export_geo_points:
            position = xyz(survey_point)
            if not all(math.isfinite(v) for v in position):
                raise ValueError("Survey point has invalid XYZ coordinates")
            entity = model.add_point(position, dxfattribs={"layer": survey_layer})
            name = str(getattr(survey_point, "name", "") or "")
            desc = str(getattr(survey_point, "desc", "") or "")
            # XDATA is attached to the POINT, not a separate floating label.
            # Split long strings into valid DXF 1000-group chunks.
            tags = []
            for field, value in (("NAME", name), ("DESC", desc)):
                tags.append((1000, field))
                for start in range(0, len(value), 200):
                    tags.append((1000, value[start:start + 200]))
                if not value:
                    tags.append((1000, ""))
            entity.set_xdata(appid, tags)
            counts["survey_points"] += 1
            # Visible, editable DXF TEXT for the survey point number.
            # Keep the exact POINT coordinates; only the label is offset.
            if name:
                height = 0.10
                x, y, z = position
                model.add_text(
                    name,
                    dxfattribs={
                        "layer": survey_layer,
                        "height": height,
                        "insert": (x + 0.12, y + 0.12, z),
                    },
                )
                counts["survey_labels"] += 1

    _export_annotations(doc, model, scene, known, counts, selected_only=selected_only, options=options)

    # Layer 0 is required by DXF; Defpoints is not.
    if "Defpoints" in doc.layers:
        doc.layers.remove("Defpoints")
    doc.saveas(filename)
    return counts


DXF_VERSIONS = ("R12", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018")

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
        version_box.addItem("AutoCAD " + version[1:], version)
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


def _export_dwg(scene, filename, selected_only, options, version, parent=None):
    """Export through a temporary DXF, then atomically publish the DWG."""
    import os
    import subprocess
    import tempfile
    from pathlib import Path

    converter = get_converter(parent)
    if converter is None:
        return None  # User cancelled the download.
    if version not in DWG_VERSIONS:
        raise ValueError("Unsupported DWG version: " + str(version))

    target = Path(filename)
    # Both temporary files live beside the destination, allowing atomic replace.
    # The user must have write permission to this directory.
    temporary_paths = []
    try:
        for suffix in (".dxf", ".dwg"):
            fd, name = tempfile.mkstemp(
                prefix=".blackfox_export_", suffix=suffix, dir=str(target.parent)
            )
            os.close(fd)
            temporary_paths.append(Path(name))
        intermediate, converted = temporary_paths
        counts = export(scene, str(intermediate), selected_only=selected_only,
                        options=options, dxf_version=version)
        result = subprocess.run(
            [str(converter), str(intermediate), str(converted), version],
            capture_output=True, text=True, timeout=180, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            details = (result.stderr or result.stdout or "Unknown error").strip()
            raise RuntimeError(
                "BlackFox DWG converter failed (exit " + str(result.returncode)
                + "):\n" + details[-2500:]
            )
        if not converted.is_file() or converted.stat().st_size < 100:
            raise RuntimeError("Converter did not produce a valid-sized DWG file")
        with converted.open("rb") as stream:
            if not stream.read(6).startswith(b"AC10"):
                raise RuntimeError("Converter output does not have a DWG header")
        os.replace(str(converted), str(target))
        return counts
    finally:
        for path in temporary_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


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
            scene = viewport.scene
            if file_format == "dwg":
                counts = _export_dwg(scene, filename, self.selected_only,
                                     options, dxf_version, viewport.window())
                if counts is None:
                    return
            else:
                counts = export(scene, filename, selected_only=self.selected_only,
                                options=options, dxf_version=dxf_version)
            summary = "\n".join(f"{k}: {v}" for k, v in counts.items())
            QMessageBox.information(viewport.window(), "Export 3D CAD",
                                    f"Saved {file_format.upper()} ({dxf_version}):\n{filename}\n\n{summary}")
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


def _restore_cad_hierarchy(scene, doc, stats, scale, make_faces):
    from core.group import Group
    from core.layers import Layer
    from formats.dxf_in import (
        _Bucket, _SAGITTA_M, _bucket_one, _build_mesh, _faces_from_outlines, _fold_xform,
    )

    sagitta = max(_SAGITTA_M / scale, 1e-6)
    offset = stats.get("offset") or (0.0, 0.0, 0.0)
    origin = (0.0, 0.0, 0.0)
    prototypes = {}
    warnings = Counter()

    def placements(entities, ancestors, displacement):
        for insert in entities:
            if insert.dxftype() != "INSERT":
                continue
            name = insert.dxf.name
            key = name.casefold()
            if key in ancestors or len(ancestors) >= 64:
                warnings["cyclic or too deeply nested block insert"] += 1
                continue
            if key not in prototypes:
                block = doc.blocks.get(name)
                if block is None:
                    warnings["missing block definition"] += 1
                    continue
                bucket = _Bucket()
                for entity in block:
                    if entity.dxftype() != "INSERT":
                        _bucket_one(entity, "0", sagitta, {}, [0], {"0": bucket})
                if bucket.points:
                    warnings["points inside block definitions"] += len(bucket.points)
                mesh = _build_mesh(bucket, scale, origin)
                if make_faces:
                    _faces_from_outlines(mesh)
                prototypes[key] = block, mesh
            block, mesh = prototypes[key]
            layer = insert.dxf.layer
            instances = insert.multi_insert() if insert.mcount > 1 else (insert,)
            for occurrence in instances:
                children = list(placements(block, (*ancestors, key), origin))
                if not children and not (mesh.edges or mesh.faces):
                    continue
                instance = Group(mesh, name=name)
                instance.xform = _fold_xform(occurrence.matrix44(), scale, displacement)
                instance.ext = {"blackfox_cad_block": True}
                if layer != "0":
                    instance.layer = layer
                    if scene.layer(layer) is None:
                        scene.layers.append(Layer(layer))
                instance.adopt(children)
                yield instance

    roots = list(placements(doc.modelspace(), (), offset))
    previous = sum(stats.get("components", {}).values())
    if previous:
        del scene.groups[-previous:]
    scene.groups.extend(roots)
    stats["groups"] += len(roots) - previous
    stats["block_warnings"] = warnings


def _apply_cad_layer_properties(scene, doc, existing_names):
    from ezdxf.colors import aci2rgb

    for layer in scene.layers:
        if layer.name in existing_names or layer.name not in doc.layers:
            continue
        cad_layer = doc.layers.get(layer.name)
        layer.visible = not (cad_layer.is_off() or cad_layer.is_frozen())
        layer.locked = cad_layer.is_locked()
        color = cad_layer.rgb
        if color is None and 1 <= cad_layer.color <= 255 and cad_layer.color != 7:
            color = aci2rgb(cad_layer.color)
        if color is not None:
            layer.color = tuple(channel / 255.0 for channel in color)


def _load_cad_dxf(window, path, source, converter_warnings):
    from formats.dxf_in import load_dxf, open_document, suggest_unit_scale

    doc = open_document(path)
    suggested, _ = suggest_unit_scale(doc)
    options = window._dxf_options(source, suggested)
    if options is None:
        return
    scale, make_faces = options
    if scale is None:
        scale = suggested or 1.0
    has_blocks = bool(doc.modelspace().query("INSERT"))
    progress, report = window._import_progress(f"Importing {source.name}…")
    stats = {}

    def load(scene):
        existing_names = {layer.name for layer in scene.layers}
        stats.update(load_dxf(scene, path, progress=report, scale=scale,
                              doc=doc, name=source.stem, make_faces=make_faces))
        if has_blocks:
            _restore_cad_hierarchy(scene, doc, stats, scale, make_faces)
        _apply_cad_layer_properties(scene, doc, existing_names)

    command = window._run_import(
        load, progress, "Import 3D CAD failed",
        describe=lambda exc: window._dxf_failure_text(exc, source),
    )
    if command is None:
        return
    window._prepare_import_display(command, report)
    progress.close()
    window._on_zoom_extents()
    window.viewport.update()
    summary = (f"Imported {source.name}: {stats.get('edges', 0)} edges, "
               f"{stats.get('groups', 0)} groups, {stats.get('points', 0)} guide points")
    window.statusBar().showMessage(summary + window._survey_note(stats.get("offset")), 8000)
    warnings = [converter_warnings] if converter_warnings else []
    layouts = [doc.modelspace()]
    blocks_seen = set()
    curved = set()
    for layout in layouts:
        for entity in layout:
            kind = entity.dxftype()
            if kind == "INSERT":
                name = entity.dxf.name
                if name not in blocks_seen:
                    blocks_seen.add(name)
                    block = doc.blocks.get(name)
                    if block is not None:
                        layouts.append(block)
            elif (kind in {"ARC", "CIRCLE", "ELLIPSE", "SPLINE"}
                  or (kind == "LWPOLYLINE" and entity.has_arc)):
                curved.add(kind)
    if curved:
        warnings.append("IngeTrazo imported these curves as segmented contours: "
                        + ", ".join(sorted(curved)))
    if stats.get("block_warnings"):
        warnings.append("IngeTrazo omitted " + ", ".join(
            f"{count} {kind}" for kind, count in sorted(stats["block_warnings"].items())))
    if any(len(layout) for layout in doc.layouts if layout.name != "Model"):
        warnings.append("IngeTrazo imports model space. Paper-space layouts were omitted.")
    if stats.get("skipped"):
        skipped = ", ".join(f"{kind} ({count})" for kind, count in sorted(stats["skipped"].items()))
        warnings.append("IngeTrazo skipped these entities: " + skipped)
    if warnings:
        QMessageBox.warning(window, "Import 3D CAD", "\n\n".join(warnings))


def _import_cad(app):
    title = "Import 3D CAD"
    filename, _ = QFileDialog.getOpenFileName(
        app.window, title, "",
        "CAD and mesh files (*.dxf *.dwg *.obj *.stl *.dae *.fbx *.gltf *.glb)",
    )
    if not filename:
        return
    source = Path(filename)
    try:
        converter = get_converter(app.window, require_import=True)
        if converter is None:
            return
        with tempfile.TemporaryDirectory(prefix="blackfox-cad-import-") as folder:
            intermediate = Path(folder) / "converted.dxf"
            result = subprocess.run(
                [str(converter), "convert", str(source), str(intermediate), "R2018"],
                capture_output=True, encoding="utf-8", errors="replace",
                timeout=180, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode:
                details = result.stderr.strip() or result.stdout.strip()
                raise RuntimeError(details[-2500:] or f"Converter exited with code {result.returncode}")
            _load_cad_dxf(app.window, intermediate, source, result.stderr.strip()[-2500:])
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
        <p><b>Version 1.0.1</b> &middot; November 2026</p>
        <p>A free and open-source extension for exporting 3D geometry,
        dimensions, text and numbered survey points from IngeTrazo to DXF and DWG.</p>
        <p>Imports DXF, DWG and mesh files. Use IngeTrazo's native Point tool
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
        ezdxf &mdash; MIT License<br>
        AcadRust by Hakan AK &mdash; Mozilla Public License 2.0 (MPL-2.0);
        used by the separately downloaded Rust DWG converter.<br>
        See LICENSE_AcadRust.txt and THIRD_PARTY_NOTICES.md in the converter folder.<br>
        PySide6 / Qt for Python &mdash; LGPLv3, GPLv3 or commercial licensing</p>
        <p><b>DWG converter source:</b> <a href="https://github.com/davidsmavrov-debug/blackfox-dwg-rust-test">BlackFox Rust converter</a><br>
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
    sub.addAction("Export 3D CAD", lambda: Export3DDXF().on_activate(app.viewport))
    sub.addAction("Export 3D CAD (Selected Geometry)", lambda: ExportSelected3DDXF().on_activate(app.viewport))
    sub.addAction("Import 3D CAD", lambda: _import_cad(app))
    sub.addSeparator()
    sub.addAction("About…", lambda: _show_about(app.window))
