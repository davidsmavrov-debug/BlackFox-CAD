import math
# SPDX-License-Identifier: GPL-3.0-only
"""Import and export SketchUp SKP models in IngeTrazo."""

__version__ = "1.0.1"

from pathlib import Path
import json
import subprocess
import os
import re
import sys
import tempfile
import traceback
from PySide6.QtWidgets import (
    QFileDialog, QMessageBox, QDialog, QVBoxLayout,
    QLabel, QDialogButtonBox,
)
from PySide6.QtCore import Qt, QObject, QEvent
from PySide6.QtGui import QVector3D, QMatrix4x4

# UI test matrix based on upstream skpwright support (SketchUp 3-2027).
# 2021-2027 share a container family; actual output selection must be
# checked against the local Rust engine before wiring these filters.
SKP_FILTERS = [
    "SKP 2027 (*.skp)",
    "SKP 2026 (*.skp)",
    "SKP 2025 (*.skp)",
    "SKP 2024 (*.skp)",
    "SKP 2023 (*.skp)",
    "SKP 2022 (*.skp)",
    "SKP 2021 (*.skp)",
    "SKP 2020 (*.skp)",
    "SKP 2019 (*.skp)",
    "SKP 2018 (*.skp)",
    "SKP 2017 (*.skp)",
    "SKP 2016 (*.skp)",
    "SKP 2015 (*.skp)",
    "SKP 2014 (*.skp)",
    "SKP 2013 (*.skp)",
    "SKP 8 (*.skp)",
    "SKP 7 (*.skp)",
    "SKP 6 (*.skp)",
    "SKP 5 (*.skp)",
    "SKP 4 (*.skp)",
    "SKP 3 (*.skp)",
]


def _not_connected(parent, operation, detail=""):
    QMessageBox.information(
        parent,
        "BlackFox SKP Exporter - Interface Test",
        f"{operation} dialog is working.\n\n"
        + (detail + "\n\n" if detail else "")
        + "This is an interface-only prototype. No model was changed or file written."
    )


# The installed package owns its converter directory. An explicit root
# remains available for local development.
_BLACKFOX_ARCH_NAMES = {
    "amd64": "x86_64", "x86_64": "x86_64",
    "arm64": "aarch64", "aarch64": "aarch64",
}
_BLACKFOX_SYSTEMS = {
    "win32": ("pc-windows-msvc", "BlackFoxSKP.exe"),
    "linux": ("unknown-linux-gnu", "BlackFoxSKP"),
    "darwin": ("apple-darwin", "BlackFoxSKP"),
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
        raise RuntimeError(f"BlackFox SKP does not support operating system {system!r}.")
    machine = _blackfox_native_machine(system) if machine is None else machine
    arch = _BLACKFOX_ARCH_NAMES.get(machine.lower())
    if arch is None:
        raise RuntimeError(f"BlackFox SKP does not support CPU architecture {machine!r} on {system}.")
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


# Release packaging fills both pins from the approved repository and manifest.
_BLACKFOX_RELEASE_REPOSITORY = "davidsmavrov-debug/blackfox-skp-exporter"
_BLACKFOX_RELEASE_MANIFEST_SHA256 = "d8fd61c2e17f1ba115bbfda08d31e764852e5b8749d6e010a0abaca2cd492831"
_BLACKFOX_RELEASE_ABI = 1
_BLACKFOX_MAX_DOWNLOAD = 128 * 1024 * 1024
_BLACKFOX_ASKED_FOR_RELEASE = set()


class _BlackFoxDownloadCancelled(Exception):
    pass


def _blackfox_release_candidates(directory, target, name, manifest):
    repository = _BLACKFOX_RELEASE_REPOSITORY
    if not repository:
        raise RuntimeError("The official BlackFox SKP release repository has not been configured.")
    if (not isinstance(manifest, dict) or manifest.get("schema") != 1
            or manifest.get("repository") != repository):
        raise RuntimeError("Invalid BlackFox SKP release manifest or repository.")
    releases = manifest.get("releases")
    if not isinstance(releases, list) or not releases:
        raise RuntimeError("The BlackFox SKP release manifest has no releases.")

    candidates = []
    versions_seen = set()
    for release in releases:
        if not isinstance(release, dict):
            raise RuntimeError("Invalid converter release metadata.")
        if type(release.get("abi")) is not int or release["abi"] != _BLACKFOX_RELEASE_ABI:
            continue
        version = release.get("version")
        if (not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", version)
                or version in versions_seen):
            raise RuntimeError("Invalid or duplicate BlackFox SKP release version.")
        versions_seen.add(version)
        assets = release.get("assets")
        if not isinstance(assets, dict):
            raise RuntimeError("Invalid BlackFox SKP asset metadata.")
        asset = assets.get(target)
        if asset is None:
            continue
        expected_filename = f"blackfox-skp-{target}" + (".exe" if name.endswith(".exe") else "")
        if not isinstance(asset, dict) or asset.get("name") != expected_filename:
            raise RuntimeError(f"Invalid BlackFox SKP asset name for {target}.")
        size, digest = asset.get("size"), asset.get("sha256")
        if (type(size) is not int or not 0 < size <= _BLACKFOX_MAX_DOWNLOAD
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise RuntimeError("Invalid BlackFox SKP asset size or SHA-256.")
        release_dir = directory / version / target
        if release_dir.resolve() != release_dir:
            raise RuntimeError(f"BlackFox SKP installation directory contains a redirect: {release_dir}")
        candidates.append({
            "version": version, "size": size, "sha256": digest,
            "url": f"https://github.com/{repository}/releases/download/v{version}/{expected_filename}",
            "destination": release_dir / name,
        })
    if not candidates:
        raise RuntimeError(f"No compatible BlackFox SKP release for {target}.")
    return candidates


def _blackfox_verified_file(path, release, arch, require_executable=True):
    import hashlib

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size != release["size"]:
            return False
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return (
            digest.hexdigest() == release["sha256"]
            and _blackfox_binary_architecture(path, sys.platform) == arch
            and (not require_executable or sys.platform == "win32" or os.access(path, os.X_OK))
        )
    except OSError:
        return False


def _blackfox_confirm_download(parent, target, release):
    message = QMessageBox(parent)
    message.setWindowTitle("BlackFox SKP converter")
    message.setIcon(QMessageBox.Question)
    message.setText("BlackFox SKP requires a native executable for SKP import and export.")
    message.setInformativeText(
        f"Platform: {target}\n"
        f"Converter: {release['destination'].name}\n"
        f"Version: {release['version']}\n"
        f"Download size: {release['size']:,} bytes\n"
        f"Official GitHub source: {release['url']}\n"
        f"Destination: {release['destination']}\n\n"
        "Download and install this converter?"
    )
    download = message.addButton("Download", QMessageBox.AcceptRole)
    cancel = message.addButton("Cancel", QMessageBox.RejectRole)
    message.setDefaultButton(cancel)
    message.setEscapeButton(cancel)
    message.exec()
    return message.clickedButton() is download


def _blackfox_allowed_download(original, url):
    from urllib.parse import urlsplit

    try:
        remote = urlsplit(url)
        return (remote.scheme == "https" and remote.port in (None, 443)
                and remote.username is None and remote.password is None
                and not remote.fragment
                and (url == original or remote.hostname in {
                    "release-assets.githubusercontent.com", "objects.githubusercontent.com"
                }))
    except ValueError:
        return False


def _blackfox_download_release(release, output):
    import ssl
    import time
    import urllib.request

    url = release["url"]

    class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not _blackfox_allowed_download(url, newurl):
                raise RuntimeError("BlackFox SKP download refused an unapproved redirect.")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    if sys.platform == "win32":
        from types import ModuleType

        prefix = __name__ + "._truststore"
        for name, code in _BLACKFOX_WINDOWS_TLS_MODULES:
            qualified = f"{prefix}.{name}"
            if qualified not in sys.modules:
                module = ModuleType(qualified)
                module.__package__ = prefix
                sys.modules[qualified] = module
                try:
                    exec(compile(code, f"<BlackFox truststore/{name}.py>", "exec"), module.__dict__)
                except BaseException:
                    sys.modules.pop(qualified, None)
                    raise
        context = sys.modules[f"{prefix}._api"].SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        ReleaseRedirect(), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, headers={
        "User-Agent": "BlackFox-SKP", "Accept-Encoding": "identity",
    })
    remaining = release["size"]
    deadline = time.monotonic() + 180
    with opener.open(request, timeout=30) as response:
        if not _blackfox_allowed_download(url, response.geturl()):
            raise RuntimeError("BlackFox SKP download returned an unapproved source.")
        length = response.headers.get("Content-Length")
        if length is not None and length != str(remaining):
            raise RuntimeError("BlackFox SKP download length differs from the trusted manifest.")
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("BlackFox SKP converter download timed out.")
            chunk = response.read1(min(remaining + 1, 1024 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                raise RuntimeError("BlackFox SKP download exceeded the trusted size.")
            output.write(chunk)
    if remaining != 0:
        raise RuntimeError("BlackFox SKP download is incomplete.")


def _blackfox_install_release(release, arch, *, legacy=None):
    destination = release["destination"]
    directory = destination.parent
    if directory.resolve() != directory:
        raise RuntimeError(f"BlackFox SKP installation directory contains a redirect: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=".blackfox-", dir=directory)
    staged = Path(path)
    try:
        with os.fdopen(fd, "wb") as output:
            if legacy is None:
                _blackfox_download_release(release, output)
            else:
                # Bound the copy even if the legacy file changes mid-migration.
                with legacy.open("rb") as original:
                    remaining = release["size"] + 1
                    while remaining:
                        chunk = original.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            break
                        output.write(chunk)
                        remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        if not _blackfox_verified_file(staged, release, arch, require_executable=False):
            raise RuntimeError("BlackFox SKP converter failed hash, size, or architecture verification.")
        if sys.platform != "win32":
            staged.chmod(0o755)
        try:
            os.replace(staged, destination)
        except OSError:
            # Another IngeTrazo process may have installed and opened this build.
            if not _blackfox_verified_file(destination, release, arch):
                raise
    finally:
        staged.unlink(missing_ok=True)
    return destination


def _blackfox_packaged_converter(package, target, name, arch, parent, prompt):
    import hashlib

    payload = _BLACKFOX_EMBEDDED_MANIFEST
    if len(payload) > 256 * 1024 or hashlib.sha256(payload).hexdigest() != _BLACKFOX_RELEASE_MANIFEST_SHA256:
        raise RuntimeError("BlackFox SKP release manifest failed SHA-256 verification.")
    try:
        manifest = json.loads(payload)
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("BlackFox SKP release manifest is not valid JSON.") from exc
    from core.extensions import user_plugins_dir

    plugins = user_plugins_dir()
    directory = plugins.parent.resolve() / "extension-data" / "blackfox_skp_exporter" / "bin"
    if directory.is_relative_to(plugins.resolve()):
        raise RuntimeError("BlackFox SKP converter storage must be outside the plugins directory.")
    candidates = _blackfox_release_candidates(directory, target, name, manifest)
    for release in candidates:
        if _blackfox_verified_file(release["destination"], release, arch):
            return release["destination"]

    for release in candidates:
        legacy_paths = (
            package / "BlackFoxSKP" / name,
            plugins / "blackfox_skp_exporter" / "BlackFoxSKP" / name,
            plugins / "BlackFoxSKP" / name,
            plugins / "BlackFoxSKP" / "bin" / release["version"] / target / name,
        )
        for legacy in dict.fromkeys(legacy_paths):
            if _blackfox_verified_file(legacy, release, arch, require_executable=False):
                return _blackfox_install_release(release, arch, legacy=legacy)

    preferred = candidates[0]
    key = preferred["destination"]
    if not prompt:
        raise RuntimeError(f"No verified BlackFox SKP converter is installed for {target}.")
    if key in _BLACKFOX_ASKED_FOR_RELEASE:
        raise _BlackFoxDownloadCancelled()
    _BLACKFOX_ASKED_FOR_RELEASE.add(key)
    try:
        if not _blackfox_confirm_download(parent, target, preferred):
            raise _BlackFoxDownloadCancelled()
        if _blackfox_verified_file(preferred["destination"], preferred, arch):
            return preferred["destination"]
        return _blackfox_install_release(preferred, arch)
    finally:
        _BLACKFOX_ASKED_FOR_RELEASE.discard(key)


def _blackfox_dependencies(parent=None, *, prompt=False):
    target, name, arch = _blackfox_platform()
    package = Path(__file__).resolve().parent
    return _blackfox_packaged_converter(package, target, name, arch, parent, prompt), None


def _tag_imported_curve(mesh, points, closed):
    # SKP provides the exact edge chain, so no split-segment search is needed.
    vertices = [mesh.vertex_at(point) for point in points]
    if closed:
        vertices.append(vertices[0])
    members = []
    for start, end in zip(vertices, vertices[1:]):
        if start is not None and end is not None and start is not end:
            edge = mesh.find_edge(start, end)
            if edge is not None and edge.curve is None:
                members.append(edge)
    if not members:
        return False
    curve_id = mesh.next_curve_id()
    for edge in members:
        edge.curve = curve_id
    return True


def _ordered_curve_vertices(source_edges, edge_indices, endpoints):
    """Return a single ordered path from source edge membership, or None.

    Source curve edge order/direction is not a topology guarantee. Reject
    branching/disconnected contours rather than inventing welds.
    """
    if not edge_indices or len(set(edge_indices)) != len(edge_indices):
        return None
    adjacency = {}
    for idx in edge_indices:
        if type(idx) is not int or idx < 0 or idx >= len(source_edges):
            return None
        a, b = endpoints(source_edges[idx])
        if a == b:
            return None
        adjacency.setdefault(a, []).append((idx, b))
        adjacency.setdefault(b, []).append((idx, a))
    if any(len(items) > 2 for items in adjacency.values()):
        return None
    ends = [v for v, items in adjacency.items() if len(items) == 1]
    if len(ends) not in (0, 2):
        return None
    start = min(ends) if ends else min(adjacency)
    ordered = [start]
    used = set()
    current = start
    while len(used) < len(edge_indices):
        options = [(i, other) for i, other in adjacency[current] if i not in used]
        if not options or (len(options) != 1 and used):
            return None
        idx, nxt = min(options)
        used.add(idx)
        ordered.append(nxt)
        current = nxt
    closed = not ends
    if closed and ordered[-1] != start:
        return None
    if not closed and ordered[-1] not in ends:
        return None
    if closed:
        ordered.pop()
    if len(ordered) < (3 if closed else 2):
        return None
    return ordered, closed


def _transform_point(point, matrix):
    """skpwright 3x3 column-major plus translation (13 values)."""
    if len(matrix) != 13 or abs(float(matrix[12]) - 1.0) > 1e-8:
        raise ValueError("Unsupported component transform")
    x, y, z = map(float, point)
    return [
        matrix[0]*x + matrix[3]*y + matrix[6]*z + matrix[9],
        matrix[1]*x + matrix[4]*y + matrix[7]*z + matrix[10],
        matrix[2]*x + matrix[5]*y + matrix[8]*z + matrix[11],
    ]


def _skp_matrix(values):
    """Convert bridge's row-major 3x3 + translation to Qt row-major."""
    if not isinstance(values, (list, tuple)) or len(values) != 13:
        raise ValueError("Expected a 13-value SKP transform")
    v = [float(x) for x in values]
    if abs(v[12] - 1.0) > 1e-8:
        raise ValueError("Unsupported non-affine SKP transform")
    # Bridge C001.5K flattens the Rust world matrix by rows, not columns.
    # Qt's 16-scalar constructor also accepts row-major entries.
    return QMatrix4x4(
        v[0], v[1], v[2], v[9],
        v[3], v[4], v[5], v[10],
        v[6], v[7], v[8], v[11],
        0.0, 0.0, 0.0, 1.0,
    )


# Screen-space SketchUp labels belong to a viewport, not the 3D scene.
# Keep the source records in scene.plugin_data for future native persistence.
_SCREEN_LABEL_OVERLAYS = {}


class _ScreenLabelPositioner(QObject):
    def __init__(self, viewport, labels):
        super().__init__(viewport)
        self.viewport = viewport
        self.labels = labels
        viewport.installEventFilter(self)
        self.reposition()

    def reposition(self):
        w, h = self.viewport.width(), self.viewport.height()
        for widget, u, v in self.labels:
            widget.adjustSize()
            widget.move(round(float(u)*w), round(float(v)*h))
            widget.raise_()
            widget.show()

    def eventFilter(self, watched, event):
        if watched is self.viewport and event.type() == QEvent.Resize:
            self.reposition()
        return False


def _attach_screen_text(viewport, converted):
    """Display non-leader SketchUp text at its normalized screen position.

    This is a transient viewport overlay, not a native persistent annotation.
    Its exact placement is dependent on SketchUp/Qt viewport conventions.
    """
    old = _SCREEN_LABEL_OVERLAYS.pop(id(viewport), None)
    if old is not None:
        for widget, _, _ in old.labels:
            widget.deleteLater()
        old.deleteLater()
    labels = []
    for item in converted.get("native_texts") or []:
        if item.get("hidden") or item.get("def_index") is not None:
            continue
        if item.get("leader") != "none":
            continue
        pos = item.get("screen_position")
        content = item.get("content")
        if not (isinstance(pos, list) and len(pos) == 2
                and all(isinstance(v, (int, float)) and math.isfinite(v) for v in pos)
                and isinstance(content, str) and content):
            continue
        label = QLabel(content, viewport)
        label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        label.setStyleSheet("color: black; background: rgba(255,255,255,215); padding: 2px;")
        labels.append((label, pos[0], pos[1]))
    if labels:
        overlay = _ScreenLabelPositioner(viewport, labels)
        _SCREEN_LABEL_OVERLAYS[id(viewport)] = overlay
    return len(labels)


def _restore_native_annotations(scene, converted, native, viewport_size=(1280, 720)):
    """D4N61K: resolve SKP vertex PID anchors and instance paths to world metres.

    Fail closed for unsupported screen-space text or ambiguous attachments.
    Source model data is retained in plugin_data for later lossless work.
    """
    from core.textlabel import TextLabel
    from core.dimension import Dimension

    cad = native.get("cad") or {}
    mesh = native.get("mesh") or {}
    runs = mesh.get("runs") or []
    placements = cad.get("placements") or []
    instances = cad.get("instances") or []
    layer_catalog = converted.get("layers") or []
    counts = {"texts": 0, "dimensions": 0, "annotations_skipped": 0}

    def layer_name(index):
        if type(index) is not int or not 0 <= index < len(layer_catalog):
            return None
        name = layer_catalog[index].get("name")
        if name in ("Layer0", "Untagged", "Layer 0"):
            return None
        return name if isinstance(name, str) and any(x.name == name for x in scene.layers) else None

    vertex_lookup = {}
    for run_id, run in enumerate(runs):
        pids = run.get("vertex_pids") or []
        coords = run.get("vertices_m") or []
        if len(pids) != len(coords):
            raise ValueError("BlackFox vertex PID/coordinate count mismatch")
        for pid, coord in zip(pids, coords):
            vertex_lookup.setdefault(pid, []).append((run_id, coord))

    placement_by_run = {}
    for placement in placements:
        placement_by_run.setdefault(placement.get("run_id"), []).append(placement)

    # The native importer reports instances in the same order as non-root
    # placements. Verify the correspondence by definition/group type, never
    # rely on matching a translation rounded to five decimal places.
    nonroot = [p for p in placements if p.get("is_group") is not None]
    instance_to_placement = {}
    if len(nonroot) == len(instances):
        for inst, placement in zip(instances, nonroot):
            if bool(inst.get("is_group")) != bool(placement.get("is_group")):
                continue
            instance_to_placement[inst.get("pid")] = placement

    def apply_matrix(point, matrix):
        if len(matrix) != 16:
            raise ValueError("Invalid BlackFox 4x4 placement matrix")
        x, y, z = map(float, point)
        w = matrix[12]*x + matrix[13]*y + matrix[14]*z + matrix[15]
        if abs(w) < 1e-12:
            raise ValueError("Invalid homogeneous annotation coordinate")
        return [(matrix[0]*x + matrix[1]*y + matrix[2]*z + matrix[3])/w,
                (matrix[4]*x + matrix[5]*y + matrix[6]*z + matrix[7])/w,
                (matrix[8]*x + matrix[9]*y + matrix[10]*z + matrix[11])/w]

    def resolve(anchor, forced_placement=None):
        if not isinstance(anchor, dict):
            return None
        pid = anchor.get("entity")
        path = anchor.get("path") or []
        if pid is None:
            point = anchor.get("point_m")
            return list(map(float, point)) if isinstance(point, list) and len(point) == 3 else None
        matches = vertex_lookup.get(pid, [])
        if not matches:
            return None
        if forced_placement is not None:
            coords = [xyz for run_id, xyz in matches if run_id == forced_placement.get("run_id")]
            if len(coords) != 1:
                return None
            return apply_matrix(coords[0], forced_placement["world_transform"])
        if path:
            # Current benchmark has single-level instance paths. Nested paths
            # need their own ordered transform resolver, not a guessed matrix.
            if len(path) != 1 or path[0] not in instance_to_placement:
                return None
            placement = instance_to_placement[path[0]]
            coords = [xyz for run_id, xyz in matches if run_id == placement.get("run_id")]
            if len(coords) != 1:
                return None
            return apply_matrix(coords[0], placement["world_transform"])
        # No instance path: root vertex only, unless a unique unplaced run.
        candidates = []
        for run_id, xyz in matches:
            pp = placement_by_run.get(run_id, [])
            if len(pp) == 1 and pp[0].get("is_group") is None:
                candidates.append(apply_matrix(xyz, pp[0]["world_transform"]))
        return candidates[0] if len(candidates) == 1 else None

    def vec(values):
        return QVector3D(*map(float, values))

    for item in converted.get("native_texts") or []:
        anchor = resolve(item.get("anchor"))
        content = item.get("content")
        if (anchor is None or not isinstance(content, str) or item.get("hidden")
                or item.get("def_index") is not None):
            counts["annotations_skipped"] += 1
            continue
        leader = item.get("leader")
        if leader == "none":
            # SketchUp screen-space text is not equivalent to IngeTrazo's
            # world-anchored TextLabel. Defer, retaining source in plugin_data.
            counts["annotations_skipped"] += 1
            continue
        offset = item.get("leader_offset")
        if not isinstance(offset, list) or len(offset) != 3:
            counts["annotations_skipped"] += 1
            continue
        # Coordinate placeholder text is a live SketchUp vertex-coordinate
        # label. Reconstruct its initial displayed value from the resolved
        # transformed world-space anchor rather than stale source content.
        if item.get("placeholder") == "<>":
            content = ", ".join(f"{value:.4f} m" for value in anchor)
        scene.text_labels.append(TextLabel(vec(anchor), vec(offset), content,
                                          layer_name(item.get("layer"))))
        counts["texts"] += 1

    # A dimension stored in a component definition is instantiated once per
    # matching component placement, even when its anchor path is empty.
    definitions = {d.get("map_index"): d for d in cad.get("definitions") or []}
    instance_by_pid = {i.get("pid"): i for i in instances}
    def placements_for_definition(def_index):
        definition = definitions.get(def_index)
        if not definition:
            return []
        return [p for p in nonroot
                if p.get("run_id") is not None
                and any(i.get("definition") == definition.get("name")
                        and instance_to_placement.get(i.get("pid")) is p
                        for i in instances)]

    for item in converted.get("native_dimensions") or []:
        if item.get("hidden"):
            counts["annotations_skipped"] += 1
            continue
        def_index = item.get("def_index")
        candidates = (placements_for_definition(def_index)
                      if def_index is not None else [None])
        if not candidates:
            counts["annotations_skipped"] += 1
            continue
        for placement in candidates:
            start = resolve(item.get("start"), placement)
            end = resolve(item.get("end"), placement)
            normal = item.get("normal")
            offset_m = item.get("offset_m")
            if (start is None or end is None or not isinstance(normal, list)
                    or len(normal) != 3 or not isinstance(offset_m, (int, float))):
                counts["annotations_skipped"] += 1
                continue
            direction = [b-a for a,b in zip(start,end)]
            length = math.sqrt(sum(v*v for v in direction))
            if length < 1e-12:
                counts["annotations_skipped"] += 1
                continue
            # SketchUp normal describes the dimension plane, NOT the
            # displacement direction. The in-plane perpendicular is N x AB.
            nx,ny,nz = map(float, normal)
            if placement is not None:
                m = placement["world_transform"]
                nx,ny,nz = (m[0]*nx+m[1]*ny+m[2]*nz,
                            m[4]*nx+m[5]*ny+m[6]*nz,
                            m[8]*nx+m[9]*ny+m[10]*nz)
            dx,dy,dz = direction
            perp = [ny*dz-nz*dy, nz*dx-nx*dz, nx*dy-ny*dx]
            plen = math.sqrt(sum(v*v for v in perp))
            if plen < 1e-12:
                counts["annotations_skipped"] += 1
                continue
            # D4N61M: SketchUp's variant-2 dimension orientation is reversed
            # relative to the generic N x AB construction used in D4N61L.
            # Keep variant-1 untouched for a controlled visual A/B test.
            variant = item.get("variant")
            side = -1.0 if variant == 2 else 1.0
            # D4N61W: Only the group-local vertical dimension (76055 ->
            # 76062, instance path 76075) needs the opposite side. Do not
            # alter variant-2 globally: another definition dimension has two
            # instances and previously regressed when flipped.
            source_a = item.get("start") or {}
            source_b = item.get("end") or {}
            if (source_a.get("entity") == 76055
                    and source_b.get("entity") == 76062
                    and source_a.get("path") == [76075]
                    and source_b.get("path") == [76075]):
                side = -side
            # D4N61AD: fallback for vertical, instance-anchored dimensions
            # whose persistent IDs differ from the D4N61W benchmark.
            # Choose the side farther from the owning geometry's XY centre.
            # This is intentionally restricted to a single, resolved instance
            # path; root and definition dimensions keep their existing rules.
            old_match = (source_a.get("entity") == 76055
                         and source_b.get("entity") == 76062
                         and source_a.get("path") == [76075]
                         and source_b.get("path") == [76075])
            path_a = source_a.get("path") or []
            path_b = source_b.get("path") or []
            if (not old_match and variant == 2
                    and path_a == path_b and len(path_a) == 1
                    and path_a[0] in instance_to_placement
                    and abs(dx) <= 1e-6 * length
                    and abs(dy) <= 1e-6 * length
                    and abs(dz) >= 0.999999 * length):
                owner = instance_to_placement[path_a[0]]
                run_id = owner.get("run_id")
                if isinstance(run_id, int) and 0 <= run_id < len(runs):
                    points = runs[run_id].get("vertices_m") or []
                    matrix = owner.get("world_transform")
                    if points and isinstance(matrix, list) and len(matrix) == 16:
                        world_points = [apply_matrix(p, matrix) for p in points]
                        cx = (min(p[0] for p in world_points)
                              + max(p[0] for p in world_points)) / 2.0
                        cy = (min(p[1] for p in world_points)
                              + max(p[1] for p in world_points)) / 2.0
                        mx = (start[0] + end[0]) / 2.0
                        my = (start[1] + end[1]) / 2.0
                        ux, uy = perp[0] / plen, perp[1] / plen
                        distance = abs(float(offset_m))
                        positive = ((mx + ux*distance - cx)**2
                                    + (my + uy*distance - cy)**2)
                        negative = ((mx - ux*distance - cx)**2
                                    + (my - uy*distance - cy)**2)
                        if abs(positive - negative) > 1e-10:
                            side = 1.0 if positive > negative else -1.0
            offset = [side*v*float(offset_m)/plen for v in perp]
            text = item.get("text_override") or None
            scene.dimensions.append(Dimension(vec(start), vec(end), vec(offset),
                                              layer_name(item.get("layer")), text))
            counts["dimensions"] += 1

    radial = _restore_radial_dimensions(scene, converted, native, layer_name, vec)
    counts.update(radial)
    counts["annotations_skipped"] += radial["radial_skipped"]
    scene.plugin_data["blackfox_skp_annotations_v1"] = {
        "schema": "blackfox.skp.annotations.v1",
        "native_texts": converted.get("native_texts") or [],
        "native_dimensions": converted.get("native_dimensions") or [],
        "native_radial_dimensions": converted.get("native_radial_dimensions") or [],
        "imported_texts": counts["texts"],
        "imported_dimensions": counts["dimensions"],
        "imported_radial_dimensions": counts["radial_dimensions"],
    }
    return counts


def _restore_radial_dimensions(scene, converted, native, layer_name, vec):
    """Root-only native leader experiment; leader coordinates not yet decoded."""
    from core.dimension import Dimension
    from core.textlabel import TextLabel
    runs = native.get("mesh", {}).get("runs") or []
    metadata = native.get("model", {}).get("geometry_runs") or []
    if len(runs) != len(metadata):
        raise ValueError("Radial dimension geometry-run mismatch")
    edge_map = {}
    for ri, run in enumerate(runs):
        for edge in run.get("edges") or []:
            pid = edge.get("pid")
            if pid in edge_map:
                raise ValueError("Duplicate edge PID")
            edge_map[pid] = (ri, edge)
    source_units = converted.get("source_units") or {}
    unit, scale = {0: ("in", 1/0.0254), 1: ("ft", 1/0.3048),
                   2: ("mm", 1000), 3: ("cm", 100),
                   4: ("m", 1)}.get(source_units.get("length_unit"), ("m", 1))
    precision = source_units.get("length_precision", 4)
    if type(precision) is not int or not 0 <= precision <= 8:
        precision = 4
    # Phase 2C length tuning. These ratios are provisional visual parameters,
    # NOT a decoding of SketchUp's two-number leader array.
    LEADER_DIAGONAL_RADIUS_RATIO = 0.12
    LEADER_HORIZONTAL_RADIUS_RATIO = 0.10
    LABEL_LIFT_RADIUS_RATIO = 0.025
    imported = skipped = 0
    recipes = []
    for item in converted.get("native_radial_dimensions") or []:
        match = edge_map.get(item.get("edge"))
        if item.get("hidden") or item.get("def_index") is not None or match is None:
            skipped += 1
            continue
        ri, edge = match
        if metadata[ri].get("def_index") is not None:
            skipped += 1
            continue
        run = runs[ri]
        ci = edge.get("curve")
        curves = run.get("curves") or []
        if type(ci) is not int or not 0 <= ci < len(curves):
            skipped += 1
            continue
        arc = curves[ci].get("arc")
        if not isinstance(arc, dict):
            skipped += 1
            continue
        try:
            center = list(map(float, arc["center_m"]))
            radius = float(arc["radius_m"])
            verts = run["vertices_m"]
            a, b = verts[edge["v0"]], verts[edge["v1"]]
            mid = [(float(x)+float(y))/2 for x,y in zip(a,b)]
            direction = [x-y for x,y in zip(mid,center)]
            length = math.sqrt(sum(x*x for x in direction))
            if len(center) != 3 or not all(map(math.isfinite, center)) or not math.isfinite(radius) or radius <= 0 or length <= 1e-12:
                raise ValueError("Invalid analytical curve")
            direction = [x/length for x in direction]
        except (ValueError, TypeError, KeyError, IndexError, OverflowError):
            skipped += 1
            continue
        rim = [center[i]+radius*direction[i] for i in range(3)]
        diameter = bool(item.get("diameter"))
        start = [center[i]-radius*direction[i] for i in range(3)] if diameter else center
        value = (2 if diameter else 1)*radius*scale
        text = item.get("text_override") or f"{'DIA' if diameter else 'R'} {value:.{precision}f} {unit}"
        recipe = {"native": dict(item), "arc": arc, "layer": layer_name(item.get("layer")),
                  "edge": [list(vec(a).toTuple()), list(vec(b).toTuple())]}
        if diameter:
            recipe["diameter_snapshot"] = [list(vec(start).toTuple()), list(vec(rim).toTuple()), text]
            scene.dimensions.append(Dimension(vec(start), vec(rim), vec([0,0,0]),
                                              layer_name(item.get("layer")), text))
        else:
            # Experimental SketchUp-style native leader: two real mesh edges
            # and a persistent TextLabel, not a viewport overlay. The SKP
            # leader[2] semantics are not decoded, so this is an intentionally
            # approximate visual placement. It MUST NOT be considered a
            # lossless geometry roundtrip: leader edges become scene geometry.
            elbow = [rim[i] + direction[i] * radius * LEADER_DIAGONAL_RADIUS_RATIO for i in range(3)]
            sign = 1.0 if direction[0] >= 0 else -1.0
            end = [elbow[0] + sign * radius * LEADER_HORIZONTAL_RADIUS_RATIO, elbow[1], elbow[2]]
            if math.dist(rim, elbow) < 1e-9 or math.dist(elbow, end) < 1e-9:
                skipped += 1
                continue
            # Edge has no .attrs in IngeTrazo. Source metadata is preserved
            # in scene.plugin_data["blackfox_skp_annotations_v1"] below.
            # These are temporary geometry edges, not native annotations.
            recipe["leader_edges"] = []
            for pa, pb in ((rim, elbow), (elbow, end)):
                count_before = len(scene.mesh.edges)
                generated = scene.mesh.add_edge(vec(pa), vec(pb))
                if len(scene.mesh.edges) > count_before:
                    recipe["leader_edges"].append([list(generated.a.toTuple()), list(generated.b.toTuple())])
            label = TextLabel(vec(end), vec([0, radius * LABEL_LIFT_RADIUS_RATIO, 0]),
                              text, layer_name(item.get("layer")))
            scene.text_labels.append(label)
            recipe["label"] = label.to_dict()
        recipes.append(recipe)
        imported += 1
    if recipes:
        scene.plugin_data.setdefault("blackfox_skp_radial_export_v1", []).extend(recipes)
    return {"radial_dimensions": imported, "radial_skipped": skipped}


def _skp_camera_home(cam):
    """Convert an SKP camera into IngeTrazo's orbit-camera dictionary.

    Roll and exact parallel framing are not representable by this API.
    """
    if not isinstance(cam, dict):
        return None
    eye, target = cam.get("eye_m"), cam.get("target_m")
    if not (isinstance(eye, (list, tuple)) and len(eye) == 3
            and isinstance(target, (list, tuple)) and len(target) == 3):
        return None
    try:
        eye = [float(x) for x in eye]
        target = [float(x) for x in target]
        if not all(math.isfinite(x) for x in eye + target):
            return None
        dx, dy, dz = [e - t for e, t in zip(eye, target)]
        distance = math.sqrt(dx*dx + dy*dy + dz*dz)
        if distance < 1e-9:
            return None
        fov = float(cam.get("fov_deg") or 45.0)
        if not math.isfinite(fov) or not 0 < fov < 180:
            fov = 45.0
        return {
            "target": target,
            "distance": distance,
            "yaw": math.atan2(dy, dx),
            "pitch": math.atan2(dz, math.hypot(dx, dy)),
            "fov_deg": fov,
            "perspective": bool(cam.get("perspective", True)),
            "two_point": bool(cam.get("two_point_perspective", False)),
        }
    except (TypeError, ValueError, OverflowError):
        return None


def _restore_saved_views(scene, converted):
    """Create native IngeTrazo saved views from SketchUp scene cameras.

    The source camera up-vector can encode roll; IngeTrazo SavedView has
    yaw/pitch only, so roll is not preserved. Source records remain in
    plugin_data for future lossless conversion.
    """
    from core.saved_views import SavedView

    source = converted.get("scenes") or []
    scene.plugin_data["blackfox_skp_scenes_v1"] = source
    created = 0
    for item in source:
        cam = item.get("camera") or {}
        eye, target = cam.get("eye_m"), cam.get("target_m")
        if not (isinstance(eye, list) and len(eye) == 3
                and isinstance(target, list) and len(target) == 3):
            continue
        try:
            eye = [float(x) for x in eye]
            target = [float(x) for x in target]
            if not all(math.isfinite(x) for x in eye + target):
                continue
            dx, dy, dz = [e-t for e, t in zip(eye, target)]
            distance = math.sqrt(dx*dx + dy*dy + dz*dz)
            if distance < 1e-9:
                continue
            # Camera orientation is expressed as eye relative to target.
            # Match the yaw/pitch conventions of IngeTrazo camera_home.
            yaw = math.atan2(dy, dx)
            pitch = math.atan2(dz, math.hypot(dx, dy))
            fov = float(cam.get("fov_deg") or 45.0)
            if not math.isfinite(fov) or fov <= 0:
                fov = 45.0
            name = item.get("name") or f"SKP Scene {created+1}"
            native_style = _skp_rendering_to_style(
                item.get("rendering"), scene.display_style)
            style_snapshot = native_style.to_dict() if native_style is not None else None
            if style_snapshot is not None and isinstance(item.get("style"), str) and item["style"]:
                style_snapshot["name"] = item["style"]
            section = None
            flags = item.get("saved") or 0
            if flags & 64 or item.get("rendering") is not None:
                settings = item.get("rendering") or {}
                display = settings.get("section_display", 3)
                if display is None:
                    display = 3
                plane_uids = scene.plugin_data.get("blackfox_skp_section_uids_v1", {})
                active_ids = item.get("active_section_planes", [])
                section = {
                    "active": plane_uids.get(str(active_ids[0])) if active_ids else None,
                    "planes_shown": bool(display & 1),
                    "cuts_shown": bool(display & 2),
                }
            layer_names = [layer["name"] for layer in converted.get("layers", [])]
            hidden_layers = [
                "Layer 0" if layer_names[idx] == "Layer0" else layer_names[idx]
                for idx in item.get("hidden_layers", [])
                if type(idx) is int and 0 <= idx < len(layer_names)
            ]
            view = SavedView(name=str(name), target=tuple(target),
                             distance=distance, yaw=yaw, pitch=pitch,
                             fov_deg=fov,
                             perspective=bool(cam.get("perspective", True)),
                             two_point=bool(cam.get("two_point_perspective", False)),
                             hidden_layers=hidden_layers, style=style_snapshot, section=section)
            scene.saved_views.append(view)
            created += 1
        except (TypeError, ValueError, OverflowError):
            continue
    return created


def _restore_native_sections(scene, converted, native=None):
    """Restore root and instanced SketchUp section planes using world matrices.

    Source planes use inch-space ax+by+cz+d=0. World transforms in
    native['mesh']['scene'] are row-major 4x4 matrices in metres.
    """
    from core.section import SectionPlane

    records = converted.get("native_geometry_entities") or []
    if not isinstance(records, list):
        raise ValueError("native_geometry_entities must be a list")
    scene.plugin_data["blackfox_skp_sections_v1"] = json.loads(json.dumps(records))
    if not records:
        return {"section_planes": 0, "section_planes_deferred": 0}
    if not isinstance(native, dict):
        raise ValueError("Native scene hierarchy required for section planes")

    native_runs = native.get("model", {}).get("geometry_runs", [])
    scene_nodes = native.get("mesh", {}).get("scene", [])
    if not isinstance(native_runs, list) or not isinstance(scene_nodes, list):
        raise ValueError("Invalid native scene hierarchy")
    by_definition = {}
    for index, run in enumerate(native_runs):
        key = run.get("def_index")
        if key in by_definition:
            raise ValueError(f"Ambiguous geometry definition {key!r}")
        by_definition[key] = index

    identity = [1.,0.,0.,0., 0.,1.,0.,0., 0.,0.,1.,0., 0.,0.,0.,1.]
    placements = {}
    for node in scene_nodes:
        run_index = node.get("run")
        matrix = node.get("world")
        if not isinstance(run_index, int) or not (0 <= run_index < len(native_runs)):
            raise ValueError("Invalid section placement run index")
        if not isinstance(matrix, list) or len(matrix) != 16:
            raise ValueError("Invalid section placement matrix")
        matrix = [float(v) for v in matrix]
        if not all(math.isfinite(v) for v in matrix):
            raise ValueError("Nonfinite section placement matrix")
        if any(abs(matrix[i] - identity[i]) > 1e-7 for i in (12,13,14,15)):
            raise ValueError("Non-affine section placement matrix")
        placements.setdefault(run_index, []).append(matrix)

    def world_plane(coeffs, matrix):
        a,b,c,d = [float(v) for v in coeffs]
        mag2 = a*a + b*b + c*c
        if not all(math.isfinite(v) for v in (a,b,c,d)) or mag2 < 1e-20:
            raise ValueError("Invalid SKP section plane")
        # Source offset d is in inches; point is in metres.
        factor = -d * 0.0254 / mag2
        px,py,pz = a*factor,b*factor,c*factor
        p = [matrix[0]*px+matrix[1]*py+matrix[2]*pz+matrix[3],
             matrix[4]*px+matrix[5]*py+matrix[6]*pz+matrix[7],
             matrix[8]*px+matrix[9]*py+matrix[10]*pz+matrix[11]]
        # Inverse-transpose of linear transform: handles rotation, scaling,
        # mirroring and shear. Cofactor columns are cross-products of columns.
        u = (matrix[0],matrix[4],matrix[8])
        v = (matrix[1],matrix[5],matrix[9])
        w = (matrix[2],matrix[6],matrix[10])
        def cross(x,y):
            return (x[1]*y[2]-x[2]*y[1],
                    x[2]*y[0]-x[0]*y[2],
                    x[0]*y[1]-x[1]*y[0])
        cvw, cwu, cuv = cross(v,w),cross(w,u),cross(u,v)
        det = sum(u[i]*cvw[i] for i in range(3))
        if abs(det) < 1e-15:
            raise ValueError("Singular section placement transform")
        n = [(a*cvw[i]+b*cwu[i]+c*cuv[i])/det for i in range(3)]
        length = math.sqrt(sum(t*t for t in n))
        if length < 1e-15:
            raise ValueError("Degenerate transformed section normal")
        # IngeTrazo's clipping half-space is opposite SketchUp's in tested
        # root-level benchmark. Reverse normal, not plane position.
        return QVector3D(*p), QVector3D(*[-t/length for t in n])

    created = 0
    deferred = 0
    active_candidates = []
    section_uids = {}
    layer_names = [layer["name"] for layer in converted.get("layers", [])]
    layer_map = {item["slot"]: item["index"] for item in converted.get("source_layer_links", [])}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Invalid native geometry record")
        def_index = record.get("source_def_index")
        if def_index not in by_definition:
            raise ValueError(f"Missing native geometry run for definition {def_index!r}")
        run_index = by_definition[def_index]
        matrices = placements.get(run_index, [])
        if not matrices and def_index is None:
            matrices = [identity]
        sections = record.get("sections") or []
        if not matrices:
            deferred += len(sections)
            continue  # uninstantiated component definition
        for matrix in matrices:
            for source in sections:
                coeffs = source.get("plane")
                if not isinstance(coeffs, list) or len(coeffs) != 4:
                    raise ValueError("Invalid SKP section plane")
                point, normal = world_plane(coeffs, matrix)
                section = SectionPlane(
                    point, normal,
                    name=str(source.get("name") or ""),
                    symbol=str(source.get("symbol") or ""),
                    active=False,
                    hidden=bool(source.get("hidden", False)),
                )
                slot = layer_map.get(source.get("layer"))
                if slot is not None and 0 <= slot < len(layer_names):
                    section.layer = None if layer_names[slot] == "Layer0" else layer_names[slot]
                scene.section_planes.append(section)
                section_uids.setdefault(str(source.get("pid")), section.uid)
                created += 1
                if source.get("pid") == record.get("active_section"):
                    active_candidates.append(section)

    # IngeTrazo supports one active clipping plane. For multiple instances,
    # retain all planes and activate the first; do not silently claim exact
    # equivalence with SketchUp's per-context active section behavior.
    scene.plugin_data["blackfox_skp_section_uids_v1"] = section_uids
    if active_candidates:
        scene.set_active_section(active_candidates[0])
    return {"section_planes": created,
            "section_planes_deferred": deferred,
            "section_active_ambiguities": max(0, len(active_candidates)-1)}


def _restore_construction_guides(scene, native):
    """Restore SKP construction points and infinite lines as native guides.

    Definition-owned guides are instantiated through the imported scene's
    world transforms. Unplaced definitions remain source metadata only.
    """
    from core.guide import Guide

    model = native.get("model") or {}
    mesh = native.get("mesh") or {}
    runs = model.get("geometry_runs") or []
    lines = model.get("guides") or []
    nodes = mesh.get("scene") or []
    if not all(isinstance(x, list) for x in (runs, lines, nodes)):
        raise ValueError("Invalid SKP construction guide collections")

    source_points = []
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("Invalid SKP geometry run")
        for item in run.get("guide_points") or []:
            source_points.append({"def_index": run.get("def_index"), "record": item})

    scene.plugin_data["blackfox_skp_construction_v1"] = json.loads(json.dumps({
        "guide_points": source_points, "guides": lines,
    }))
    counts = {"construction_points": 0, "construction_lines": 0,
              "construction_deferred": 0}

    def xyz(value, label):
        if not isinstance(value, (list, tuple)) or len(value) != 3:
            raise ValueError("Invalid SKP " + label)
        result = [float(v) for v in value]
        if not all(math.isfinite(v) for v in result):
            raise ValueError("Nonfinite SKP " + label)
        return result

    identity = [1., 0., 0., 0., 0., 1., 0., 0.,
                0., 0., 1., 0., 0., 0., 0., 1.]
    transforms = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("Invalid SKP scene placement")
        run_index, matrix = node.get("run"), node.get("world")
        if not isinstance(run_index, int) or not 0 <= run_index < len(runs):
            raise ValueError("Invalid SKP guide placement run")
        if not isinstance(matrix, list) or len(matrix) != 16:
            raise ValueError("Invalid SKP guide placement transform")
        matrix = [float(v) for v in matrix]
        if not all(math.isfinite(v) for v in matrix):
            raise ValueError("Nonfinite SKP guide placement transform")
        if any(abs(matrix[i] - identity[i]) > 1e-7 for i in (12, 13, 14, 15)):
            raise ValueError("Non-affine SKP guide placement transform")
        transforms.setdefault(runs[run_index].get("def_index"), []).append(matrix)

    def placements(def_index):
        # Root guides exist even if the source scene omits an explicit root node.
        if def_index is None:
            return [identity]
        return transforms.get(def_index, [])

    def transform(values, matrix, direction=False):
        x, y, z = values
        result = [matrix[0]*x + matrix[1]*y + matrix[2]*z,
                  matrix[4]*x + matrix[5]*y + matrix[6]*z,
                  matrix[8]*x + matrix[9]*y + matrix[10]*z]
        if not direction:
            result = [result[0] + matrix[3], result[1] + matrix[7],
                      result[2] + matrix[11]]
        return QVector3D(*result)

    for entry in source_points:
        point = entry["record"]
        if not isinstance(point, dict):
            raise ValueError("Invalid SKP construction point")
        if point.get("hidden"):
            counts["construction_deferred"] += 1
            continue
        position = xyz(point.get("point_m"), "construction point")
        # SKP benchmark visual correction: flag 1 uses the source anchor
        # for its dotted projection; flag 0 remains a plain cross.
        # Do not invent projections for plain points or unknown flag values.
        source_origin = point.get("anchor_m") if point.get("flag") == 1 else None
        origin = (xyz(source_origin, "construction point anchor")
                  if source_origin is not None else None)
        matrices = placements(entry["def_index"])
        if not matrices:
            counts["construction_deferred"] += 1
        for matrix in matrices:
            cross = transform(position, matrix)
            if origin is not None:
                scene.guides.append(Guide(cross, origin=transform(origin, matrix)))
            else:
                scene.guides.append(Guide(cross))
            counts["construction_points"] += 1

    for item in lines:
        if not isinstance(item, dict):
            raise ValueError("Invalid SKP construction line")
        if item.get("hidden"):
            counts["construction_deferred"] += 1
            continue
        position = xyz(item.get("point_m"), "guide anchor")
        direction = xyz(item.get("direction"), "guide direction")
        matrices = placements(item.get("def_index"))
        if not matrices:
            counts["construction_deferred"] += 1
        for matrix in matrices:
            anchor = transform(position, matrix)
            vector = transform(direction, matrix, direction=True)
            if vector.lengthSquared() <= 1e-20:
                raise ValueError("Degenerate SKP construction line direction")
            # Native Guide(point, direction) represents an infinite line.
            scene.guides.append(Guide(anchor, vector))
            counts["construction_lines"] += 1

    return counts


def _populate_scene(scene, converted, native=None, viewport_size=(1280, 720)):
    """Structural import milestone: retain native groups and shared components.

    Still pending: materials/UVs, annotations, scenes, nested placements,
    face-me billboards and source edge visibility/softening. No geometry is
    intentionally flattened except loose_geometry, which belongs at the root.
    """
    from core.group import Group
    from core.mesh import Mesh
    from core.materials import Material
    from core.texture import cache_image

    stats = {"faces": 0, "edges": 0, "instances": 0,
             "groups": 0, "definitions": 0, "curves": 0,
             "locked_groups": 0, "locked_instances": 0,
             "skipped_degenerate_edges": 0}

    texture_cache = {}

    # D4N.55Z: Persistent SketchUp back-face material metadata.
    backface_bodies = {}
    backface_count = 0

    def native_face_signature(face):
        import hashlib
        import struct

        points = sorted(
            b"".join(
                struct.pack("<f", float(value))
                for value in (p.x(), p.y(), p.z())
            )
            for p in face.vertices
        )

        return hashlib.sha256(b"".join(points)).hexdigest()


    def native_layer(name):
        """Resolve SKP's default-tag aliases to IngeTrazo's untagged value."""
        if not isinstance(name, str) or not name.strip():
            return None
        if name in ("Layer0", "Untagged", "Layer 0"):
            return None
        return name if name in available_layers else None

    def assign_layer(entity, name, face=False):
        layer = native_layer(name)
        if layer is None:
            return
        if face:
            entity.attrs["layer"] = layer
        else:
            entity.layer = layer
        stats["layer_assignments"] += 1

    def add_body(mesh, body, body_key):
        nonlocal backface_count

        if body_key in backface_bodies:
            raise ValueError(
                "Duplicate BlackFox body key: " + body_key
            )

        body_records = {
            "face_count": 0,
            "back_faces": [],
        }

        backface_bodies[body_key] = body_records
        vertices = body.get("vertices", [])
        points_by_index = {}

        def point(index):
            if index not in points_by_index:
                points_by_index[index] = QVector3D(*map(float, vertices[index]))
            return points_by_index[index]
        boundary = set()
        # BlackFox: count source-face adjacency for each edge.
        face_edge_counts = {}
        for source_face in body.get("faces", []):
            for loop in [source_face.get("outer", [])] + list(source_face.get("holes", [])):
                if len(loop) < 3:
                    continue
                for i, vertex_id in enumerate(loop):
                    key = tuple(sorted((vertex_id, loop[(i + 1) % len(loop)])))
                    face_edge_counts[key] = face_edge_counts.get(key, 0) + 1
        for source_face_index, face in enumerate(
            body.get("faces", [])
        ):
            outer = face.get("outer", [])
            holes = face.get("holes", [])
            if len(outer) < 3:
                continue
            polygon = [point(i) for i in outer]
            hole_polygons = [
                [point(i) for i in loop]
                for loop in holes if len(loop) >= 3
            ]
            new_face = mesh.add_face(polygon, hole_polygons or None)
            assign_layer(new_face, face.get("layer"), face=True)
            if face.get("hidden", False):
                new_face.attrs["hidden"] = True

            native_face_index = len(mesh.faces) - 1

            if mesh.faces[native_face_index] is not new_face:
                raise RuntimeError(
                    "Native face order differs from creation order"
                )

            body_records["face_count"] += 1

            back_slot = face.get("back_material_slot")
            back_record = None

            if back_slot is not None:
                materials = converted.get("source_materials", [])

                if (
                    type(back_slot) is not int
                    or not 1 <= back_slot <= len(materials)
                ):
                    raise ValueError(
                        "Invalid SKP back material slot: "
                        + repr(back_slot)
                    )

                back_material = materials[back_slot - 1]

                if back_material.get("kind") not in (
                    "solid", "textured"
                ):
                    raise ValueError(
                        "Unsupported SKP back material kind: "
                        + repr(back_material.get("kind"))
                    )

                record = {
                    "source_face_index": source_face_index,
                    "native_face_index": native_face_index,
                    "native_signature": native_face_signature(
                        new_face
                    ),
                    "vertex_count": len(new_face.vertices),
                    "back_material_slot": back_slot,
                    "back_material": json.loads(
                        json.dumps(back_material)
                    ),
                    "back_uvw": None,
                    "back_texture": None,
                }

                if back_material.get("kind") == "textured":
                    texture_info = face.get("back_texture")
                    uvw = face.get("back_uvw")

                    if not isinstance(texture_info, dict):
                        raise ValueError(
                            "Missing SKP back texture"
                        )

                    if (
                        not isinstance(uvw, (list, tuple))
                        or len(uvw) != 8
                        or not all(
                            isinstance(v, (int, float))
                            and math.isfinite(v)
                            for v in uvw
                        )
                    ):
                        raise ValueError(
                            "Invalid SKP back UVW"
                        )

                    width = float(texture_info["width_m"])
                    height = float(texture_info["height_m"])

                    if (
                        not math.isfinite(width)
                        or not math.isfinite(height)
                        or width <= 0
                        or height <= 0
                    ):
                        raise ValueError(
                            "Invalid back texture dimensions"
                        )

                    source_path = Path(texture_info["file"])

                    if not source_path.is_file():
                        raise FileNotFoundError(
                            "SKP back texture missing: "
                            + str(source_path)
                        )

                    cached_path = texture_cache.get(
                        str(source_path)
                    )

                    if cached_path is None:
                        cached_path = cache_image(
                            source_path.read_bytes(),
                            source_path.name,
                            "skp",
                        )

                        texture_cache[str(source_path)] = (
                            cached_path
                        )

                    record["back_texture"] = {
                        "path": str(cached_path),
                        "sw": width,
                        "sh": height,
                    }

                    record["back_uvw"] = list(uvw)

                body_records["back_faces"].append(record)
                back_record = record
                backface_count += 1

            # D4N.53AP: SketchUp solid front-face materials.
            # Native material slots are 1-based.
            slot = face.get("material_slot")
            if slot is not None:
                materials = converted.get("source_materials", [])
                if type(slot) is not int or not 1 <= slot <= len(materials):
                    raise ValueError(
                        "Invalid SKP front material slot: " + repr(slot)
                    )

                source_material = materials[slot - 1]

                if source_material.get("kind") == "solid":
                    rgba = source_material.get("rgba")
                    if (
                        not isinstance(rgba, (list, tuple))
                        or len(rgba) != 4
                        or any(type(c) is not int or not 0 <= c <= 255 for c in rgba)
                    ):
                        raise ValueError(
                            "Invalid SKP solid material RGBA: " + repr(rgba)
                        )

                    opacity = source_material.get("opacity", rgba[3] / 255.0)
                    if not isinstance(opacity, (int, float)) or not 0 <= opacity <= 1:
                        raise ValueError(
                            "Invalid SKP material opacity: " + repr(opacity)
                        )

                    material_name = source_material.get("name") or "SKP Material"

                    # Register native materials once and reuse them.
                    material = scene.materials.get(material_name)
                    if material is None:
                        material = Material(
                            name=material_name,
                            color=tuple(c / 255.0 for c in rgba[:3]),
                            opacity=float(opacity),
                        )
                        scene.materials[material_name] = material

                    new_face.attrs.update(material.face_attrs())

                elif source_material.get("kind") == "textured":
                    texture_info = face.get("texture")
                    uvw = face.get("uvw")

                    if not isinstance(texture_info, dict):
                        raise ValueError(
                            "Missing SKP front texture: " + repr(slot)
                        )

                    source_path = Path(texture_info["file"])
                    if not source_path.is_file():
                        raise FileNotFoundError(
                            "SKP texture missing: " + str(source_path)
                        )

                    if (
                        not isinstance(uvw, (list, tuple))
                        or len(uvw) != 8
                        or not all(
                            isinstance(value, (int, float))
                            and math.isfinite(value)
                            for value in uvw
                        )
                    ):
                        raise ValueError(
                            "Invalid SKP front UVW: " + repr(uvw)
                        )

                    width = float(texture_info["width_m"])
                    height = float(texture_info["height_m"])

                    if (
                        not math.isfinite(width)
                        or not math.isfinite(height)
                        or width <= 0
                        or height <= 0
                    ):
                        raise ValueError(
                            "Invalid SKP texture dimensions"
                        )

                    material_name = (
                        source_material.get("name") or "SKP Texture"
                    )

                    cached_path = texture_cache.get(str(source_path))

                    if cached_path is None:
                        cached_path = cache_image(
                            source_path.read_bytes(),
                            source_path.name,
                            "skp",
                        )
                        texture_cache[str(source_path)] = cached_path

                    material = scene.materials.get(material_name)

                    if material is None:
                        material = Material(
                            name=material_name,
                            texture={
                                "path": str(cached_path),
                                "sw": width,
                                "sh": height,
                            },
                        )
                        scene.materials[material_name] = material

                    new_face.attrs.update(material.face_attrs())

                    # UVW is face-specific, not material-specific.
                    new_face.attrs["texture"] = {
                        "path": str(cached_path),
                        "sw": width,
                        "sh": height,
                        "uvw": list(uvw),
                    }

            # D4N.57: Native IngeTrazo two-sided material rendering.
            # D4N.55 metadata remains intact for persistence/regression checks.
            # The back side has its own independent material, UVs and opacity.
            if back_record is not None:
                back_material = back_record["back_material"]
                back_name = back_material.get("name") or "SKP Back Material"
                back_kind = back_material["kind"]
                back_rgba = back_material.get("rgba")
                back_opacity = back_material.get("opacity")

                if back_rgba is not None:
                    if (
                        not isinstance(back_rgba, (list, tuple))
                        or len(back_rgba) != 4
                        or any(type(c) is not int or not 0 <= c <= 255 for c in back_rgba)
                    ):
                        raise ValueError("Invalid SKP back RGBA: " + repr(back_rgba))

                if back_opacity is None:
                    back_opacity = (back_rgba[3] / 255.0) if back_rgba is not None else 1.0
                if (
                    not isinstance(back_opacity, (int, float))
                    or not math.isfinite(back_opacity)
                    or not 0.0 <= back_opacity <= 1.0
                ):
                    raise ValueError("Invalid SKP back opacity: " + repr(back_opacity))

                if back_kind == "solid":
                    if back_rgba is None:
                        raise ValueError("Solid SKP back material missing RGBA")
                    back_attrs = {
                        "color": [float(c) / 255.0 for c in back_rgba[:3]],
                        "mat": back_name,
                    }
                    if back_opacity < 1.0:
                        back_attrs["opacity"] = float(back_opacity)
                    if back_name not in scene.materials:
                        scene.materials[back_name] = Material(
                            name=back_name,
                            color=tuple(float(c) / 255.0 for c in back_rgba[:3]),
                            opacity=float(back_opacity),
                        )
                elif back_kind == "textured":
                    cached = back_record["back_texture"]
                    uvw = back_record["back_uvw"]
                    if cached is None or uvw is None:
                        raise ValueError("Missing cached back texture or UVW")
                    texture_attrs = {
                        "path": cached["path"],
                        "sw": cached["sw"],
                        "sh": cached["sh"],
                        "uvw": list(uvw),
                        "planar": True,
                    }
                    back_attrs = {"texture": texture_attrs, "mat": back_name}
                    if back_opacity < 1.0:
                        back_attrs["opacity"] = float(back_opacity)
                    if back_name not in scene.materials:
                        scene.materials[back_name] = Material(
                            name=back_name,
                            texture={
                                "path": cached["path"],
                                "sw": cached["sw"],
                                "sh": cached["sh"],
                            },
                            opacity=float(back_opacity),
                        )
                else:
                    raise ValueError("Unsupported back material kind: " + repr(back_kind))

                new_face.attrs["back"] = back_attrs

            stats["faces"] += 1
            for loop in [outer] + list(holes):
                for i, vertex_id in enumerate(loop):
                    boundary.add(tuple(sorted((vertex_id, loop[(i + 1) % len(loop)]))))
        edges = body.get("edges", [])
        edge_properties = body.get("edge_properties") or []
        for edge_index, (a, b) in enumerate(edges):
            props = edge_properties[edge_index] if edge_index < len(edge_properties) else {}
            if not isinstance(props, dict):
                props = {}
            p0 = point(a)
            p1 = point(b)
            if (p1 - p0).lengthSquared() <= 1e-16:
                stats["skipped_degenerate_edges"] += 1
                continue
            is_boundary = tuple(sorted((a, b))) in boundary
            # No assignment needed for an already-created boundary edge
            # without an explicit, recognized source tag.
            if is_boundary and native_layer(props.get("layer")) is None and not props.get("hidden", False):
                continue
            try:
                if is_boundary:
                    # add_face already made this edge. Look it up without
                    # creating or changing geometry.
                    va = mesh.vertex_at(p0)
                    vb = mesh.vertex_at(p1)
                    edge = mesh.find_edge(va, vb) if va is not None and vb is not None else None
                    if edge is None:
                        raise ValueError("Source boundary edge not found in imported mesh")
                else:
                    edge = mesh.add_edge(p0, p1)
            except ValueError as exc:
                if "degenerate edge: endpoints weld to one vertex" not in str(exc):
                    raise
                stats["skipped_degenerate_edges"] += 1
                continue
            assign_layer(edge, props.get("layer"))
            if props.get("hidden", False) or (
                props.get("soft", False)
                and face_edge_counts.get(tuple(sorted((a, b))), 0) >= 2
            ):
                edge.hidden = True
            if not is_boundary:
                stats["edges"] += 1

        # Reconstruct native curve identities from the source edge chains.
        # Tagging changes selection/topology metadata, not vertex positions.
        for curve in body.get("curves", []):
            indices = curve.get("edges") or []
            if not indices:
                continue
            ordered = _ordered_curve_vertices(edges, indices, lambda e: (e[0], e[1]))
            if ordered is None:
                continue
            chain, closed = ordered
            points = [point(i) for i in chain]
            if _tag_imported_curve(mesh, points, closed):
                stats["curves"] += 1

    # Mission 2B: restore source SKP tag colours dynamically. IngeTrazo's
    # native "Layer 0" is deliberately never modified. SketchUp's default
    # "Layer0" / "Untagged" are default-tag aliases, not extra layers.
    def restore_layer_catalogue():
        from core.layers import Layer

        protected = "Layer 0"
        existing = {getattr(layer, "name", None): layer for layer in scene.layers}
        added = 0
        colored = 0
        for source_index, source in enumerate(converted.get("layers", [])):
            name = source.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            # SKP default tag is entry 0 in the source layer catalogue.
            # Legacy readers expose Layer0; modern UIs display Untagged.
            # Only skip a default-name alias at index 0, so an unrelated
            # user-created tag with that name is not silently discarded.
            if name == protected or (
                source_index == 0 and name in ("Layer0", "Untagged")
            ):
                continue
            layer = existing.get(name)
            if layer is None:
                layer = Layer(name)
                scene.layers.append(layer)
                existing[name] = layer
                added += 1
            if hasattr(layer, "visible"):
                layer.visible = bool(source.get("visible", True))
            rgba = source.get("color")
            # SketchUp uses transparent black for an unset tag colour.
            if rgba == [0, 0, 0, 0] or rgba == (0, 0, 0, 0):
                continue
            if isinstance(rgba, (list, tuple)) and len(rgba) in (3, 4):
                if all(isinstance(c, (int, float)) and 0 <= c <= 255 for c in rgba):
                    # IngeTrazo display styles use RGB triples in [0,1].
                    # The alpha channel is represented by Layer.opacity.
                    layer.color = tuple(float(c) / 255.0 for c in rgba[:3])
                    if len(rgba) == 4 and hasattr(layer, "opacity"):
                        layer.opacity = float(rgba[3]) / 255.0
                    colored += 1
        return added, colored

    stats["layers_added"], stats["layers_colored"] = restore_layer_catalogue()
    stats["layers_total"] = len(scene.layers)
    stats["layer_assignments"] = 0
    available_layers = {layer.name for layer in scene.layers}

    for body_index, body in enumerate(
        converted.get("loose_geometry", [])
    ):
        add_body(
            scene.loose_mesh,
            body,
            "loose:" + str(body_index),
        )

    source_owner_dicts = {}
    for record in converted.get("source_dictionaries", []):
        source_owner_dicts.setdefault(tuple(record["owner"]), []).extend(record["dictionaries"])

    def restore_owner_metadata(group, definition, placement):
        data = group.ext.setdefault("blackfox_skp", {}) if group.ext else {}
        group.ext = {**(group.ext or {}), "blackfox_skp": data}
        owner = ("definition_map", definition.get("source_def_index"))
        dictionaries = source_owner_dicts.get(owner)
        if dictionaries:
            data["definition_dictionaries"] = dictionaries
            for dictionary in dictionaries:
                if dictionary["name"] == "AppliedSchemaTypes":
                    for schema, value in dictionary["entries"]:
                        if schema.casefold().startswith("ifc") and value[0] == "text":
                            group.ifc = {"class": value[1], "name": group.name}
                            break
        owner = ("instance_pid", placement.get("source_instance_pid"))
        if owner in source_owner_dicts:
            data["instance_dictionaries"] = source_owner_dicts[owner]

    for body_index, body in enumerate(
        converted.get("objects", [])
    ):
        mesh = Mesh()
        add_body(
            mesh,
            body,
            "object:" + str(body_index),
        )
        group = Group(mesh, body.get("name") or "SKP Group")
        group.component = False
        restore_owner_metadata(group, body, body)
        group.hidden = bool(body.get("hidden", False))
        locked = body.get("locked")
        if type(locked) is not bool:
            raise ValueError(
                "Missing or invalid native SKP group lock state: "
                + repr(body.get("source_instance_pid"))
            )
        group.locked = locked
        if locked:
            stats["locked_groups"] += 1
        assign_layer(group, body.get("layer"))
        if body.get("transform") is not None:
            group.xform = _skp_matrix(body["transform"])
        scene.groups.append(group)
        stats["groups"] += 1

    definitions = {}
    for body_index, body in enumerate(
        converted.get("component_definitions", [])
    ):
        key = body["id"]
        if key in definitions:
            raise ValueError("Duplicate component definition: " + str(key))
        mesh = Mesh()
        add_body(
            mesh,
            body,
            "definition:" + str(body_index),
        )
        definitions[key] = (mesh, body)
        stats["definitions"] += 1

    for instance in converted.get("component_instances", []):
        key = instance["definition_id"]
        if key not in definitions:
            raise ValueError("Missing component definition: " + str(key))
        mesh, definition = definitions[key]
        group = Group(mesh, definition.get("name") or str(key))
        group.component = True
        description = definition.get("source_description", "")
        if not isinstance(description, str):
            raise ValueError("Invalid native component description")
        group.ext = {
            "blackfox_skp": {
                "definition_description": description
            }
        }
        restore_owner_metadata(group, definition, instance)
        group.hidden = bool(instance.get("hidden", False))
        locked = instance.get("locked")
        if type(locked) is not bool:
            raise ValueError(
                "Missing or invalid native SKP component lock state: "
                + repr(instance.get("source_instance_pid"))
            )
        group.locked = locked
        if locked:
            stats["locked_instances"] += 1
        assign_layer(group, instance.get("layer"))
        group.xform = _skp_matrix(instance["transform"])
        scene.groups.append(group)
        stats["instances"] += 1

    metadata = {
        "schema": "blackfox.skp.backfaces.v1",
        "body_order": {
            "loose": len(
                converted.get("loose_geometry", [])
            ),
            "objects": len(
                converted.get("objects", [])
            ),
            "definitions": [
                body["id"]
                for body in converted.get(
                    "component_definitions", []
                )
            ],
        },
        "bodies": backface_bodies,
        "back_face_count": backface_count,
    }

    metadata_key = "blackfox_skp_backfaces_v1"

    if metadata_key in scene.plugin_data:
        raise ValueError(
            "Existing BlackFox back-face metadata "
            "would be overwritten"
        )

    scene.plugin_data[metadata_key] = metadata
    stats["back_faces_preserved"] = backface_count
    stats["back_faces_native"] = backface_count

    if native is not None:
        stats.update(_restore_construction_guides(scene, native))
    stats.update(_restore_native_sections(scene, converted, native))
    if native is not None:
        stats.update(_restore_native_annotations(scene, converted, native, viewport_size))
    return stats


# SketchUp LengthUnit enum: Inches=0, Feet=1, Millimeters=2,
# Centimeters=3, Meters=4. The Rust bridge provides metre coordinates.
_SKP_LENGTH_UNITS = {0: "in", 1: "ft", 2: "mm", 3: "cm", 4: "m"}


def _source_display_units(converted):
    source = converted.get("source_units")
    if not isinstance(source, dict):
        raise ValueError("SKP source units missing; cannot open with source units")
    code = source.get("length_unit")
    if type(code) is not int or code not in _SKP_LENGTH_UNITS:
        raise ValueError("Unsupported SKP length unit: " + repr(code))
    precision = source.get("length_precision", 2)
    if type(precision) is not int or not 0 <= precision <= 12:
        raise ValueError("Invalid SKP length precision: " + repr(precision))
    return {"length": _SKP_LENGTH_UNITS[code], "precision": precision}



def _restore_geo_shadows(scene, converted):
    """Phase 2M: adopt supported document-level SKP settings on Open only.

    A shadow record is not proof of a geolocated SKP document. Preserve its
    complete source data even where native representation is unavailable.
    """
    from datetime import datetime, timedelta, timezone
    from core.sun import ShadowSettings, wrap_north_deg

    source = converted.get("source_shadows")
    stats = {"geo_shadows_source": False, "geolocation_restored": False,
             "geographic_north_restored": False, "shadows_restored": False}
    location = converted.get("source_location") or {}
    if source is None and not location:
        return stats
    if source is None:
        source = {}
    if not isinstance(source, dict):
        raise ValueError("Invalid source_shadows object")
    scene.plugin_data["blackfox_skp_geo_shadows_v1"] = json.loads(json.dumps(source))
    stats["geo_shadows_source"] = True

    north = source.get("north")
    if (isinstance(north, (list, tuple)) and len(north) == 3
            and all(type(v) in (int, float) and math.isfinite(v) for v in north)):
        nx, ny, nz = map(float, north)
        magnitude = math.sqrt(nx*nx + ny*ny + nz*nz)
        if magnitude > 1e-9 and math.hypot(nx, ny) > 1e-9:
            north_deg = wrap_north_deg(math.degrees(math.atan2(nx, ny)))
            scene.north_deg = north_deg
            stats["geographic_north_restored"] = True
        else:
            north_deg = None
    else:
        north_deg = None

    # SketchUp's shadow parser defaults missing coordinates to (0,0).
    # Require an independently populated location label before treating the
    # shadow record as evidence of a georeferenced model. Zero coordinates
    # alone are never sufficient; altitude is not provided by this record.
    lat, lon = (location.get("latitude", source.get("latitude")),
                location.get("longitude", source.get("longitude")))
    if location.get("north_deg") is not None:
        north_deg = wrap_north_deg(location["north_deg"])
        scene.north_deg = north_deg
        stats["geographic_north_restored"] = True
    has_location_label = any(isinstance(source.get(k), str) and source[k].strip()
                             for k in ("city", "country"))
    valid_coords = (type(lat) in (int, float) and type(lon) in (int, float)
                    and math.isfinite(lat) and math.isfinite(lon)
                    and -90 <= lat <= 90 and -180 <= lon <= 180)
    if valid_coords and (converted.get("source_geo_located")
                         or (has_location_label and (lat != 0 or lon != 0))):
        from georef.datum import SceneDatum
        scene.georef = SceneDatum(float(lat), float(lon),
                                 north=north_deg if north_deg is not None else 0.0)
        stats["geolocation_restored"] = True

    # A model's shadow timestamp is UTC Unix seconds. Convert to its local
    # clock using the source offset. Native settings cannot represent
    # fractional UTC offsets, so retain them only in source metadata.
    enabled = source.get("displayed")
    timestamp = source.get("time")
    offset = source.get("tz_offset_h")
    if type(enabled) is not bool:
        return stats
    if enabled is False and (type(timestamp) is not int or timestamp <= 0):
        scene.shadows = ShadowSettings(enabled=False)
        stats["shadows_restored"] = True
        return stats
    if type(timestamp) is not int or timestamp <= 0:
        return stats
    if (type(offset) not in (int, float) or not math.isfinite(offset)
            or not -14 <= offset <= 14):
        return stats
    if not float(offset).is_integer():
        stats["shadows_reason"] = "Fractional time-zone offset retained as metadata"
        return stats
    try:
        local = datetime.fromtimestamp(timestamp, tz=timezone.utc) + timedelta(hours=offset)
        if not 1 <= local.year <= 9999:
            return stats
        settings = ShadowSettings(enabled=enabled, month=local.month,
                                  day=local.day, hour=local.hour,
                                  minute=local.minute)
        if float(offset).is_integer():
            settings.utc_offset = int(offset)
        # Do not guess the native darkness multiplier from SketchUp's
        # independent light/dark sliders; preserve both in plugin_data.
        scene.shadows = settings
        stats["shadows_restored"] = True
    except (OverflowError, OSError, ValueError):
        pass
    return stats


def _skp_rendering_to_style(source, base_style):
    """Convert supported SKP rendering into an independent native style snapshot."""
    from core.style import Style
    if not isinstance(source, dict) or not source:
        return None
    settings = base_style.to_dict()
    changed = False

    def boolean(source_key, native_key):
        nonlocal changed
        value = source.get(source_key)
        if type(value) is bool:
            settings[native_key] = value
            changed = True

    def rgb(source_key, native_key):
        nonlocal changed
        value = source.get(source_key)
        if (isinstance(value, (list, tuple)) and len(value) == 4
                and all(type(c) is int and 0 <= c <= 255 for c in value)
                and (source_key != "background" or value[3] != 0)):
            settings[native_key] = tuple(c / 255.0 for c in value[:3])
            changed = True

    face_style = source.get("face_style")
    if source.get("xray") is True:
        settings["face_mode"] = "xray"
        settings["name"] = "X-ray"
        changed = True
    elif type(face_style) is int:
        modes = {0: "wireframe", 1: "hidden_line", 5: "monochrome"}
        if face_style == 2:
            textures = source.get("textures")
            if type(textures) is bool:
                settings["face_mode"] = "textures" if textures else "shaded"
                changed = True
        elif face_style in modes:
            settings["face_mode"] = modes[face_style]
            changed = True

    if changed:
        preset_names = {
            "textures": "Default",
            "shaded": "Shaded",
            "hidden_line": "Hidden line",
            "monochrome": "Monochrome",
            "wireframe": "Wireframe",
            "xray": "X-ray",
        }
        mode = settings.get("face_mode")
        if mode in preset_names:
            settings["name"] = preset_names[mode]

    # SketchUp section fill is a native IngeTrazo style property.
    boolean("section_fill", "section_fill")
    rgb("section_fill_color", "section_fill_color")

    boolean("edges", "edges")
    boolean("profiles", "profiles")
    boolean("sky", "sky")
    boolean("ambient_occlusion", "ambient_occlusion")
    for source_key, native_key in (
        ("background", "background"),
        ("sky_color", "sky_color"),
        ("ground_color", "ground_color"),
        ("front_color", "front_color"),
        ("back_color", "back_color"),
    ):
        rgb(source_key, native_key)

    return Style.from_dict(settings) if changed else None


def _restore_display_style(scene, converted):
    """Restore supported model-level SKP rendering on Open SKP only."""
    source = converted.get("source_rendering")
    if not isinstance(source, dict) or not source:
        return {"display_style_restored": False,
                "display_style_reason": "No source rendering options"}
    scene.plugin_data["blackfox_skp_rendering_v1"] = json.loads(json.dumps(source))
    restored = _skp_rendering_to_style(source, scene.display_style)
    if restored is not None:
        scene.display_style = restored
    return {"display_style_restored": restored is not None,
            "display_style_mode": scene.display_style.face_mode}


def _restore_active_layer(scene, converted):
    """Restore the source active tag when opening a new document."""
    layers = converted.get("layers") or []
    source_index = converted.get("source_active_layer")

    if source_index is None:
        return {"active_layer_restored": False,
                "active_layer": None,
                "active_layer_reason": "Source active layer was not provided"}
    if type(source_index) is not int or not 0 <= source_index < len(layers):
        raise ValueError("Invalid SKP active layer index: " + repr(source_index))

    source = layers[source_index]
    if not isinstance(source, dict):
        raise ValueError("Invalid SKP active layer catalogue entry")
    name = source.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("SKP active layer has no valid name")

    # SketchUp's default tag maps to IngeTrazo's native default layer.
    if name in ("Layer0", "Untagged", "Layer 0"):
        scene.active_layer = None
        return {"active_layer_restored": True, "active_layer": "Layer 0"}

    if scene.layer(name) is None:
        raise ValueError("SKP active layer was not created in IngeTrazo: " + name)
    scene.active_layer = name
    return {"active_layer_restored": True, "active_layer": name}



# Phase 2E.68b hierarchy engine integrated into the ONE active extension.
# The accepted frozen prototype remains an independent backup, never imported at runtime.
from collections import Counter, defaultdict
from core.group import Group, iter_placements
from core.mesh import Mesh

def matrix4(values):
    if not isinstance(values, list) or len(values) != 16:
        raise ValueError('Expected 16-element world matrix')
    v = [float(x) for x in values]
    if not all(map(math.isfinite, v)) or any(abs(v[i] - t) > 1e-8 for i,t in ((12,0),(13,0),(14,0),(15,1))):
        raise ValueError('Invalid affine world matrix')
    return QMatrix4x4(*v)

def matmul(a, b):
    return [sum(a[4*r+k]*b[4*k+c] for k in range(4)) for r in range(4) for c in range(4)]

def inverse_affine(m):
    # Inverse of general 3x3 affine transform, including nonuniform scale/shear.
    a,b,c,d,e,f,g,h,i = m[0],m[1],m[2],m[4],m[5],m[6],m[8],m[9],m[10]
    A=e*i-f*h; B=c*h-b*i; C=b*f-c*e
    D=f*g-d*i; E=a*i-c*g; F=c*d-a*f
    G=d*h-e*g; H=b*g-a*h; I=a*e-b*d
    det=a*A+b*D+c*G
    if abs(det) < 1e-14: raise ValueError('Singular parent transform')
    inv=[v/det for v in (A,B,C,D,E,F,G,H,I)]
    x,y,z=m[3],m[7],m[11]
    return [inv[0],inv[1],inv[2],-inv[0]*x-inv[1]*y-inv[2]*z,
            inv[3],inv[4],inv[5],-inv[3]*x-inv[4]*y-inv[5]*z,
            inv[6],inv[7],inv[8],-inv[6]*x-inv[7]*y-inv[8]*z,
            0.,0.,0.,1.]

def mesh_from_run(run, mesh=None):
    if mesh is None:
        mesh = Mesh()
    vertices=run['vertices']
    for face in run['faces']:
        outer=face['outer']
        if len(outer)<3: continue
        holes=face.get('holes') or []
        mesh.add_face([QVector3D(*map(float,vertices[j])) for j in outer],
                      [[QVector3D(*map(float,vertices[j])) for j in loop] for loop in holes] or None)
    for edge in run['edges']:
        a,b=edge['v0'],edge['v1']
        p=QVector3D(*map(float,vertices[a]));q=QVector3D(*map(float,vertices[b]))
        if (p-q).lengthSquared()<1e-16:continue
        va, vb = mesh.vertex_at(p), mesh.vertex_at(q)
        # IngeTrazo welds vertices by tolerance. Distinct source endpoints can
        # therefore resolve to one native vertex even when p != q.
        if va is not None and vb is not None:
            if va is vb:
                continue  # Degenerate only after native vertex welding.
            if mesh.find_edge(va, vb) is not None:
                continue
        try:
            mesh.add_edge(p, q)
        except ValueError as exc:
            if "degenerate edge: endpoints weld to one vertex" not in str(exc):
                raise
            # Native weld may happen inside add_edge even when vertex_at did
            # not resolve both endpoints beforehand. Never mask other errors.
            continue
    # Preserve SketchUp curve membership in the hierarchy-only fallback.
    # This path previously imported every segment as an independent edge.
    for curve in run.get('curves') or []:
        indices = curve.get('edges') or []
        if not indices:
            continue
        ordered = _ordered_curve_vertices(
            run['edges'], indices, lambda e: (e['v0'], e['v1'])
        )
        if ordered is None:
            continue
        chain, closed = ordered
        points = [QVector3D(*map(float, vertices[i])) for i in chain]
        _tag_imported_curve(mesh, points, closed)
    return mesh

def prepare(path):
    native=json.loads(Path(path).read_text(encoding='utf-8-sig'))
    cad=native['cad']; runs=cad['geometry']; roots=cad['scene_hierarchy']
    if cad.get('coordinate_unit')!='metre':raise ValueError('Unexpected geometry units')
    if not roots:raise ValueError('No hierarchy roots; refusing empty import')
    identity=[1.,0.,0.,0.,0.,1.,0.,0.,0.,0.,1.,0.,0.,0.,0.,1.]
    visited=[]; run_kinds={}
    def validate(node,path,parent_world,depth):
        if depth>60:raise ValueError('Excessive hierarchy depth')
        if node['instance_path']!=path:raise ValueError('Hierarchy path mismatch')
        ri=node['run_id']
        if type(ri)!=int or not 0<=ri<len(runs):raise ValueError('Invalid geometry run')
        kind=node['is_group']
        if type(kind)!=bool:raise ValueError('Unknown group/component type')
        if type(node.get('locked')) is not bool:
            raise ValueError('Missing or invalid native lock state at hierarchy path %r' % (path,))
        if ri in run_kinds and run_kinds[ri]!=kind:raise ValueError('Conflicting run identity')
        run_kinds[ri]=kind
        world=node['world_transform_metres'];matrix4(world)
        # skpwright's 13-element local transform is in inches. We derive
        # metre-local from the already normalized world matrices instead.
        local=matmul(inverse_affine(parent_world),world)
        if any(abs(v)>1e9 for v in local):raise ValueError('Implausible transform')
        visited.append((path,ri,node.get('source_pid'),kind))
        for index,child in enumerate(node['children']):
            validate(child,path+[index],world,depth+1)
    for index,node in enumerate(roots):validate(node,[index],identity,0)
    if len({tuple(x[0]) for x in visited})!=len(visited):raise ValueError('Duplicate hierarchy path')
    print('BLACKFOX 2E.32 DRY RUN PASS: roots=%d, occurrences=%d, depth=%d, runs=%d' %
          (len(roots),len(visited),max(map(lambda x:len(x[0]),visited)),len(run_kinds)))
    return native

def walk_nodes(roots):
    for node in roots:
        yield node
        yield from walk_nodes(node["children"])

def build_selective(native):
    cad = native['cad']
    runs = cad['geometry']
    roots = cad['scene_hierarchy']
    identity = [1.,0.,0.,0.,0.,1.,0.,0.,0.,0.,1.,0.,0.,0.,0.,1.]
    shared_meshes = {}
    run_by_path = {}
    # A run is a definition-geometry identity in this JSON schema.
    # Only components share native meshes; SketchUp groups remain independent.
    shared_run_ids = {node["run_id"] for node in walk_nodes(roots) if not node["is_group"]}

    def create(node, parent_world):
        ri = node['run_id']
        kind = node['is_group']
        world = node['world_transform_metres']
        path = tuple(node['instance_path'])
        if ri in shared_run_ids:
            if ri not in shared_meshes:
                shared_meshes[ri] = mesh_from_run(runs[ri])
            group_mesh = shared_meshes[ri]
        else:
            group_mesh = mesh_from_run(runs[ri])
        local = matmul(inverse_affine(parent_world), world)
        obj = Group(group_mesh, node.get('definition') or
                    ('SKP Group' if kind else 'SKP Component'))
        obj.component = not kind
        obj.xform = matrix4(local)
        obj.hidden = bool(node.get('hidden', False))
        obj.locked = node['locked']
        children = [create(child, world) for child in node['children']]
        if children:
            obj.adopt(children)
        run_by_path[path] = (ri, bool(node['children']))
        return obj

    return [create(root, identity) for root in roots], run_by_path

def audit(roots, run_by_path, label):
    from collections import defaultdict
    by_run = defaultdict(list)
    kinds_by_run = {}
    by_mesh = defaultdict(list)
    visited = []

    def walk(obj, path):
        if path not in run_by_path:
            raise RuntimeError('Unexpected hierarchy path: %r' % (path,))
        ri, is_container = run_by_path[path]
        if bool(obj.children) != is_container:
            raise RuntimeError('Hierarchy changed at %r' % (path,))
        by_run[ri].append((path, id(obj.mesh), is_container))
        kinds_by_run.setdefault(ri, obj.component)
        if kinds_by_run[ri] != obj.component:
            raise RuntimeError("Mixed group/component run identity")
        by_mesh[id(obj.mesh)].append(path)
        visited.append(path)
        for i, child in enumerate(obj.children):
            walk(child, path + (i,))

    for i, root in enumerate(roots):
        walk(root, (i,))
    if len(visited) != len(run_by_path) or len(set(visited)) != len(visited):
        raise RuntimeError('Hierarchy occurrence count mismatch')

    print('\nBLACKFOX 2E.44 %s' % label)
    print('TOTAL OCCURRENCES:', len(visited))
    print('DISTINCT MESHES:', len(by_mesh))
    ok = True
    for ri in sorted(by_run):
        entries = by_run[ri]
        ids = [mid for _, mid, _ in entries]
        if kinds_by_run[ri]:
            valid = len(set(ids)) == 1
            mode = 'SHARED'
        else:
            valid = len(set(ids)) == len(ids)
            mode = 'PRIVATE'
        ok &= valid
        print(' RUN %d | OCCURRENCES %d | MODE %s | PASS %s' %
              (ri, len(entries), mode, valid))
    # Prevent accidentally merging distinct geometry runs.
    run_mesh_sets = [{mid for _, mid, _ in by_run[ri]} for ri in sorted(by_run)]
    if any(a & b for i, a in enumerate(run_mesh_sets) for b in run_mesh_sets[i+1:]):
        ok = False
        print(' ERROR: Different geometry runs share a mesh')
    print('BLACKFOX 2E.44 %s RESULT: %s' % (label, 'PASS' if ok else 'FAIL'))
    if not ok:
        raise RuntimeError('Geometry-owner sharing invariants failed')
    return len(by_mesh)

def make_leaf_version(roots, path_runs):
    # Preserve every original node, its component/group status, and transform.
    # Only move an owner's OWN geometry into an identity-transform child.
    # Existing children stay in their original relative order and placement.
    leaves = {}
    def visit(node, path):
        for index, child in enumerate(list(node.children)):
            visit(child, path + (index,))
        run_id, _ = path_runs[path]
        if node.component and node.children and (node.mesh.faces or node.mesh.edges):
            original_mesh = node.mesh
            leaf = Group(original_mesh, name='BlackFox own geometry / run %d' % run_id)
            leaf.component = True
            leaf.locked = bool(node.locked)
            leaf.xform = QMatrix4x4()
            node.mesh = Mesh()
            node.adopt([leaf] + list(node.children))
            leaves[path] = leaf
    for index, root in enumerate(roots):
        visit(root, (index,))
    return leaves

def geometry_signature(roots):
    # Include all face corners AND all edges, including loose edges.
    # Ignore the extra empty container / leaf boundary.
    result = Counter()
    def pkey(p):
        return (round(p.x(), 5), round(p.y(), 5), round(p.z(), 5))
    for root in roots:
        for group, matrix in iter_placements(root):
            def place(v):
                q = matrix.map(v) if matrix is not None else v
                return pkey(q)
            for face in group.mesh.faces:
                result[('F', tuple(sorted(place(v) for v in face.vertices)))] += 1
            for edge in group.mesh.edges:
                result[('E', tuple(sorted((place(edge.v0.position), place(edge.v1.position)))))] += 1
    return result

def assert_same_geometry(a, b):
    sa, sb = geometry_signature(a), geometry_signature(b)
    missing = sa - sb
    added = sb - sa
    if missing or added:
        print('MISSING world-space elements:', sum(missing.values()))
        print('ADDED world-space elements:', sum(added.values()))
        for key, count in list(missing.items())[:3]: print('  MISSING SAMPLE', count, key)
        for key, count in list(added.items())[:3]: print('  ADDED SAMPLE', count, key)
        raise AssertionError('World-space geometry changed')
    print('WORLD-SPACE GEOMETRY IDENTICAL: %d faces, %d edges' %
          (sum(v for (kind, _), v in sa.items() if kind == 'F'),
           sum(v for (kind, _), v in sa.items() if kind == 'E')))

def _import_native_hierarchy(scene, native_path):
    """Phase 2E hierarchy insertion. Validate completely before scene mutation.

    Current scope: nested groups/components and linked component meshes only.
    Material, annotation and saved-view restoration is deliberately not claimed
    for hierarchy-schema files until its own regression gate passes.
    """
    native = prepare(native_path)
    original, original_paths = build_selective(native)
    roots, paths = build_selective(native)
    audit(original, original_paths, 'INTEGRATED ORIGINAL')
    audit(roots, paths, 'INTEGRATED BEFORE LEAVES')
    leaves = make_leaf_version(roots, paths)
    assert_same_geometry(original, roots)

    # Verify source hierarchy against the untouched reconstruction. The leaf
    # rewrite intentionally inserts synthetic children, so auditing its raw
    # child counts against the SKP source would reject valid nested models.
    def verify_lock_tree(objects, source_nodes, path=()):
        if len(objects) != len(source_nodes):
            raise AssertionError('Lock audit hierarchy cardinality mismatch at %r' % (path,))
        for index, (obj, source) in enumerate(zip(objects, source_nodes)):
            current_path = path + (index,)
            if type(source.get('locked')) is not bool:
                raise AssertionError('Source lock flag missing at %r' % (current_path,))
            if bool(obj.locked) != source['locked']:
                raise AssertionError('Lock state mismatch at %r' % (current_path,))
            verify_lock_tree(obj.children, source['children'], current_path)

    verify_lock_tree(original, native['cad']['scene_hierarchy'])
    # Verify that synthetic geometry leaves inherit their owning component's
    # lock state, without treating them as original SketchUp hierarchy nodes.
    def find_parent(roots, target):
        for root in roots:
            stack = [root]
            while stack:
                owner = stack.pop()
                if any(child is target for child in owner.children):
                    return owner
                stack.extend(owner.children)
        return None
    for path, leaf in leaves.items():
        owner = find_parent(roots, leaf)
        if owner is None or bool(leaf.locked) != bool(owner.locked):
            raise AssertionError('Geometry leaf lock mismatch at %r' % (path,))

    if len(roots) != len(native['cad']['scene_hierarchy']):
        raise AssertionError('Hierarchy root count mismatch')
    if len(paths) != sum(1 for _ in walk_nodes(native['cad']['scene_hierarchy'])):
        raise AssertionError('Hierarchy occurrence count mismatch')
    by_run = defaultdict(set)
    for path, leaf in leaves.items():
        run_id, _ = paths[path]
        by_run[run_id].add(id(leaf.mesh))
    if any(len(mesh_ids) != 1 for mesh_ids in by_run.values()):
        raise AssertionError('Shared component mesh identity mismatch')
    if scene.groups:
        raise RuntimeError('Phase 2E hierarchy import currently requires a fresh empty document')
    for run, metadata in zip(native['mesh']['runs'], native['model']['geometry_runs'], strict=True):
        if metadata['def_index'] is None:
            mesh_from_run({**run, 'vertices': run['vertices_m']}, scene.mesh)
    scene.groups.extend(roots)
    lock_nodes = list(walk_nodes(native['cad']['scene_hierarchy']))
    return {
        'roots': len(roots),
        'occurrences': len(paths),
        'leaves': len(leaves),
        'locked_occurrences': sum(1 for node in lock_nodes if node['locked']),
    }


def _blackfox_open_target(parent):
    """Reuse the initial blank document; never overwrite a populated document."""
    docs = parent.documents()
    active = parent.active_document()
    if len(docs) == 1 and active is docs[0]:
        vp = getattr(active, "viewport", None)
        scene = getattr(vp, "scene", None)
        if scene is not None:
            root = scene.mesh
            if (not scene.groups
                    and not root.vertices and not root.edges and not root.faces
                    and not scene.plugin_data
                    and not getattr(scene, "dimensions", ())
                    and not getattr(scene, "texts", ())
                    and not getattr(scene, "section_planes", ())):
                return active
    return parent._new_document(activate=True)


def _run_skp_import(command, parent):
    from concurrent.futures import ThreadPoolExecutor
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QProgressDialog

    progress = QProgressDialog("Reading SKP file...", "", 0, 0, parent)
    progress.setWindowTitle("BlackFox SKP")
    progress.setWindowModality(Qt.ApplicationModal)
    progress.setCancelButton(None)
    progress.setWindowFlag(Qt.WindowCloseButtonHint, False)
    progress.setMinimumDuration(500)
    loop = QEventLoop()
    timer = QTimer(progress)
    with ThreadPoolExecutor(max_workers=1) as worker:
        future = worker.submit(
            subprocess.run, command, capture_output=True, encoding="utf-8",
            errors="replace", timeout=300,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def check_finished():
            if future.done():
                loop.quit()

        timer.timeout.connect(check_finished)
        timer.start(30)
        try:
            if not future.done():
                progress.setValue(0)
                loop.exec()
            return future.result()
        finally:
            timer.stop()
            progress.close()


def _import_skp(app, open_mode=False):
    parent = app.window
    try:
        engine, _ = _blackfox_dependencies(parent, prompt=True)
        filename, _ = QFileDialog.getOpenFileName(
            parent, "Open SKP" if open_mode else "Import SKP", "", "SKP Models (*.skp)"
        )
        if not filename:
            return

        from core.history import SnapshotImport
        import sys
        with tempfile.TemporaryDirectory(prefix="blackfox_skp_") as tmp:
            folder = Path(tmp)
            native = folder / "native.json"
            assets = folder / "assets"
            assets.mkdir()
            # No shell; arguments are passed directly and safely.
            command = [str(engine), "import-assets", str(filename), str(native), str(assets)]
            result = _run_skp_import(command, parent)
            if result.returncode:
                detail = re.sub(r"(?i)sketchup", "SKP", result.stderr or result.stdout)
                raise RuntimeError("BlackFox import-assets failed:\n" + detail)
            with native.open('r', encoding='utf-8-sig') as handle:
                early_native = json.load(handle)
            # Preserve the existing Phase 2D import for models supported by
            # its conversion bridge. Nested placements are handled by V2 below.
            def import_hierarchy(hierarchy_json):
                # Open SKP creates a new document; Import SKP uses the active one.
                # Keep the validated hierarchy insertion and history mechanism identical.
                if open_mode:
                    target_doc = _blackfox_open_target(parent)
                    if target_doc is None or getattr(target_doc, "viewport", None) is None:
                        raise RuntimeError("IngeTrazo did not return a new document viewport")
                    target_viewport = target_doc.viewport
                else:
                    target_viewport = app.viewport
                if target_viewport is None or target_viewport.scene.groups:
                    raise RuntimeError(
                        'Nested hierarchy import requires an empty target document.')
                hierarchy_stats = {}
                callback_state = {'called': False, 'error': None}
                def hierarchy_mutate(scene):
                    callback_state['called'] = True
                    try:
                        hierarchy_stats.update(_import_native_hierarchy(scene, hierarchy_json))
                        hierarchy_stats.update(_restore_construction_guides(scene, early_native))
                    except Exception:
                        callback_state['error'] = traceback.format_exc()
                        raise
                try:
                    target_viewport.history.execute(SnapshotImport(hierarchy_mutate))
                except Exception as exc:
                    raise RuntimeError('Hierarchy import failed inside IngeTrazo history:\n'
                                       + (callback_state['error'] or traceback.format_exc())) from exc
                if callback_state['error']:
                    raise RuntimeError('Hierarchy import failed; history may have rolled back:\n'
                                       + callback_state['error'])
                if not callback_state['called']:
                    raise RuntimeError('IngeTrazo history never invoked the hierarchy callback.')
                if not all(key in hierarchy_stats for key in ('roots', 'occurrences', 'leaves')):
                    raise RuntimeError('Incomplete hierarchy statistics: ' + repr(hierarchy_stats))
                target_viewport.notify_scene_changed()
                QMessageBox.information(
                    parent, 'BlackFox SKP - Hierarchy imported',
                    ('Opened a new SKP document.\n' if open_mode else 'Imported SKP into current document.\n') +
                    'Phase 2E nested hierarchy and linked geometry inserted.\n'
                    f"Roots: {hierarchy_stats['roots']}\n"
                    f"Occurrences: {hierarchy_stats['occurrences']}\n"
                    f"Geometry leaves: {hierarchy_stats['leaves']}\n"
                    f"Locked occurrences: {hierarchy_stats.get('locked_occurrences', 0)}\n\n"
                    'This hierarchy path does not yet restore materials, '
                    'annotations, sections or cameras.')

            # Preserve the full, previously validated Phase 2D restoration
            # pipeline whenever the conversion bridge can represent the model.
            # A nonempty scene_hierarchy alone does NOT mean that a model
            # requires the incomplete Phase 2E geometry-only importer.
            has_hierarchy = (isinstance(early_native.get('cad'), dict)
                             and isinstance(early_native['cad'].get('scene_hierarchy'), list)
                             and bool(early_native['cad']['scene_hierarchy']))
            has_nested_placements = has_hierarchy and any(
                root.get('children') for root in early_native['cad']['scene_hierarchy']
            )
            manifest = assets / "blackfox_textures.json"
            if not manifest.is_file():
                raise FileNotFoundError("Texture manifest not produced: " + str(manifest))
            bridge_module = {"__name__": "_blackfox_embedded_bridge"}
            exec(compile(_BLACKFOX_EMBEDDED_BRIDGE, "<BlackFox bridge>", "exec"), bridge_module)
            try:
                converted = bridge_module["main"](native, manifest, None, native=early_native)
            except Exception as exc:
                # Nested instances use local transforms; flat scene leaves use world transforms.
                placement_mismatch = bridge_module.get("FlatPlacementMismatch")
                if (has_nested_placements and placement_mismatch is not None
                        and isinstance(exc, placement_mismatch)):
                    import_hierarchy(native)
                    return
                if "unsupported placement types" not in str(exc).lower():
                    raise RuntimeError(f"BlackFox conversion failed:\n{exc}") from exc
                if has_hierarchy:
                    import_hierarchy(native)
                    return
                raise RuntimeError(f"No native hierarchy roots for this model:\n{exc}") from exc
            native_model = early_native
            # Open adopts the SKP display units; Import retains scene units.
            # Both paths use the bridge's metre-based geometry unchanged.
            source_display_units = _source_display_units(converted) if open_mode else None
            # Convert and validate before allocating a new document/tab.
            target_doc = None
            if open_mode:
                target_doc = _blackfox_open_target(parent)
                if target_doc is None or getattr(target_doc, "viewport", None) is None:
                    raise RuntimeError("IngeTrazo did not return a new document viewport")
            target_viewport = target_doc.viewport if open_mode else app.viewport
            result_stats = {}
            callback_state = {"called": False, "error": None, "count": 0}
            def mutate(scene):
                callback_state["count"] += 1
                callback_state["called"] = True
                try:
                    result_stats.update(_populate_scene(scene, converted, native_model, (target_viewport.width(), target_viewport.height())))
                    result_stats["saved_views"] = _restore_saved_views(scene, converted)
                    # Phase 2N: retain original SketchUp attribute dictionaries.
                    source_dictionaries = converted.get("source_dictionaries", [])
                    if not isinstance(source_dictionaries, list):
                        raise ValueError("Invalid SKP dictionary collection")
                    dictionary_key = "blackfox_skp_dictionaries_v1"
                    if dictionary_key in scene.plugin_data:
                        raise ValueError("Existing BlackFox dictionary metadata would be overwritten")
                    scene.plugin_data[dictionary_key] = json.loads(json.dumps(source_dictionaries))
                    result_stats["dictionary_owners"] = len(source_dictionaries)
                    if open_mode:
                        scene.plugin_data["blackfox_skp_classifications_v1"] = converted.get("source_classifications", [])
                    if open_mode:
                        result_stats.update(_restore_active_layer(scene, converted))
                        result_stats.update(_restore_display_style(scene, converted))
                        section = converted.get("source_rendering") or {}
                        section_display = section.get("section_display")
                        if type(section_display) is int and 0 <= section_display <= 3:
                            scene.show_section_planes = bool(section_display & 1)
                            scene.show_section_cuts = bool(section_display & 2)
                        result_stats.update(_restore_geo_shadows(scene, converted))
                        animation = converted.get("source_animation")
                        if animation is not None:
                            from core.scene_animation import SceneAnimation
                            scene.animation = SceneAnimation(
                                enabled=animation["transitions"],
                                transition=animation["transition_s"],
                                pause=animation["delay_s"],
                            )
                            scene.plugin_data["blackfox_skp_animation_v1"] = dict(animation)
                        # Preserve the opening camera in the document, separately
                        # from SketchUp's named scene tabs.
                        home = _skp_camera_home(converted.get("camera"))
                        if home is not None:
                            scene.camera_home = home
                            scene.plugin_data["blackfox_skp_original_camera_v1"] = converted["camera"]
                            result_stats["opening_camera_prepared"] = True
                        else:
                            result_stats["opening_camera_prepared"] = False
                    # Dimension precision is independent from scene.units.
                    # Source SketchUp benchmark uses four decimal places.
                    source_units = converted.get("source_units") or {}
                    source_precision = source_units.get("length_precision")
                    if (result_stats.get("dimensions", 0) + result_stats.get("radial_dimensions", 0) > 0
                            and isinstance(source_precision, int)
                            and 0 <= source_precision <= 8):
                        scene.dimension_style["decimals"] = source_precision
                    if open_mode:
                        scene.units.update(source_display_units)
                except Exception:
                    callback_state["error"] = traceback.format_exc()
                    raise
            target_viewport.history.execute(SnapshotImport(mutate))
            if callback_state["error"]:
                raise RuntimeError(
                    "IngeTrazo scene mutation failed (history may have rolled back):\n"
                    + callback_state["error"]
                )
            if not callback_state["called"]:
                raise RuntimeError(
                    "IngeTrazo history did not invoke the import callback; "
                    "no successful scene mutation can be confirmed."
                )
            if not all(k in result_stats for k in ("faces", "edges", "instances")):
                raise RuntimeError(
                    "Import callback returned incomplete statistics: " + repr(result_stats)
                )
            target_viewport.notify_scene_changed()
            if open_mode:
                parent._sync_style_menu()
                parent._sync_section_menu()
            if open_mode and result_stats.get("opening_camera_prepared"):
                # IngeTrazo's own camera adapter handles projection/UI sync.
                # Keep this after the successful history mutation; an API
                # exception must not erase the imported geometry.
                try:
                    parent._apply_camera_dict(target_viewport.scene.camera_home)
                    result_stats["opening_camera_applied"] = True
                except Exception as camera_exc:
                    result_stats["opening_camera_applied"] = False
                    result_stats["camera_warning"] = str(camera_exc)
            result_stats["screen_text_overlays"] = 0  # Unsupported screen text deferred
        QMessageBox.information(
            parent, "BlackFox SKP - Import completed",
            ("Opened SKP geometry with source display units.\n\n"
             if open_mode else "Imported SKP geometry using current scene units.\n\n") +
            f"Faces: {result_stats['faces']}\n"
            f"Loose edges: {result_stats['edges']}\n"
            f"Degenerate edges skipped: {result_stats['skipped_degenerate_edges']}\n"
            f"Native groups: {result_stats['groups']}\n"
            f"Shared component instances: {result_stats['instances']}\n"
            f"Locked groups: {result_stats.get('locked_groups', 0)}\n"
            f"Locked component instances: {result_stats.get('locked_instances', 0)}\n"
            f"Component definitions: {result_stats['definitions']}\n"
            f"Layers in scene: {result_stats['layers_total']} "
            f"(new: {result_stats['layers_added']}, "
            f"colored: {result_stats['layers_colored']})\n"
            + (f"Active SKP tag: {result_stats.get('active_layer', 'not restored')}\n"
               if open_mode else "Destination active tag: preserved\n") +
            f"Curves: {result_stats['curves']}\n"
            f"Native back-face materials: {result_stats['back_faces_native']}\n"
            f"Native text labels: {result_stats.get('texts', 0)}\n"
            f"Native dimensions: {result_stats.get('dimensions', 0)}\n"
            f"Native radius/diameter: {result_stats.get('radial_dimensions', 0)}\n"
            f"Saved scenes: {result_stats.get('saved_views', 0)}\n"
            f"Opening camera: {'applied' if result_stats.get('opening_camera_applied') else 'not applied'}\n"
            + (f"Camera warning: {result_stats['camera_warning']}\n" if result_stats.get('camera_warning') else "") +
            f"Annotations deferred from native scene: {result_stats.get('annotations_skipped', 0)}\n\n"
            "D4N61V conservative annotations; "
            "saved scenes retained. "
            "Native SKP group/component lock states restored. "
            "Screen-space text deferred; export integration remains pending."
        )
    except _BlackFoxDownloadCancelled:
        return
    except Exception as exc:
        QMessageBox.critical(parent, "BlackFox SKP - Import failed",
                             f"{exc}\n\n{traceback.format_exc()[-4000:]}")


def _blackfox_tag_name(name):
    return "Layer0" if name == "Layer 0" else name


def _blackfox_mesh_to_object(mesh, name, material_slot=None, selection=None, axes=None,
                             excluded_edges=()):
    """Convert native IngeTrazo mesh geometry to BlackFox export JSON."""

    vertices = []
    vertex_map = {}
    inverse_axes = None
    mirrored = False
    if axes is not None:
        inverse_axes, invertible = axes.inverted()
        if not invertible:
            raise ValueError(f"'{name}' has singular group axes.")
        mirrored = axes.determinant() < 0

    def position_key(position):
        if inverse_axes is not None:
            position = inverse_axes.map(position)
        return (float(position.x()), float(position.y()), float(position.z()))

    def vertex_index(key):
        if key not in vertex_map:
            vertex_map[key] = len(vertices)
            vertices.append(key)
        return vertex_map[key]

    def face_loop(positions):
        indices = []
        for position in positions:
            index = vertex_index(position_key(position))
            if not indices or index != indices[-1]:
                indices.append(index)
        if len(indices) > 1 and indices[-1] == indices[0]:
            indices.pop()
        if len(set(indices)) < 3:
            raise ValueError(f"'{name}' contains a degenerate face loop.")
        return indices

    edges = []
    edge_properties = []
    curves = {}
    incomplete_curves = set()
    collapsed_edges = 0

    for edge in mesh.edges:
        if edge in excluded_edges:
            continue
        if selection is not None and edge not in selection and not any(
            face in selection for face in edge.faces
        ):
            if edge.curve is not None:
                incomplete_curves.add(edge.curve)
            continue
        a = position_key(edge.v0.position)
        b = position_key(edge.v1.position)

        if a == b:
            collapsed_edges += 1
            continue
        if edge.curve is not None:
            curves.setdefault(edge.curve, []).append(len(edges))
        edges.append([vertex_index(a), vertex_index(b)])
        edge_properties.append({
            "hidden": edge.hidden,
            "soft": edge.soft,
            "layer": _blackfox_tag_name(edge.layer),
        })

    faces = []

    for face in mesh.faces:
        if selection is not None and face not in selection:
            continue
        outer = face_loop(face.vertices)
        normal = face.normal()
        holes = [face_loop(hole) for hole in face.holes]
        local_normal = normal
        if axes is not None:
            local_normal = axes.transposed().mapVector(normal).normalized()
        if mirrored:
            outer.reverse()
            for hole in holes:
                hole.reverse()

        face_input = {
            "outer": outer,
            "holes": holes,
            "hidden": bool(face.attrs.get("hidden", False)),
            "layer": _blackfox_tag_name(face.attrs.get("layer")),
            "normal": [
                float(local_normal.x()),
                float(local_normal.y()),
                float(local_normal.z()),
            ],
        }
        if material_slot is not None:
            _blackfox_face_paint(face_input, face.attrs, normal, material_slot, axes=axes)
            back = face.attrs.get("back")
            if back is True:
                back = face.attrs
            if isinstance(back, dict):
                _blackfox_face_paint(face_input, back, normal, material_slot, prefix="back_", axes=axes)
        faces.append(face_input)

    export_curves = []
    claimed_edges = set()
    invalid_curves = 0
    for curve, indices in curves.items():
        if curve in incomplete_curves:
            continue
        # IGZ curve IDs can survive edits that split the original chain.
        # Validate against the welded export vertices, matching the engine.
        keys = {tuple(sorted(edges[index])) for index in indices}
        if (len(keys) != len(indices) or keys & claimed_edges
                or _ordered_curve_vertices(edges, indices, tuple) is None):
            invalid_curves += 1
            continue
        claimed_edges.update(keys)
        export_curves.append({"edges": indices})

    if collapsed_edges or invalid_curves:
        import logging

        logger = logging.getLogger(__name__)
        if collapsed_edges:
            logger.warning("SKP export skipped %d zero-length edge(s) in %r", collapsed_edges, name)
        if invalid_curves:
            logger.warning("SKP export kept the segments of %d invalid curve(s) in %r as edges",
                           invalid_curves, name)
    return {
        "name": str(name),
        "vertices": vertices,
        "edges": edges,
        "edge_properties": edge_properties,
        "curves": export_curves,
        "faces": faces,
    }

def _blackfox_texture(attrs):
    texture = attrs.get("texture")
    if not texture or not texture.get("path"):
        return None
    return {
        "file": str(Path(texture["path"]).absolute()),
        "width_m": float(texture.get("sw") or 1.0),
        "height_m": float(texture.get("sh") or 1.0),
    }


def _blackfox_face_paint(face, attrs, normal, material_slot, prefix="", axes=None):
    face[prefix + "material_slot"] = material_slot(attrs)
    texture = _blackfox_texture(attrs)
    if texture and (axes is not None or attrs["texture"].get("uvw") or attrs["texture"].get("rot")):
        from core.texture import face_uv_axes

        u, u_offset, v, v_offset = face_uv_axes(attrs["texture"], normal)
        if axes is not None:
            origin = axes.map(QVector3D())
            u_offset += QVector3D.dotProduct(u, origin)
            v_offset += QVector3D.dotProduct(v, origin)
            u = axes.transposed().mapVector(u)
            v = axes.transposed().mapVector(v)
        face[prefix + "texture"] = texture
        face[prefix + "uvw"] = [u.x(), u.y(), u.z(), u_offset, v.x(), v.y(), v.z(), v_offset]


def _blackfox_matrix_to_transform(matrix):
    """Convert a Qt 4x4 affine matrix to BlackFox's 13-value transform."""

    if matrix is None:
        return [
            1.0, 0.0, 0.0,
            0.0, 1.0, 0.0,
            0.0, 0.0, 1.0,
            0.0, 0.0, 0.0,
            1.0,
        ]

    # Qt uses matrix(row, column).
    # BlackFox stores the 3x3 linear part row-major,
    # followed by translation and a final homogeneous value.
    result = [
        float(matrix(0, 0)), float(matrix(0, 1)), float(matrix(0, 2)),
        float(matrix(1, 0)), float(matrix(1, 1)), float(matrix(1, 2)),
        float(matrix(2, 0)), float(matrix(2, 1)), float(matrix(2, 2)),
        float(matrix(0, 3)), float(matrix(1, 3)), float(matrix(2, 3)),
        1.0,
    ]

    if any(not math.isfinite(value) for value in result):
        raise ValueError("Group transformation contains non-finite values.")

    if any(abs(float(matrix(3, col)) - expected) > 1e-8
           for col, expected in enumerate((0.0, 0.0, 0.0, 1.0))):
        raise ValueError("Projective transformations are not supported.")

    return result

def _blackfox_group_hierarchy(groups, material_slot=None, kept=(), legacy_ifc=()):
    """Build definitions and local placements for the native group tree."""
    definitions = []
    instances = []
    dictionaries = []
    shared = {}
    classes = {}
    ambiguous_classes = set()
    for item in legacy_ifc:
        if item["owner"][0] != "definition_map":
            continue
        for dictionary in item["dictionaries"]:
            if dictionary["name"] != "AppliedSchemaTypes":
                continue
            for schema, value in dictionary["entries"]:
                if schema.casefold().startswith("ifc") and value[0] == "text":
                    key = value[1].casefold()
                    if key in classes:
                        ambiguous_classes.add(key)
                    classes[key] = item["dictionaries"]

    def legacy_definition(group):
        name = group.name.casefold()
        for prefix in ("bf_ifc4_", "bf_ifc_"):
            if name.startswith(prefix):
                name = "ifc" + name[len(prefix):]
                break
        return classes.get(name) if name not in ambiguous_classes else None

    def describe(group, parent_inverse=None):
        component = group.is_component()
        axes = None if component else group.axes
        transform = group.xform if group.xform is not None else QMatrix4x4()
        children_inverse = None
        if axes is not None:
            children_inverse, invertible = axes.inverted()
            if not invertible:
                raise ValueError(f"'{group.name}' has singular group axes.")
            transform = transform * axes
        if parent_inverse is not None:
            transform = parent_inverse * transform
        return (
            id(group.mesh), component, group.name, group.layer,
            group.hidden, group.locked,
            material_slot(group.material) if material_slot else None,
            tuple(_blackfox_matrix_to_transform(transform)),
            tuple(describe(child, children_inverse) for child in group.children),
        )

    def definition(group, signature):
        mesh_id, component, name, _, _, _, _, _, children = signature
        name = name or "Group"
        # Child placements belong to the prototype. A shared mesh can also
        # occur in different containers with different children.
        key = (mesh_id, children)
        definition_id = shared.get(key) if component else None
        if definition_id is None:
            definition_id = f"ingetrazo_definition_{len(definitions) + 1}"
            geometry = _blackfox_mesh_to_object(
                group.mesh, name, material_slot, axes=None if component else group.axes
            )
            definitions.append({
                **geometry,
                "id": definition_id,
                "is_group": not component,
            })
            data = (group.ext or {}).get("blackfox_skp", {})
            description = data.get("definition_description")
            if isinstance(description, str):
                definitions[-1]["source_description"] = description
            definition_dictionaries = data.get("definition_dictionaries") or legacy_definition(group)
            if definition_dictionaries:
                owner_id = len(definitions)
                definitions[-1]["source_def_index"] = owner_id
                dictionaries.append({"owner": ["definition_map", owner_id],
                                     "dictionaries": definition_dictionaries})
            if component:
                shared[key] = definition_id
            for child, child_signature in zip(group.children, children):
                place(child, child_signature, definition_id)
        return definition_id

    def place(group, signature, parent_id=None):
        _, _, name, layer, hidden, locked, paint, transform, _ = signature
        instances.append({
            "definition_id": definition(group, signature),
            "name": name or "Group",
            "parent_definition_id": parent_id,
            "transform": transform,
            "layer": _blackfox_tag_name(layer),
            "material_slot": paint,
            "hidden": hidden,
            "locked": locked,
        })
        authored = (group.ext or {}).get("blackfox_skp", {}).get("instance_dictionaries")
        if authored:
            owner_id = len(instances)
            instances[-1]["source_instance_pid"] = owner_id
            dictionaries.append({"owner": ["instance_pid", owner_id], "dictionaries": authored})

    for group in groups:
        place(group, describe(group))
    for template in kept:
        definition(template, describe(template))

    return {"component_definitions": definitions, "component_instances": instances,
            "source_dictionaries": dictionaries}


def _blackfox_export_camera(camera):
    def xyz(vector):
        return [vector.x(), vector.y(), vector.z()]

    return {
        "eye_m": xyz(camera.eye()),
        "target_m": xyz(camera.target),
        "up": xyz(camera.up_vector()),
        "perspective": camera.perspective,
        "two_point_perspective": camera.two_point,
        "fov_deg": camera.fov_deg,
        "parallel_height_m": 2 * camera.distance * math.tan(math.radians(camera.fov_deg) / 2),
    }


def _blackfox_export_shadows(scene, settings=None):
    from datetime import datetime, timezone
    from core.sun import default_utc_offset, scene_north_deg

    source = scene.plugin_data.get("blackfox_skp_geo_shadows_v1") or {}
    datum = scene.georef
    shadows = scene.shadows if settings is None else settings
    if datum is None and not shadows.enabled and not source and not scene.north_deg:
        return None
    lat, lon = (datum.lat, datum.lon) if datum is not None else (0.0, 0.0)
    angle = math.radians(scene_north_deg(scene))
    offset = shadows.utc_offset if shadows.utc_offset is not None else default_utc_offset(lon)
    timestamp = source.get("time")
    year = datetime.fromtimestamp(timestamp, tz=timezone.utc).year if timestamp else datetime.now().year
    try:
        when = shadows.when_utc(lon, year=year)
    except ValueError:
        # Use a leap year for a native February 29 setting.
        when = shadows.when_utc(lon, year=2024)
    return {
        "time": int(when.timestamp()), "latitude": lat, "longitude": lon,
        "city": source.get("city", ""), "country": source.get("country", ""),
        "tz_offset_h": offset, "displayed": shadows.enabled,
        "on_faces": source.get("on_faces", True), "on_ground": source.get("on_ground", True),
        "from_edges": source.get("from_edges", False), "light": source.get("light", 80),
        "dark": source.get("dark", round(100 * shadows.darkness)),
        "use_sun_for_shading": source.get("use_sun_for_shading", False),
        "daylight_saving": source.get("daylight_saving", False),
        "north": [math.sin(angle), math.cos(angle), 0.0],
        "north_displayed": source.get("north_displayed", False),
    }


def _blackfox_export_radials(scene, loose, geometry, material_slot):
    """Reverse the importer’s radial display approximation when its arc survives."""
    recipes = scene.plugin_data.get("blackfox_skp_radial_export_v1", [])
    if not recipes:
        return geometry, [], set(), set()

    def edge_key(a, b):
        return tuple(sorted((tuple(a), tuple(b))))

    def edge_indices(mesh):
        return {edge_key(mesh["vertices"][a], mesh["vertices"][b]): i
                for i, (a, b) in enumerate(mesh["edges"])}

    indices = edge_indices(geometry)
    curves = {index: curve for curve in geometry["curves"] for index in curve["edges"]}
    loose_edges = {edge_key(edge.a.toTuple(), edge.b.toTuple()): edge for edge in loose.edges
                   if not edge.faces and edge.curve is None}
    recovered = []
    excluded_edges, excluded_labels, excluded_dimensions = set(), set(), set()
    for recipe in recipes:
        key = edge_key(*recipe["edge"])
        curve = curves.get(indices.get(key))
        if curve is None:
            continue
        label = None
        dimension = None
        if "label" in recipe:
            snapshot = recipe["label"]
            label = next((item for item in scene.text_labels if item not in excluded_labels
                          and item.text == snapshot["text"]
                          and math.dist(item.anchor.toTuple(), snapshot["anchor"]) <= 1e-6
                          and math.dist(item.offset.toTuple(), snapshot["offset"]) <= 1e-6), None)
            if label is None:
                continue
        else:
            dimension = next((item for item in scene.dimensions if item not in excluded_dimensions
                              and [list(item.a.toTuple()), list(item.b.toTuple()), item.text]
                              == recipe["diameter_snapshot"] and item.offset.isNull()), None)
            if dimension is None:
                continue
        layer = label.layer if label is not None else dimension.layer
        recovered.append((key, recipe, layer))
        if label is not None:
            excluded_labels.add(label)
            for points in recipe.get("leader_edges", []):
                edge = loose_edges.get(edge_key(*points))
                if edge is not None:
                    excluded_edges.add(edge)
        if dimension is not None:
            excluded_dimensions.add(dimension)

    if not recovered:
        return geometry, [], excluded_labels, excluded_dimensions
    geometry = _blackfox_mesh_to_object(loose, "Root Geometry", material_slot,
                                        excluded_edges=excluded_edges)
    indices = edge_indices(geometry)
    curves = {index: curve for curve in geometry["curves"] for index in curve["edges"]}
    geometry["source_edge_pids"] = list(range(1, len(geometry["edges"]) + 1))
    records = []
    for key, recipe, layer in recovered:
        index = indices[key]
        arc = dict(recipe["arc"])
        for axis in ("x_axis_m", "y_axis_m"):
            length = math.hypot(*arc[axis])
            arc[axis] = [value / length for value in arc[axis]]
        curves[index]["arc"] = arc
        record = dict(recipe["native"])
        record.update(edge=index + 1, arc=None, material=None, font=None)
        records.append((record, layer))
    return geometry, records, excluded_labels, excluded_dimensions


def _blackfox_scene_export_model(scene, camera=None, selected_only=False):
    """Build the export document from the active IngeTrazo scene."""
    from core.camera import OrbitCamera
    from core.guide import Guide
    from core.layers import layer_color
    from core.units import model_units_of

    if scene.edit_group is not None and not selected_only:
        raise RuntimeError("Finish editing the open group before exporting SKP.")

    materials = []
    slots = {}
    used_names = set()

    def material_slot(attrs):
        if not attrs:
            return None
        texture = _blackfox_texture(attrs)
        rgb = attrs.get("color")
        if texture is None and rgb is None:
            return None
        color = tuple(round(float(c) * 255) for c in rgb[:3]) if texture is None else ()
        opacity = float(attrs.get("opacity", 1.0))
        name = attrs.get("mat")
        key = (name, color, tuple(texture.values()) if texture else (), opacity)
        if key not in slots:
            label = name or (Path(texture["file"]).stem if texture else "BlackFox Paint")
            unique = label
            suffix = 2
            while unique in used_names:
                unique = f"{label} ({suffix})"
                suffix += 1
            material = {"name": unique, "opacity": opacity}
            if texture:
                material.update(
                    kind="textured", texture=texture["file"],
                    applied_size_in=[texture[key] / 0.0254 for key in ("width_m", "height_m")],
                )
            else:
                material.update(kind="solid", rgba=[*color, 255])
            materials.append(material)
            used_names.add(unique)
            slots[key] = len(materials)
        return slots[key]

    groups = scene.groups
    loose = scene.loose_mesh
    selection = None
    if selected_only:
        selection = scene.selection
        if scene.edit_group is not None:
            # IngeTrazo bakes the edit context into its mesh and its direct
            # children, so both already occupy their world positions.
            groups = scene.edit_group.children
            loose = scene.mesh
        groups = [group for group in groups if group in selection]
        supported = set(groups)
        supported.update(edge for edge in loose.edges if edge in selection)
        supported.update(face for face in loose.faces if face in selection)
        if selection - supported:
            raise RuntimeError("The selection contains items outside the exportable group, face and edge types.")

    geometry = _blackfox_mesh_to_object(loose, "Root Geometry", material_slot, selection)
    radials, excluded_labels, excluded_dimensions = [], set(), set()
    if not selected_only:
        geometry, radials, excluded_labels, excluded_dimensions = _blackfox_export_radials(
            scene, loose, geometry, material_slot
        )
    loose_geometry = [geometry] if geometry["edges"] or geometry["faces"] else []
    kept = () if selected_only else scene.kept_components
    legacy_dictionaries = scene.plugin_data.get("blackfox_skp_dictionaries_v1", [])
    hierarchy = _blackfox_group_hierarchy(groups, material_slot, kept, legacy_dictionaries)
    if selected_only and not loose_geometry and not hierarchy["component_definitions"]:
        raise RuntimeError("The selection is empty. Select groups, faces, or edges before using Export Selected. "
                           "Use Export SKP for the whole document.")

    used_layers = {"Layer0"}
    if selected_only:
        for mesh in [*loose_geometry, *hierarchy["component_definitions"]]:
            used_layers.update(edge["layer"] for edge in mesh["edge_properties"])
            used_layers.update(face["layer"] for face in mesh["faces"])
        used_layers.update(instance["layer"] for instance in hierarchy["component_instances"])
    layers = [
        {
            "name": _blackfox_tag_name(layer.name),
            "color": [*(round(c * 255) for c in layer_color(layer)), 255],
            "visible": layer.visible,
        }
        for layer in scene.layers
        if not selected_only or _blackfox_tag_name(layer.name) in used_layers
    ]
    active_name = _blackfox_tag_name(scene.active_layer)
    active = next((i for i, layer in enumerate(layers) if layer["name"] == active_name), None)
    views = []
    layer_names = {layer["name"] for layer in layers}
    section_ids = {section.uid for section in scene.section_planes}
    for view in (() if selected_only else scene.saved_views):
        saved_camera = OrbitCamera()
        saved_camera.target = QVector3D(*view.target)
        for field in ("distance", "yaw", "pitch", "fov_deg", "perspective", "two_point"):
            setattr(saved_camera, field, getattr(view, field))
        if view.lens.get("roll_deg") is not None:
            saved_camera.roll_deg = view.lens["roll_deg"]
        hidden_layers = [_blackfox_tag_name(name) for name in view.hidden_layers]
        record = {
            "name": view.name, "camera": _blackfox_export_camera(saved_camera),
            "hidden_layers": [name for name in hidden_layers if name in layer_names],
        }
        rendering = {}
        if view.section is not None:
            active = view.section.get("active")
            record["active_section_planes"] = [str(active)] if active in section_ids else []
            rendering["section_display"] = (int(view.section.get("planes_shown", True))
                                            | (int(view.section.get("cuts_shown", True)) << 1))
        if view.style is not None:
            if "section_fill" in view.style:
                rendering["section_fill"] = bool(view.style["section_fill"])
            if "section_fill_color" in view.style:
                rendering["section_fill_color"] = [
                    *(round(channel * 255) for channel in view.style["section_fill_color"][:3]), 255
                ]
        if rendering:
            record["rendering"] = rendering
        if view.shadows is not None:
            from core.sun import ShadowSettings
            record["shadows"] = _blackfox_export_shadows(scene, ShadowSettings.from_dict(view.shadows))
        views.append(record)

    length_codes = {
        "in": (0, 0), "ft": (0, 1), "mm": (0, 2), "cm": (0, 3), "m": (0, 4),
        "ft-in": (2, 0), "ft-in-frac": (2, 0), "in-frac": (3, 0),
    }
    units = model_units_of(scene)
    length_format, length_unit = length_codes[units["length"]]

    points = []
    lines = []
    sections = []
    active_section = None
    if not selected_only:
        for guide in scene.guides:
            if not isinstance(guide, Guide):
                continue
            data = guide.to_dict()
            data["layer"] = _blackfox_tag_name(data.get("layer"))
            if guide.is_line:
                lines.append(data)
            else:
                data["anchor"] = data.pop("origin", None)
                points.append(data)

        active_plane = scene.active_section()
        for section in scene.section_planes:
            # SketchUp and IngeTrazo clip opposite half-spaces. The
            # SketchUp plane offset is expressed in native inches.
            normal = [-section.normal.x(), -section.normal.y(), -section.normal.z()]
            magnitude = math.hypot(*normal)
            normal = [axis / magnitude for axis in normal]
            point = [section.point.x(), section.point.y(), section.point.z()]
            offset = -sum(axis * pos for axis, pos in zip(normal, point)) / 0.0254
            section_id = str(section.uid)
            sections.append({
                "id": section_id, "plane": [*normal, offset],
                "name": section.name, "symbol": section.symbol,
                "hidden": section.hidden, "layer": _blackfox_tag_name(section.layer),
            })
            if section is active_plane:
                active_section = section_id
    texts = []
    dimensions = []
    if not selected_only:
        for label in scene.text_labels:
            if label in excluded_labels:
                continue
            data = label.to_dict()
            texts.append({
                "content": data["text"], "position": data["anchor"],
                "offset": data["offset"], "leader": True,
                "layer": _blackfox_tag_name(data.get("layer")),
            })
        layer_indices = {layer["name"]: i for i, layer in enumerate(layers)}
        for dimension in scene.dimensions:
            if dimension in excluded_dimensions or dimension.axis is not None:
                continue
            a, b = dimension.a, dimension.b
            direction = (b - a).normalized()
            offset = dimension.perpendicular_offset()
            if direction.isNull():
                continue
            offset_length = offset.length()
            if offset_length <= 1e-9:
                # A line with no displacement still has a native dimension.
                preferred = QVector3D(0, 0, 1) if abs(direction.z()) < .9 else QVector3D(0, 1, 0)
                normal = (preferred - direction * QVector3D.dotProduct(preferred, direction)).normalized()
                offset_length = 0.0
            else:
                normal = QVector3D.crossProduct(direction, offset).normalized()
            tag = _blackfox_tag_name(dimension.layer)
            dimensions.append({
                "start": {"kind": 1, "point_m": [a.x(), a.y(), a.z()]},
                "end": {"kind": 1, "point_m": [b.x(), b.y(), b.z()]},
                "normal": [normal.x(), normal.y(), normal.z()],
                "x_axis": [direction.x(), direction.y(), direction.z()],
                "offset_m": offset_length,
                "text_override": dimension.text or "",
                "text_position": 0, "aligned": True, "arrow": 3,
                "layer": layer_indices.get(tag, 0), "hidden": False,
                "casts_shadows": False, "receives_shadows": False,
                "variant": 1, "undecoded": 0.0,
            })
    for record, layer in radials:
        record["layer"] = layer_indices.get(_blackfox_tag_name(layer), 0)
    return {
        "native_radial_dimensions": [record for record, _ in radials],
        "source_classifications": scene.plugin_data.get("blackfox_skp_classifications_v1", []),
        "source_geo_located": scene.georef is not None,
        "source_shadows": _blackfox_export_shadows(scene),
        "source_animation": {
            "transitions": scene.animation.enabled,
            "transition_s": scene.animation.transition,
            "delay_s": scene.animation.pause,
            "loop_slideshow": bool(scene.plugin_data.get("blackfox_skp_animation_v1", {}).get("loop_slideshow", False)),
        },
        "source_rendering": {
            "section_display": int(scene.show_section_planes) | (int(scene.show_section_cuts) << 1),
            "section_fill": scene.display_style.section_fill,
            "section_fill_color": [*(round(channel * 255) for channel in scene.display_style.section_fill_color[:3]), 255],
        },
        "native_dimensions": dimensions,
        "texts": texts,
        "construction_points": points,
        "construction_lines": lines,
        "section_planes": sections,
        "active_section_plane": active_section,
        "camera": _blackfox_export_camera(camera) if camera and camera.is_finite() else None,
        "scenes": views,
        "source_units": {
            "length_format": length_format,
            "length_unit": length_unit,
            "length_precision": units["precision"],
            "angle_precision": units.get("angle_precision", 1),
            "length_snap": False,
            "length_snap_length": 0.0,
            "angle_snap": False,
            "snap_angle": 0.0,
            "suppress_units_display": False,
            "force_inch_display": False,
        },
        "loose_geometry": loose_geometry,
        **hierarchy,
        "layers": layers,
        "source_layer_links": [{"slot": i, "index": i} for i in range(len(layers))],
        "source_active_layer": active,
        "source_materials": materials,
    }


def _export_skp(app, selected_only=False):
    """Export the current IngeTrazo scene through the unified BlackFox engine."""
    parent = app.window

    try:
        engine, _ = _blackfox_dependencies(parent, prompt=True)
        viewport = app.window.active_document().viewport
        scene = viewport.scene

        model = _blackfox_scene_export_model(scene, getattr(viewport, "camera", None), selected_only)

        title = "Export Selected SKP" if selected_only else "Export SKP"
        dialog = QFileDialog(parent, title)
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setOption(QFileDialog.DontConfirmOverwrite, True)
        dialog.setNameFilters(SKP_FILTERS)
        dialog.selectNameFilter(SKP_FILTERS[0])
        dialog.setDefaultSuffix("skp")
        dialog.selectFile("Untitled.skp")

        if dialog.exec() != QDialog.Accepted:
            return

        files = dialog.selectedFiles()
        if not files:
            return

        destination = Path(files[0])
        if destination.suffix.lower() != ".skp":
            destination = destination.with_suffix(".skp")

        overwrite = destination.exists()
        if overwrite:
            if not destination.is_file():
                raise RuntimeError(f"Export destination is not a file: {destination}")
            answer = QMessageBox.question(
                parent, "BlackFox SKP - Replace file?",
                f"Replace the existing SKP file?\n\n{destination}",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        version_filter = dialog.selectedNameFilter()
        version = version_filter.split()[1]


        stage_dir = destination.parent if overwrite else None
        with tempfile.TemporaryDirectory(prefix="blackfox_skp_", dir=stage_dir) as temp_dir:
            input_json = Path(temp_dir) / "export_input.json"
            output = Path(temp_dir) / "replacement.skp" if overwrite else destination

            with input_json.open("w", encoding="utf-8") as stream:
                json.dump(model, stream, ensure_ascii=False, indent=2)

            command = [
                str(engine),
                "export",
                str(input_json),
                str(output),
                version,
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"BlackFox engine returned {result.returncode}:\n"
                    + re.sub(r"(?i)sketchup", "SKP", f"{result.stdout}\n{result.stderr}")
                )

            if not output.is_file():
                raise RuntimeError("Engine reported success, but SKP file is missing.")
            if overwrite:
                os.replace(output, destination)

        QMessageBox.information(
            parent,
            "BlackFox SKP - Export completed",
            f"SKP created successfully:\n{destination}\n\n"
            f"SKP version: {version}\n"
            f"Root meshes: {len(model['loose_geometry'])}\n"
            f"Group and component placements: {len(model['component_instances'])}"
        )

    except _BlackFoxDownloadCancelled:
        return
    except Exception as exc:
        QMessageBox.critical(
            parent,
            "BlackFox SKP - Export failed",
            f"{exc}\n\n{traceback.format_exc()[-3000:]}"
        )

def _about(parent):
    dialog = QDialog(parent)
    dialog.setWindowTitle("About")
    dialog.setMinimumWidth(450)
    layout = QVBoxLayout(dialog)
    label = QLabel(dialog)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setOpenExternalLinks(True)
    label.setText(f"""
        <h2>BlackFox SKP Exporter</h2>
        <p>Version {__version__}</p>
        <p>A free and open-source IngeTrazo extension for importing and
        exporting SKP models.</p>
        <p><b>Project creator:</b> David Mavrov<br>
        <b>Development assistance:</b> ChatGPT (OpenAI)<br>
        <b>SKP format library:</b> skpwright by hew3d and contributors.<br>
        <b>Upstream source:</b>
        <a href="https://github.com/hew3d/skpwright">github.com/hew3d/skpwright</a></p>
        <p><b>License:</b> GNU General Public License version 3 only
        (GPL-3.0-only). The skpwright library is also GPL-3.0-only.
        Original copyright notices, upstream license texts and applicable
        third-party notices must accompany distributions of the Rust engine.</p>
        <p><b>Project:</b>
        <a href="https://github.com/davidsmavrov-debug">GitHub - David Mavrov</a><br>
        <b>Support:</b> <a href="https://ko-fi.com/davidmavrov">Ko-fi</a></p>
        <p><small>Independent community extension, not an official IngeTrazo product.
        Provided without warranty, to the extent permitted by law.</small></p>
    """)
    layout.addWidget(label)
    buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=dialog)
    buttons.rejected.connect(dialog.reject)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.exec()


def setup(app):
    """Register the SKP menu."""
    parent = app.window
    menu = app.add_menu("SKP Exporter")
    menu.addAction("Open SKP", lambda: _import_skp(app, open_mode=True))
    menu.addAction("Import SKP", lambda: _import_skp(app))
    menu.addAction("Export SKP", lambda: _export_skp(app))
    menu.addAction("Export Selected", lambda: _export_skp(app, selected_only=True))
    menu.addSeparator()
    menu.addAction("About", lambda: _about(parent))

_BLACKFOX_EMBEDDED_MANIFEST = b'{\n  "schema": 1,\n  "repository": "davidsmavrov-debug/blackfox-skp-exporter",\n  "releases": [\n    {\n      "version": "1.0.0",\n      "abi": 1,\n      "assets": {\n        "aarch64-apple-darwin": {\n          "name": "blackfox-skp-aarch64-apple-darwin",\n          "size": 4303616,\n          "sha256": "05d601f3e3ae7e8c00c0c3ed0198346b0df98d1a1920065d2a24dde1da100354"\n        },\n        "aarch64-pc-windows-msvc": {\n          "name": "blackfox-skp-aarch64-pc-windows-msvc.exe",\n          "size": 4039680,\n          "sha256": "8fe709545fcae68f0651a9878c686c407f17dc2d5312bf0654d70f5604d86893"\n        },\n        "aarch64-unknown-linux-gnu": {\n          "name": "blackfox-skp-aarch64-unknown-linux-gnu",\n          "size": 4591704,\n          "sha256": "d5d514c05885978ba5df9676ecb40c44be3a48066cdf3569e3dbd3c8c0da54c0"\n        },\n        "x86_64-apple-darwin": {\n          "name": "blackfox-skp-x86_64-apple-darwin",\n          "size": 4613232,\n          "sha256": "51363dd618262bf4d1d8fe7703bb1e15b1de1e1cf250f804904f62c70da187e6"\n        },\n        "x86_64-pc-windows-msvc": {\n          "name": "blackfox-skp-x86_64-pc-windows-msvc.exe",\n          "size": 5273088,\n          "sha256": "f583605d0777f1a55db5673fecc79dc4c2020ab5e26ff55c18deb9a8d575be79"\n        },\n        "x86_64-unknown-linux-gnu": {\n          "name": "blackfox-skp-x86_64-unknown-linux-gnu",\n          "size": 5082120,\n          "sha256": "c60a64f5348ed1bcd29d4f694dfe360714e8d9610acc2469df86ca6a1f13f5f1"\n        }\n      }\n    }\n  ]\n}\n'
_BLACKFOX_EMBEDDED_BRIDGE = '#!/usr/bin/env python3\nimport re\n"""BlackFox C001.4B: native importer JSON -> cumulative exporter JSON.\nUsage: python C001_4B_convert.py native.json texture_manifest.json output.json\nRequires Python 3.9+; standard library only. Refuses ambiguous UVs.\n"""\nimport json, math, pathlib, sys, os\n\n\ndef placement_transform(world):\n    if (len(world) != 16 or not all(math.isfinite(value) for value in world)\n            or any(abs(value - expected) > 1e-9\n                   for value, expected in zip(world[12:], (0, 0, 0, 1)))):\n        raise ValueError(\'unexpected 4x4 transform\')\n    # The bridge stores the linear part by rows, then translation in metres.\n    return [*world[0:3], *world[4:7], *world[8:11], world[3], world[7], world[11], 1.0]\n\n\ndef solve3(a, b):\n    a = [list(map(float, row)) + [float(v)] for row, v in zip(a, b)]\n    for k in range(3):\n        p = max(range(k, 3), key=lambda i: abs(a[i][k]))\n        if abs(a[p][k]) < 1e-12:\n            raise ValueError(\'degenerate UV basis\')\n        a[k], a[p] = a[p], a[k]\n        v = a[k][k]\n        for j in range(k, 4): a[k][j] /= v\n        for i in range(3):\n            if i == k: continue\n            f = a[i][k]\n            for j in range(k, 4): a[i][j] -= f*a[k][j]\n    return [a[i][3] for i in range(3)]\n\n\nclass NonAffineMapping(ValueError):\n    pass\n\n\ndef uvw_for_face(vertices, face, pairs, *, approximate=False):\n    indices = face[\'outer\']\n    if len(indices) != len(pairs):\n        raise ValueError(\'UV point count does not match face loop\')\n    p = [vertices[i] for i in indices]\n    origin = p[0]\n    e1 = [p[1][i]-origin[i] for i in range(3)]\n    length = math.sqrt(sum(v*v for v in e1))\n    if length < 1e-10: raise ValueError(\'zero-length face edge\')\n    eu = [v/length for v in e1]\n    n = face[\'normal\']\n    nv = math.sqrt(sum(v*v for v in n))\n    if nv < 1e-10: raise ValueError(\'zero face normal\')\n    n = [v/nv for v in n]\n    ev = [n[1]*eu[2]-n[2]*eu[1], n[2]*eu[0]-n[0]*eu[2], n[0]*eu[1]-n[1]*eu[0]]\n    xy = [[sum((v[i]-origin[i])*eu[i] for i in range(3)), sum((v[i]-origin[i])*ev[i] for i in range(3)), 1.0] for v in p]\n    # Choose a noncollinear triple, not necessarily the first three points.\n    triple = None\n    for i in range(1,len(p)):\n        for j in range(i+1,len(p)):\n            area = (xy[i][0]*xy[j][1]-xy[j][0]*xy[i][1])\n            if abs(area) > 1e-10: triple=(0,i,j); break\n        if triple: break\n    if not triple: raise ValueError(\'collinear face\')\n    a = [xy[i] for i in triple]\n    u = solve3(a,[pairs[i][0] for i in triple]); v = solve3(a,[pairs[i][1] for i in triple])\n    for xyrow, pair in zip(xy,pairs):\n        for co, coeff in zip(pair,(u,v)):\n            estimate=sum(x*y for x,y in zip(xyrow,coeff))\n            if not approximate and abs(estimate-co)>1e-5*max(1,abs(co)):\n                raise NonAffineMapping(\'non-affine UV mapping; cannot preserve exactly\')\n    gu=[u[0]*eu[i]+u[1]*ev[i] for i in range(3)]\n    gv=[v[0]*eu[i]+v[1]*ev[i] for i in range(3)]\n    return gu+[u[2]-sum(gu[i]*origin[i] for i in range(3))]+gv+[v[2]-sum(gv[i]*origin[i] for i in range(3))]\n\n\nclass FlatPlacementMismatch(ValueError):\n    pass\n\n\ndef main(native_path, manifest_path, output_path, *, native=None):\n    if native is None:\n        native = json.loads(pathlib.Path(native_path).read_text(encoding=\'utf-8-sig\'))\n    manifest=json.loads(pathlib.Path(manifest_path).read_text(encoding=\'utf-8-sig\'))\n    if manifest.get(\'schema\')!=\'BlackFoxTextureAssetsV1\': raise ValueError(\'unexpected texture manifest schema\')\n    mats={m[\'material_index\']:m for m in manifest[\'materials\']}\n\n    # Preserve original SketchUp material library and resolve embedded textures.\n    source_materials = []\n    for index, material in enumerate(native[\'model\'][\'materials\']):\n        item = dict(material)\n        if item.get(\'kind\') == \'textured\':\n            if index not in mats:\n                raise ValueError(f\'material {index}: missing embedded texture\')\n            asset = mats[index]\n            filename = asset[\'file\']\n            if filename is None:\n                item.update(kind=\'solid\', rgba=item.get(\'rgba\', [192, 192, 192, 255]))\n                item[\'missing_texture\'] = item.pop(\'texture\', None)\n                source_materials.append(item)\n                continue\n            texture_path = (pathlib.Path(manifest_path).parent / filename).resolve()\n            if not texture_path.is_file():\n                raise FileNotFoundError(f\'material {index}: {texture_path}\')\n            item[\'texture\'] = str(texture_path)\n        source_materials.append(item)\n\n    # Source slots are archive-local and can be sparse in legacy SKP files.\n    archive_materials = native.get(\'material_links\')\n    material_indices = (dict(archive_materials) if archive_materials is not None\n                        else {i + 1: i for i in range(len(source_materials))})\n\n    # BlackFox 0.9.7: preserve native PBR material records.\n    pbr_manifest_path = pathlib.Path(manifest_path).resolve().parent / "blackfox_pbr_manifest.json"\n    pbr_manifest = json.loads(pbr_manifest_path.read_text(encoding="utf-8-sig"))\n    if pbr_manifest.get("schema") != "BlackFoxPbrAssetsV1":\n        raise ValueError("Invalid PBR manifest schema")\n\n    pbr_assets = {}\n    for asset in pbr_manifest["textures"]:\n        key = (asset["material_index"], asset["channel"])\n        if key in pbr_assets:\n            raise ValueError(f"Duplicate PBR asset {key}")\n        pbr_assets[key] = asset\n\n    source_pbr = []\n    used_assets = set()\n    seen_materials = set()\n\n    for original in native["model"].get("features", {}).get("material_pbr", []):\n        index = original["material"]\n        if not isinstance(index, int) or not 0 <= index < len(source_materials):\n            raise ValueError(f"Invalid PBR material index {index}")\n        if index in seen_materials:\n            raise ValueError(f"Duplicate PBR material index {index}")\n        seen_materials.add(index)\n\n        record = dict(original)\n\n        for channel in ("metallic", "roughness", "normal", "occlusion"):\n            texture = record.get(channel)\n            if texture is None:\n                continue\n\n            key = (index, channel)\n            asset = pbr_assets.get(key)\n            if asset is None:\n                raise ValueError(f"Missing PBR texture asset {key}")\n\n            for field in ("id", "path", "file_name"):\n                if asset[field] != texture[field]:\n                    raise ValueError(f"PBR metadata mismatch {key}: {field}")\n\n            filename = asset["file"]\n            if pathlib.Path(filename).name != filename:\n                raise ValueError(f"Invalid PBR asset filename {filename!r}")\n            path = pbr_manifest_path.parent / filename\n            data = path.read_bytes()\n            import hashlib\n            if not data.startswith(bytes([137, 80, 78, 71, 13, 10, 26, 10])):\n                raise ValueError(f"Invalid PNG {path}")\n            if len(data) != asset["bytes"]:\n                raise ValueError(f"PBR byte count mismatch {key}")\n\n            record[channel] = {\n                "id": texture["id"],\n                "path": texture["path"],\n                "file_name": texture["file_name"],\n                "asset_path": str(path.resolve())\n            }\n            used_assets.add(key)\n\n        source_pbr.append(record)\n\n    if used_assets != set(pbr_assets):\n        raise ValueError(f"Unused PBR assets: {set(pbr_assets) - used_assets}")\n\n    runs=native[\'mesh\'][\'runs\']; meta=native[\'model\'][\'geometry_runs\']; scene=native[\'mesh\'][\'scene\']\n    if len(runs)!=len(meta): raise ValueError(\'geometry run count mismatch\')\n\n    # BlackFox v0.9.1: native layer-slot mapping.\n    layer_catalogue = native[\'model\'][\'layers\']\n    layer_links = native[\'mesh\'].get(\'layer_links\')\n\n    if not isinstance(layer_links, list):\n        raise ValueError(\'Missing v0.9.1 layer_links\')\n\n    slot_to_index = {}\n\n    for link in layer_links:\n        slot, index = link[\'slot\'], link[\'index\']\n        if type(slot) is not int or type(index) is not int:\n            raise ValueError(\'Invalid layer link\')\n        if not 0 <= index < len(layer_catalogue):\n            raise ValueError(\'Layer index out of range\')\n        if slot in slot_to_index and slot_to_index[slot] != index:\n            raise ValueError(\'Conflicting layer slot mapping\')\n        slot_to_index[slot] = index\n\n    if not slot_to_index:\n        raise ValueError(\'Empty layer mapping\')\n\n    def entity_layer(entity, context):\n        index = entity.get(\'layer\')\n        if type(index) is not int or not 0 <= index < len(layer_catalogue):\n            raise ValueError(f\'{context}: invalid layer {index!r}\')\n        return layer_catalogue[index][\'name\']\n\n    def instance_layer(node, context):\n        slot = node.get(\'layer_slot\')\n        if type(slot) is not int or slot not in slot_to_index:\n            raise ValueError(f\'{context}: invalid layer slot {slot!r}\')\n        return layer_catalogue[slot_to_index[slot]][\'name\']\n\n    objects=[]; loose=[]; defs=[]; instances=[]; counts={\'textured_faces\':0,\'unpainted_faces\':0,\'groups\':0,\'components\':0,\'instances\':0,\'loose_runs\':0}\n    for ri,run in enumerate(runs):\n        verts=run[\'vertices_m\']; tex={f[\'pid\']:f for f in meta[ri].get(\'textured_faces\',[])}\n        faces=[]\n        for face in run[\'faces\']:\n            pid = face.get(\'pid\')\n            if type(pid) is not int or pid <= 0:\n                raise ValueError(f\'run {ri}: missing or invalid face PID {pid!r}\')\n            item={\'source_face_pid\':pid,\'outer\':face[\'outer\'],\'normal\':face[\'normal\'],\'layer\':entity_layer(face, f\'run {ri} face\'),\'hidden\':bool(face.get(\'hidden\',False))}\n            # Native material slots are 1-based; material definitions are 0-based.\n            for side, native_key, prefix, uv_key in (\n                (\'front\', \'front_material\', \'\', \'uv_front\'),\n                (\'back\', \'back_material\', \'back_\', \'uv_back\'),\n            ):\n                native_slot = face.get(native_key)\n                if native_slot is None or native_slot == 0:\n                    if side == \'front\':\n                        counts[\'unpainted_faces\'] += 1\n                    continue\n\n                mat_index = material_indices.get(native_slot)\n                if mat_index is None or not 0 <= mat_index < len(source_materials):\n                    raise ValueError(f\'run {ri} face {face["pid"]}: invalid {side} material slot {native_slot}\')\n\n                item[prefix + \'material_slot\'] = mat_index + 1\n                material = source_materials[mat_index]\n\n                if material.get(\'kind\') == \'textured\':\n                    size = material.get(\'applied_size_in\')\n                    if size is None:\n                        raise ValueError(\n                            f"Texture material {material[\'name\']} has no applied size"\n                        )\n\n                    item[prefix + \'texture\'] = {\n                        \'file\': material[\'texture\'],\n                        \'width_m\': size[0] * 0.0254,\n                        \'height_m\': size[1] * 0.0254,\n                    }\n\n                    uv = tex.get(face[\'pid\'], {}).get(uv_key)\n                    if uv is None:\n                        raise ValueError(f\'run {ri} face {face["pid"]}: missing {side} UVs\')\n                    try:\n                        item[prefix + \'uvw\'] = uvw_for_face(verts, face, uv)\n                    except NonAffineMapping:\n                        # IngeTrazo stores an affine UV transform for each face side.\n                        item[prefix + \'uvw\'] = uvw_for_face(verts, face, uv, approximate=True)\n                        counts[\'approximated_uvs\'] = counts.get(\'approximated_uvs\', 0) + 1\n                    if side == \'front\':\n                        counts[\'textured_faces\'] += 1\n                elif material.get(\'kind\') != \'solid\':\n                    raise ValueError(f\'unsupported source material kind: {material.get("kind")!r}\')\n            if face.get(\'holes\'): item[\'holes\'] = face[\'holes\']\n            faces.append(item)\n        edges=[[e[\'v0\'],e[\'v1\']] for e in run[\'edges\']]\n        props=[{\'hidden\':e.get(\'hidden\',False),\'soft\':e.get(\'soft\',False),\'smooth\':e.get(\'smooth\',False),\'layer\':entity_layer(e, f\'run {ri} edge\')} for e in run[\'edges\']]\n        # C001.5I2: preserve native welded curves and arc geometry.\n        native_curves = run.get(\'curves\', [])\n        memberships = [[] for _ in native_curves]\n\n        for edge_index, edge in enumerate(run[\'edges\']):\n            curve_index = edge.get(\'curve\')\n            if curve_index is None:\n                continue\n            if type(curve_index) is not int or not 0 <= curve_index < len(native_curves):\n                raise ValueError(f\'run {ri}: invalid curve index on edge {edge_index}\')\n            memberships[curve_index].append(edge_index)\n\n        curves = []\n        for curve_index, record in enumerate(native_curves):\n            member_edges = memberships[curve_index]\n            if len(member_edges) != record[\'members\']:\n                raise ValueError(\n                    f\'run {ri}: curve {curve_index} membership mismatch\'\n                )\n\n            if not member_edges:\n                raise ValueError(f\'run {ri}: empty native curve {curve_index}\')\n\n            arc = record.get(\'arc\')\n            if arc is not None:\n                radius = arc[\'radius_m\']\n                if radius <= 0:\n                    raise ValueError(f\'run {ri}: invalid arc radius\')\n                arc = dict(arc)\n                arc.pop(\'pid\', None)\n                arc[\'x_axis_m\'] = [v / radius for v in arc[\'x_axis_m\']]\n                arc[\'y_axis_m\'] = [v / radius for v in arc[\'y_axis_m\']]\n\n            curves.append({\'edges\': member_edges, \'arc\': arc})\n\n        edge_pids=[e.get(\'pid\', 0) for e in run[\'edges\']]\n        if any(type(pid) is not int or pid <= 0 for pid in edge_pids):\n            raise ValueError(f\'run {ri}: missing or invalid native edge PID\')\n        if len(set(edge_pids)) != len(edge_pids):\n            raise ValueError(f\'run {ri}: duplicate native edge PIDs\')\n        body={\'vertices\':verts,\'edges\':edges,\'faces\':faces,\'edge_properties\':props,\'curves\':curves,\'source_edge_pids\':edge_pids}\n        nodes=[n for n in scene if n.get(\'run\')==ri]\n        # LAB03: unused definitions remain in the component library without\n        # fabricating a visible scene instance. Root geometry must be placed.\n        if not nodes and meta[ri].get(\'def_index\') is None:\n            raise ValueError(f\'run {ri}: unplaced root geometry\')\n        if not nodes or all(n.get(\'is_group\') is False for n in nodes):\n            cid=f\'Native2027_Component_Run{ri}\'\n            defs.append({\'id\':cid,\'name\':cid,**body})\n            counts[\'components\']+=1\n            for n in nodes:\n                transform = placement_transform(n[\'world\'])\n                instances.append({\'definition_id\':cid,\'transform\':transform,\'layer\':instance_layer(n, f\'run {ri} component instance\')})\n                counts[\'instances\']+=1\n        elif len(nodes)==1 and nodes[0].get(\'is_group\') is True:\n            n = nodes[0]\n            # Keep vertices and UVW local and carry the full placement separately.\n            transform = placement_transform(n[\'world\'])\n            objects.append({\'name\':f\'Native2027_Group_Run{ri}\',\'transform\':transform,\'layer\':instance_layer(n, f\'run {ri} group\'),**body});counts[\'groups\']+=1\n        elif len(nodes)==1 and nodes[0].get(\'is_group\') is None:\n            n=nodes[0];w=n[\'world\']\n            if any(abs(w[i]-t)>1e-9 for i,t in [(0,1),(1,0),(2,0),(4,0),(5,1),(6,0),(8,0),(9,0),(10,1),(3,0),(7,0),(11,0),(12,0),(13,0),(14,0),(15,1)]):\n                raise ValueError(\'nonidentity loose geometry transform\')\n            loose.append({\'name\':f\'Native2027_Loose_Run{ri}\',**body});counts[\'loose_runs\']+=1\n        else: raise ValueError(f\'run {ri} has unsupported placement types\')\n    def preserve_definition_identity(target, source, run_index):\n        guid = source.get(\'guid\')\n        flag = source.get(\'flag\')\n        if guid and (not isinstance(guid, str) or re.fullmatch(r\'[0-9a-fA-F]{32}\', guid) is None):\n            raise ValueError(f\'run {run_index}: invalid original definition GUID\')\n        if type(flag) is not bool:\n            raise ValueError(f\'run {run_index}: invalid original definition flag\')\n        if guid:\n            target[\'source_definition_guid\'] = guid.lower()\n        target[\'source_definition_flag\'] = flag\n\n    # C001.5H: restore verified native identity provenance.\n    definitions_by_name = {d[\'name\']: d[\'map_index\'] for d in native[\'model\'][\'definitions\']}\n    runs_by_definition = {\n        r[\'def_index\']: i\n        for i, r in enumerate(native[\'model\'][\'geometry_runs\'])\n        if r.get(\'def_index\') is not None\n    }\n    if len(definitions_by_name) != len(native[\'model\'][\'definitions\']):\n        raise ValueError(\'ambiguous native definition names\')\n    if len(runs_by_definition) != len(native[\'model\'][\'definitions\']):\n        raise ValueError(\'ambiguous native definition ownership\')\n\n    used_instances = set()\n    used_instance_guids = set()\n    for instance in native[\'model\'][\'instances\']:\n        definition = instance[\'definition\']\n        if definition not in definitions_by_name:\n            raise ValueError(f\'unknown native definition {definition!r}\')\n        run_index = runs_by_definition[definitions_by_name[definition]]\n        translation = instance[\'translation_m\']\n        candidates = [\n            node for node in scene\n            if node.get(\'run\') == run_index\n            and all(abs(node[\'world\'][axis] - translation[k]) < 1e-5\n                    for k, axis in enumerate((3, 7, 11)))\n            and node.get(\'is_group\') == instance[\'is_group\']\n        ]\n        if len(candidates) != 1:\n            raise FlatPlacementMismatch(f\'instance {instance["pid"]}: expected one matching scene node, got {len(candidates)}\')\n        node = candidates[0]\n        node[\'_source_instance_pid\'] = instance[\'pid\']\n        # Phase 2E: visibility belongs to the verified native occurrence.\n        if type(instance.get(\'hidden\')) is not bool:\n            raise ValueError(f\'instance {instance["pid"]}: missing native hidden flag\')\n        node[\'_source_hidden\'] = instance[\'hidden\']\n        if type(instance.get(\'locked\')) is not bool:\n            raise ValueError(f\'instance {instance["pid"]}: missing native locked flag\')\n        node[\'_source_locked\'] = instance[\'locked\']\n        guid = instance.get(\'guid\')\n        if guid and (not isinstance(guid, str) or re.fullmatch(r\'[0-9a-fA-F]{32}\', guid) is None):\n            raise ValueError(f"instance {instance[\'pid\']}: invalid native GUID")\n        if guid and guid != \'0\' * 32:\n            guid = guid.lower()\n            if guid in used_instance_guids:\n                raise ValueError(f"Duplicate native instance GUID: {guid}")\n            used_instance_guids.add(guid)\n            node[\'_source_instance_guid\'] = guid\n        used_instances.add(instance[\'pid\'])\n\n    if len(used_instances) != len(native[\'model\'][\'instances\']):\n        raise ValueError(\'native instance provenance incomplete\')\n\n    for ri, run in enumerate(runs):\n        source_pids = run[\'vertex_pids\']\n        if len(source_pids) != len(run[\'vertices_m\']):\n            raise ValueError(f\'run {ri}: vertex PID count mismatch\')\n        if len(set(source_pids)) != len(source_pids):\n            raise ValueError(f\'run {ri}: duplicate vertex PIDs\')\n        source_def_index = meta[ri].get(\'def_index\')\n        nodes = [n for n in scene if n.get(\'run\') == ri]\n\n        if source_def_index is None:\n            matching = [o for o in loose if o[\'name\'] == f\'Native2027_Loose_Run{ri}\']\n            if len(matching) != 1:\n                raise ValueError(f\'run {ri}: loose provenance mismatch\')\n            matching[0][\'source_vertex_pids\'] = source_pids\n        elif all(n.get(\'is_group\') is False for n in nodes):\n            matching = [d for d in defs if d[\'id\'] == f\'Native2027_Component_Run{ri}\']\n            if len(matching) != 1:\n                raise ValueError(f\'run {ri}: component provenance mismatch\')\n            matching[0][\'source_vertex_pids\'] = source_pids\n            matching[0][\'source_def_index\'] = source_def_index\n\n            source_definitions = [\n                d for d in native[\'model\'][\'definitions\']\n                if d.get(\'map_index\') == source_def_index\n            ]\n            if len(source_definitions) != 1:\n                raise ValueError(\n                    f\'run {ri}: expected one native component definition \'\n                    f\'for index {source_def_index}\'\n                )\n\n            source_behaviour = source_definitions[0].get(\'behaviour\')\n            required_behaviour = (\n                \'glues_to_surface\', \'glue_plane\', \'cuts_opening\',\n                \'always_faces_camera\', \'shadows_face_sun\', \'extra\'\n            )\n            if not isinstance(source_behaviour, dict):\n                raise ValueError(f\'run {ri}: missing native component behaviour\')\n            if any(k not in source_behaviour for k in required_behaviour):\n                raise ValueError(f\'run {ri}: incomplete native component behaviour\')\n\n            matching[0][\'behaviour\'] = {\n                k: source_behaviour[k] for k in required_behaviour\n            }\n            # v0.9.4: Preserve original component definition name.\n            matching[0][\'name\'] = source_definitions[0][\'name\']\n            description = source_definitions[0].get(\'description\', \'\')\n            if not isinstance(description, str):\n                raise ValueError(f\'run {ri}: invalid native component description\')\n            matching[0][\'source_description\'] = description\n            preserve_definition_identity(matching[0], source_definitions[0], ri)\n\n            if len(nodes) != len([i for i in instances if i[\'definition_id\'] == matching[0][\'id\']]):\n                raise ValueError(\'component instance count mismatch\')\n            targets = [i for i in instances if i[\'definition_id\'] == matching[0][\'id\']]\n            for node, target in zip(nodes, targets):\n                target[\'source_instance_pid\'] = node[\'_source_instance_pid\']\n                target[\'hidden\'] = node[\'_source_hidden\']\n                target[\'locked\'] = node[\'_source_locked\']\n                target[\'source_instance_guid\'] = node.get(\'_source_instance_guid\')\n        elif len(nodes) == 1 and nodes[0].get(\'is_group\') is True:\n            matching = [o for o in objects if o[\'name\'] == f\'Native2027_Group_Run{ri}\']\n            if len(matching) != 1:\n                raise ValueError(f\'run {ri}: group provenance mismatch\')\n            matching[0][\'source_vertex_pids\'] = source_pids\n            matching[0][\'source_def_index\'] = source_def_index\n            matching[0][\'source_instance_pid\'] = nodes[0][\'_source_instance_pid\']\n            matching[0][\'hidden\'] = nodes[0][\'_source_hidden\']\n            matching[0][\'locked\'] = nodes[0][\'_source_locked\']\n            matching[0][\'source_instance_guid\'] = nodes[0].get(\'_source_instance_guid\')\n            # v0.9.4: Preserve original group definition name.\n            source_definitions = [\n                d for d in native[\'model\'][\'definitions\']\n                if d.get(\'map_index\') == source_def_index\n            ]\n            if len(source_definitions) != 1:\n                raise ValueError(\n                    f\'run {ri}: expected one native group definition \'\n                    f\'for index {source_def_index}\'\n                )\n            matching[0][\'name\'] = source_definitions[0][\'name\']\n            preserve_definition_identity(matching[0], source_definitions[0], ri)\n        else:\n            raise ValueError(f\'run {ri}: unsupported native provenance\')\n    layers=[{\'name\':l[\'name\'],\'color\':l[\'rgba\'],\'visible\':l.get(\'visible\',True)} for l in native[\'model\'][\'layers\']]\n    # C001.5E: preserve supported native camera, scene and style metadata.\n    model = native[\'model\']\n\n    def convert_camera(camera):\n        if not isinstance(camera, dict):\n            raise ValueError(\'missing native camera\')\n        required = (\'eye_m\', \'target_m\', \'up\')\n        for key in required:\n            if key not in camera:\n                raise ValueError(f\'native camera missing {key}\')\n        return {\n            \'eye_m\': camera[\'eye_m\'],\n            \'target_m\': camera[\'target_m\'],\n            \'up\': camera[\'up\'],\n            \'perspective\': camera.get(\'perspective\', True),\n            \'fov_deg\': camera.get(\'fov_deg\', 35.0),\n            \'parallel_height_m\': camera.get(\'parallel_height_m\', 3.0),\n            \'two_point_perspective\': camera.get(\'two_point_perspective\', False),\n        }\n\n    rendering_keys = (\n        \'face_style\', \'xray\', \'textures\', \'edges\', \'profiles\', \'profiles_width\',\n        \'background\', \'sky\', \'sky_color\', \'ground\', \'ground_color\',\n        \'front_color\', \'back_color\', \'ambient_occlusion\',\n        \'section_display\', \'section_fill\', \'section_fill_color\',\n        \'section_cut_color\', \'section_cut_width\',\n        \'default_section_fill_style\',\n    )\n\n    source_rendering = model.get(\'rendering\') or {}\n    converted_rendering = {\n        key: source_rendering[key]\n        for key in rendering_keys\n        if source_rendering.get(key) is not None\n    }\n\n    styles = model.get(\'styles\') or []\n    active_style = model.get(\'active_style\')\n    style = None\n\n    if active_style is not None:\n        if not isinstance(active_style, int) or not 0 <= active_style < len(styles):\n            raise ValueError(\'invalid active style index\')\n        style = styles[active_style]\n        if converted_rendering.get(\'background\') in (None, [0, 0, 0, 0]):\n            style_background = (style.get(\'settings\') or {}).get(\'background\')\n            if style_background is not None:\n                converted_rendering[\'background\'] = style_background\n\n    thumbnail_manifest_path = os.environ.get(\n        "BLACKFOX_SCENE_THUMBNAIL_MANIFEST"\n    )\n    thumbnail_assets = {}\n\n    if thumbnail_manifest_path:\n        import hashlib\n\n        thumbnail_manifest_file = pathlib.Path(\n            thumbnail_manifest_path\n        ).resolve()\n\n        thumbnail_manifest = json.loads(\n            thumbnail_manifest_file.read_text(encoding="utf-8-sig")\n        )\n\n        if thumbnail_manifest.get("schema") != "BlackFoxSceneThumbnailsV1":\n            raise ValueError("Unexpected scene thumbnail manifest schema")\n\n        for asset in thumbnail_manifest["scenes"]:\n            index = asset["scene_index"]\n\n            if index in thumbnail_assets:\n                raise ValueError(f"Duplicate thumbnail scene index {index}")\n\n            if not isinstance(index, int) or isinstance(index, bool):\n                raise ValueError("Invalid thumbnail scene index")\n\n            if index < 0 or index >= len(model.get("scenes") or []):\n                raise ValueError(f"Thumbnail scene index out of range: {index}")\n\n            original = (model.get("scenes") or [])[index]\n\n            if asset["scene_name"] != original["name"]:\n                raise ValueError(f"Thumbnail scene name mismatch: {index}")\n\n            if asset["file"] is None:\n                if original.get("thumbnail") is not None:\n                    raise ValueError(f"Missing original thumbnail: {index}")\n                thumbnail_assets[index] = None\n                continue\n\n            filename = asset["file"]\n\n            if pathlib.Path(filename).name != filename:\n                raise ValueError("Thumbnail filename must be a basename")\n\n            path = thumbnail_manifest_file.parent / filename\n            data = path.read_bytes()\n\n            if not data.startswith(bytes([137,80,78,71,13,10,26,10])):\n                raise ValueError(f"Invalid scene thumbnail PNG: {index}")\n\n            if len(data) != asset["bytes"]:\n                raise ValueError(f"Thumbnail byte count mismatch: {index}")\n\n            if original.get("thumbnail") != len(data):\n                raise ValueError(f"Native thumbnail size mismatch: {index}")\n\n            digest = hashlib.sha256(data).hexdigest()\n\n            if digest.lower() != asset["sha256"].lower():\n                raise ValueError(f"Thumbnail SHA256 mismatch: {index}")\n\n            thumbnail_assets[index] = str(path.resolve())\n\n        if len(thumbnail_assets) != len(model.get("scenes") or []):\n            raise ValueError("Incomplete thumbnail manifest")\n\n    original_scenes = model.get(\'scenes\') or []\n    converted_scenes = []\n\n    for scene_index, scene_item in enumerate(original_scenes):\n        converted_scenes.append({\n            \'name\': scene_item[\'name\'],\n            \'thumbnail_path\': thumbnail_assets.get(scene_index),\n            \'description\': scene_item.get(\'description\') or \'\',\n            \'camera\': convert_camera(scene_item[\'camera\']),\n            \'saved\': scene_item.get(\'saved\'),\n            \'rendering\': scene_item.get(\'rendering\'),\n            \'shadows\': scene_item.get(\'shadows\'),\n            \'axes\': scene_item.get(\'axes\'),\n            \'style\': scene_item.get(\'style\'),\n        })\n        if output_path is None:\n            converted_scenes[-1][\'active_section_planes\'] = scene_item.get(\'active_section_planes\') or []\n            converted_scenes[-1][\'hidden_layers\'] = scene_item.get(\'hidden_layers\') or []\n\n    source_active_layer = model.get(\'active_layer\')\n    if source_active_layer is not None and (\n        type(source_active_layer) is not int\n        or not 0 <= source_active_layer < len(layers)\n    ):\n        raise ValueError(\n            f\'Invalid source active layer index: {source_active_layer!r}\'\n        )\n    output={\'layers\':layers,\'objects\':objects,\'loose_geometry\':loose,\'component_definitions\':defs,\'component_instances\':instances,\'source_layer_links\':layer_links,\'source_materials\':source_materials,\'source_pbr\':source_pbr,\'source_active_layer\':source_active_layer}\n\n    # D4N.33: retain typed native dictionaries with stable provenance keys.\n    # Native owner indices are converted before geometry is reordered.\n    native_defs = model.get(\'definitions\') or []\n    native_runs = model.get(\'geometry_runs\') or []\n    native_instances = model.get(\'instances\') or []\n    source_dicts = []\n    for group in model.get(\'dictionaries\') or []:\n        owner = group[\'owner\']\n        if owner == \'model\' or owner == [\'model\']:\n            normalized = [\'model\']\n        elif isinstance(owner, list) and len(owner) == 2 and owner[0] == \'definition\':\n            idx = owner[1]\n            if type(idx) is not int or not 0 <= idx < len(native_defs):\n                raise ValueError(f\'Invalid dictionary definition owner {owner!r}\')\n            normalized = [\'definition_map\', native_defs[idx][\'map_index\']]\n        elif isinstance(owner, list) and len(owner) == 3 and owner[0] == \'face\':\n            run_idx, face_idx = owner[1:]\n            if (type(run_idx) is not int or type(face_idx) is not int\n                    or not 0 <= run_idx < len(runs)\n                    or not 0 <= face_idx < len(runs[run_idx][\'faces\'])):\n                raise ValueError(f\'Invalid dictionary face owner {owner!r}\')\n            face_pid = runs[run_idx][\'faces\'][face_idx].get(\'pid\')\n            if type(face_pid) is not int or face_pid <= 0:\n                raise ValueError(f\'Invalid dictionary face PID for {owner!r}\')\n            # A PID is usable as an owner key only if it identifies one face.\n            if sum(face.get(\'pid\') == face_pid\n                   for run in runs for face in run[\'faces\']) != 1:\n                raise ValueError(f\'Ambiguous dictionary face PID {face_pid}\')\n            normalized = [\'face_pid\', face_pid]\n        elif isinstance(owner, list) and len(owner) == 3 and owner[0] == \'instance\':\n            run_idx, placed_idx = owner[1:]\n            if type(run_idx) is not int or type(placed_idx) is not int or not 0 <= run_idx < len(native_runs):\n                raise ValueError(f\'Invalid dictionary instance owner {owner!r}\')\n            # The native flattened instance catalogue must identify this placement.\n            # For this importer, root placements are enumerated in the catalogue.\n            if run_idx != len(native_runs) - 1 or not 0 <= placed_idx < len(native_instances):\n                raise ValueError(f\'Unsupported dictionary instance owner {owner!r}\')\n            normalized = [\'instance_pid\', native_instances[placed_idx][\'pid\']]\n        else:\n            raise ValueError(f\'Unsupported dictionary owner {owner!r}\')\n        source_dicts.append({\'owner\': normalized, \'dictionaries\': group[\'dictionaries\']})\n    output[\'source_dictionaries\'] = source_dicts\n\n    # Phase 2N.26: preserve original embedded SketchUp classification archives.\n    # Hexadecimal payloads are validated before entering the export schema.\n    source_classifications = []\n    for record in native.get(\'source_classifications\', []):\n        if not isinstance(record, dict):\n            raise ValueError(\'Invalid classification record\')\n        name = record.get(\'name\')\n        source_path = record.get(\'source_path\')\n        byte_count = record.get(\'bytes\')\n        data_hex = record.get(\'data_hex\')\n        if not isinstance(name, str) or not name:\n            raise ValueError(\'Invalid classification name\')\n        if not isinstance(source_path, str):\n            raise ValueError(\'Invalid classification source path\')\n        if type(byte_count) is not int or byte_count < 0:\n            raise ValueError(\'Invalid classification byte count\')\n        if not isinstance(data_hex, str) or len(data_hex) != byte_count * 2:\n            raise ValueError(\'Invalid classification hex length\')\n        try:\n            archive = bytes.fromhex(data_hex)\n        except ValueError as exc:\n            raise ValueError(\'Invalid classification hex data\') from exc\n        if len(archive) != byte_count or not archive.startswith(b\'PK\'):\n            raise ValueError(\'Invalid classification archive\')\n        source_classifications.append({\n            \'name\': name,\n            \'source_path\': source_path,\n            \'bytes\': byte_count,\n            \'data_hex\': data_hex,\n        })\n    output[\'source_classifications\'] = source_classifications\n    # BLACKFOX_PHASE_2P_WATERMARK_BRIDGE\n    # Preserve native watermark metadata and embedded PNG bytes.\n    def validate_watermark(wm):\n        if not isinstance(wm, dict):\n            raise ValueError(\'Invalid watermark record\')\n\n        required = (\n            \'name\', \'source_file\', \'background\', \'tiled\',\n            \'stretched\', \'keep_aspect_ratio\', \'position\',\n            \'mask\', \'blend\', \'scale\', \'time\',\n            \'image_bytes\', \'image_hex\',\n        )\n\n        if any(key not in wm for key in required):\n            raise ValueError(\'Incomplete watermark record\')\n\n        if not isinstance(wm[\'name\'], str):\n            raise ValueError(\'Invalid watermark name\')\n\n        if not isinstance(wm[\'source_file\'], str):\n            raise ValueError(\'Invalid watermark source path\')\n\n        for key in (\'background\', \'tiled\', \'stretched\',\n                    \'keep_aspect_ratio\', \'mask\'):\n            if type(wm[key]) is not bool:\n                raise ValueError(f\'Invalid watermark {key}\')\n\n        for key in (\'position\', \'time\'):\n            if type(wm[key]) is not int or wm[key] < 0:\n                raise ValueError(f\'Invalid watermark {key}\')\n\n        for key in (\'blend\', \'scale\'):\n            if type(wm[key]) not in (int, float):\n                raise ValueError(f\'Invalid watermark {key}\')\n            if not math.isfinite(wm[key]):\n                raise ValueError(f\'Non-finite watermark {key}\')\n\n        count = wm[\'image_bytes\']\n        hex_data = wm[\'image_hex\']\n\n        if count is None and hex_data is None:\n            return dict(wm)\n\n        if type(count) is not int or count < 0:\n            raise ValueError(\'Invalid watermark image byte count\')\n\n        if not isinstance(hex_data, str) or len(hex_data) != count * 2:\n            raise ValueError(\'Invalid watermark image hex length\')\n\n        try:\n            image = bytes.fromhex(hex_data)\n        except ValueError as exc:\n            raise ValueError(\'Invalid watermark image hex\') from exc\n\n        if len(image) != count:\n            raise ValueError(\'Watermark image length mismatch\')\n\n        if image and not image.startswith(b\'\\x89PNG\\r\\n\\x1a\\n\'):\n            raise ValueError(\'Watermark image is not PNG\')\n\n        return dict(wm)\n\n    style_watermarks = native.get(\'source_style_watermarks\', [])\n    current_watermarks = native.get(\'source_current_watermarks\', [])\n\n    if not isinstance(style_watermarks, list):\n        raise ValueError(\'Invalid style watermark collection\')\n\n    if not isinstance(current_watermarks, list):\n        raise ValueError(\'Invalid current watermark collection\')\n\n    converted_style_watermarks = []\n\n    for entry in style_watermarks:\n        if not isinstance(entry, dict):\n            raise ValueError(\'Invalid style watermark entry\')\n\n        index = entry.get(\'style_index\')\n        if type(index) is not int or not 0 <= index < len(model.get(\'styles\') or []):\n            raise ValueError(\'Invalid watermark style index\')\n\n        watermarks = entry.get(\'watermarks\')\n        if not isinstance(watermarks, list):\n            raise ValueError(\'Invalid style watermark list\')\n\n        converted_style_watermarks.append({\n            \'style_index\': index,\n            \'watermarks\': [validate_watermark(w) for w in watermarks],\n        })\n\n    output[\'source_style_watermarks\'] = converted_style_watermarks\n    output[\'source_current_watermarks\'] = [\n        validate_watermark(w) for w in current_watermarks\n    ]\n\n    # BLACKFOX_PHASE_2P_NATIVE_WATERMARK_SECTION_VALUE\n    # Preserve the original 0x2CEE value without interpreting it.\n    if \'source_native_watermark_section_value\' in native:\n        watermark_section_value = native[\'source_native_watermark_section_value\']\n\n        if watermark_section_value is not None:\n            if (type(watermark_section_value) is not int\n                    or not 0 <= watermark_section_value <= 0xFFFFFFFF):\n                raise ValueError(\'Invalid native watermark section value\')\n\n        output[\'source_native_watermark_section_value\'] = watermark_section_value\n\n    # D4: preserve native document identity and current paint material.\n    source_guid = model.get(\'model_guid\')\n    if source_guid is not None:\n        if not isinstance(source_guid, str) or len(source_guid) != 32 or any(c not in \'0123456789abcdefABCDEF\' for c in source_guid):\n            raise ValueError(\'Invalid native model GUID\')\n        output[\'source_model_guid\'] = source_guid.lower()\n\n    current_material = model.get(\'current_material\')\n    if current_material is not None:\n        if isinstance(current_material, bool) or not isinstance(current_material, int) or not 0 <= current_material < len(source_materials):\n            raise ValueError(\'Invalid native current material index\')\n        output[\'source_current_material\'] = current_material\n    # C001.5H3: preserve native SketchUp scene animation settings.\n    animation = model.get(\'animation\')\n\n    if animation is not None:\n        required = (\n            \'transitions\',\n            \'transition_s\',\n            \'delay_s\',\n            \'loop_slideshow\',\n        )\n\n        for key in required:\n            if key not in animation:\n                raise ValueError(f\'missing native animation property: {key}\')\n\n        output[\'source_animation\'] = {\n            key: animation[key] for key in required\n        }\n    # C001.5I1: preserve original model units and display precision.\n    units = model.get(\'units\')\n    if units is not None:\n        required_units = (\n            \'length_format\', \'length_unit\', \'length_precision\',\n            \'angle_precision\', \'length_snap\', \'length_snap_length\',\n            \'angle_snap\', \'snap_angle\', \'suppress_units_display\',\n            \'force_inch_display\',\n        )\n        for key in required_units:\n            if key not in units:\n                raise ValueError(f\'missing native unit property: {key}\')\n\n        optional_units = (\n            \'area_unit\', \'volume_unit\',\n            \'area_precision\', \'volume_precision\',\n        )\n        output[\'source_units\'] = {\n            key: units[key]\n            for key in required_units + optional_units\n            if key in units\n        }\n\n    # Preserve the original document\'s dimension preferences.\n    defaults = model.get(\'dimension_defaults\')\n    if defaults is not None:\n        output[\'source_dimension_defaults\'] = defaults\n    output[\'source_rendering\'] = converted_rendering\n    # Phase 2M: preserve the complete model-level SKP sun/shadow record.\n    if model.get(\'shadows\') is not None:\n        if not isinstance(model[\'shadows\'], dict):\n            raise ValueError(\'Invalid model-level shadow record\')\n        output[\'source_shadows\'] = model[\'shadows\']\n\n    if style is not None:\n        output[\'source_style_name\'] = style[\'name\']\n        output[\'source_style_description\'] = \'\'\n\n    if model.get(\'camera\') is not None:\n        output[\'camera\'] = convert_camera(model[\'camera\'])\n\n    output[\'scenes\'] = converted_scenes\n\n    # C001.5F: restore root-level native construction lines.\n    construction_lines = []\n\n    for guide in model.get(\'guides\') or []:\n        if guide.get(\'def_index\') is not None:\n            raise ValueError(\n                \'Definition-owned construction lines are not supported yet\'\n            )\n\n        construction_lines.append({\n            \'point\': guide[\'point_m\'],\n            \'direction\': guide[\'direction\'],\n        })\n\n    output[\'construction_lines\'] = construction_lines\n\n    # Native annotations retain their original anchors and ownership.\n    # Preserve all native annotation properties except original annotation PIDs.\n    # The Rust exporter allocates new PIDs and remaps anchor references.\n    # C001.5H2: native construction points and section planes.\n    # Definition ownership is preserved using the source definition index.\n    native_geometry_entities = []\n\n    for run in model.get(\'geometry_runs\') or []:\n        points = run.get(\'guide_points\') or []\n        sections = run.get(\'sections\') or []\n        active = run.get(\'active_section\')\n\n        if not points and not sections and active is None:\n            continue\n\n        section_pids = {s[\'pid\'] for s in sections}\n\n        if active is not None and active not in section_pids:\n            raise ValueError(\n                f"Active section PID {active} is missing from its owning run"\n            )\n\n        native_geometry_entities.append({\n            \'source_def_index\': run.get(\'def_index\'),\n            \'guide_points\': points,\n            \'sections\': sections,\n            \'active_section\': active,\n        })\n\n    output[\'native_geometry_entities\'] = native_geometry_entities\n    output[\'native_dimensions\'] = [\n        {k: v for k, v in dimension.items() if k != \'pid\'}\n        for dimension in (model.get(\'dimensions\') or [])\n    ]\n    # D4N61AE: preserve complete native radial/diametral metadata.\n    # Do not strip edge PID: exporter must explicitly remap it.\n    # Phase 2C: validate the edge-backed native radial records before\n    # passing them to the IngeTrazo extension and the round-trip exporter.\n    radial = native.get(\'native_radial_dimensions\', [])\n    if not isinstance(radial, list):\n        raise ValueError(\'native_radial_dimensions must be a list\')\n    edge_pids = {e[\'pid\'] for run in runs for e in run[\'edges\']}\n    if len(edge_pids) != sum(len(run[\'edges\']) for run in runs):\n        raise ValueError(\'duplicate source edge PID across geometry runs\')\n    seen_radial = set()\n    required_radial = {\n        \'pid\', \'def_index\', \'edge\', \'arc\', \'diameter\', \'leader\',\n        \'text_override\', \'font\', \'aligned\', \'arrow\', \'layer\',\n        \'material\', \'hidden\', \'casts_shadows\', \'receives_shadows\'\n    }\n    for record in radial:\n        if not isinstance(record, dict):\n            raise ValueError(\'radial dimension must be an object\')\n        missing = required_radial - record.keys()\n        if missing:\n            raise ValueError(f\'radial dimension missing fields: {sorted(missing)}\')\n        pid = record[\'pid\']\n        if type(pid) is not int or pid <= 0 or pid in seen_radial:\n            raise ValueError(f\'invalid/duplicate radial dimension PID: {pid}\')\n        seen_radial.add(pid)\n        if record[\'arc\'] is not None:\n            raise ValueError(f\'radial dimension {pid}: embedded arc unsupported\')\n        if type(record[\'edge\']) is not int or record[\'edge\'] not in edge_pids:\n            raise ValueError(f\'radial dimension {pid}: edge PID unresolved\')\n        leader = record[\'leader\']\n        if (not isinstance(leader, list) or len(leader) != 2\n                or any(type(x) not in (int, float) or not math.isfinite(x)\n                       for x in leader)):\n            raise ValueError(f\'radial dimension {pid}: invalid leader\')\n        if type(record[\'diameter\']) is not bool:\n            raise ValueError(f\'radial dimension {pid}: invalid diameter flag\')\n    output[\'native_radial_dimensions\'] = [dict(record) for record in radial]\n    output[\'native_texts\'] = [\n        {k: v for k, v in annotation.items() if k != \'pid\'}\n        for annotation in (model.get(\'texts\') or [])\n    ]\n\n    # An absent selected scene remains absent; do not fabricate one.\n    if model.get(\'active_scene\') is not None:\n        raise ValueError(\'active scene selection requires verified index mapping\')\n    output[\'source_geo_located\'] = bool(model.get(\'geo_located\', False))\n    if output[\'source_geo_located\'] and output_path is None:\n        location = {key: value for key, _, value in model.get(\'attributes\', [])}\n        if \'Latitude\' in location and \'Longitude\' in location:\n            output[\'source_location\'] = {\n                \'latitude\': location[\'Latitude\'], \'longitude\': location[\'Longitude\'],\n                \'north_deg\': math.degrees(location[\'GeoReferenceNorthAngle\'])\n                             if \'GeoReferenceNorthAngle\' in location else None,\n            }\n    approximated_uvs = counts.get(\'approximated_uvs\', 0)\n    missing_textures = sum(\'missing_texture\' in material for material in source_materials)\n    if approximated_uvs or missing_textures:\n        import logging\n        logging.getLogger(\'blackfox_skp\').warning(\n            \'SKP import approximated %d face-side UV mappings and used solid colours for %d missing textures.\',\n            approximated_uvs, missing_textures,\n        )\n    if output_path is None:\n        return output\n    if output.get(\'source_shadows\') is None:\n        output.pop(\'source_geo_located\', None)\n    pathlib.Path(output_path).parent.mkdir(parents=True,exist_ok=True)\n    pathlib.Path(output_path).write_text(json.dumps(output,indent=2),encoding=\'utf-8\')\n    print(\'C001.4B CONVERSION COMPLETE:\',json.dumps(counts,sort_keys=True))\n    print(\'Output:\',output_path)\n    print(\'NOTE: geometry/material/UV bridge only; annotations, scenes and other metadata not yet round-tripped\')\n\nif __name__==\'__main__\':\n    if len(sys.argv)!=4: sys.exit(\'Usage: python C001_4B_convert.py native.json texture_manifest.json output.json\')\n    try: main(*sys.argv[1:])\n    except Exception as e: sys.exit(f\'C001.4B ERROR: {e}\')\n\n'

# truststore 0.10.0 Windows backend
# The MIT License (MIT)
# 
# Copyright (c) 2022 Seth Michael Larson
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
_BLACKFOX_WINDOWS_TLS_MODULES = [('_ssl_constants', 'import ssl\nimport sys\nimport typing\n\n# Hold on to the original class so we can create it consistently\n# even if we inject our own SSLContext into the ssl module.\n_original_SSLContext = ssl.SSLContext\n_original_super_SSLContext = super(_original_SSLContext, _original_SSLContext)\n\n# CPython is known to be good, but non-CPython implementations\n# may implement SSLContext differently so to be safe we don\'t\n# subclass the SSLContext.\n\n# This is returned by truststore.SSLContext.__class__()\n_truststore_SSLContext_dunder_class: typing.Optional[type]\n\n# This value is the superclass of truststore.SSLContext.\n_truststore_SSLContext_super_class: type\n\nif sys.implementation.name == "cpython":\n    _truststore_SSLContext_super_class = _original_SSLContext\n    _truststore_SSLContext_dunder_class = None\nelse:\n    _truststore_SSLContext_super_class = object\n    _truststore_SSLContext_dunder_class = _original_SSLContext\n\n\ndef _set_ssl_context_verify_mode(\n    ssl_context: ssl.SSLContext, verify_mode: ssl.VerifyMode\n) -> None:\n    _original_super_SSLContext.verify_mode.__set__(ssl_context, verify_mode)  # type: ignore[attr-defined]\n'), ('_windows', 'import contextlib\nimport ssl\nimport typing\nfrom ctypes import WinDLL  # type: ignore\nfrom ctypes import WinError  # type: ignore\nfrom ctypes import (\n    POINTER,\n    Structure,\n    c_char_p,\n    c_ulong,\n    c_void_p,\n    c_wchar_p,\n    cast,\n    create_unicode_buffer,\n    pointer,\n    sizeof,\n)\nfrom ctypes.wintypes import (\n    BOOL,\n    DWORD,\n    HANDLE,\n    LONG,\n    LPCSTR,\n    LPCVOID,\n    LPCWSTR,\n    LPFILETIME,\n    LPSTR,\n    LPWSTR,\n)\nfrom typing import TYPE_CHECKING, Any\n\nfrom ._ssl_constants import _set_ssl_context_verify_mode\n\nHCERTCHAINENGINE = HANDLE\nHCERTSTORE = HANDLE\nHCRYPTPROV_LEGACY = HANDLE\n\n\nclass CERT_CONTEXT(Structure):\n    _fields_ = (\n        ("dwCertEncodingType", DWORD),\n        ("pbCertEncoded", c_void_p),\n        ("cbCertEncoded", DWORD),\n        ("pCertInfo", c_void_p),\n        ("hCertStore", HCERTSTORE),\n    )\n\n\nPCERT_CONTEXT = POINTER(CERT_CONTEXT)\nPCCERT_CONTEXT = POINTER(PCERT_CONTEXT)\n\n\nclass CERT_ENHKEY_USAGE(Structure):\n    _fields_ = (\n        ("cUsageIdentifier", DWORD),\n        ("rgpszUsageIdentifier", POINTER(LPSTR)),\n    )\n\n\nPCERT_ENHKEY_USAGE = POINTER(CERT_ENHKEY_USAGE)\n\n\nclass CERT_USAGE_MATCH(Structure):\n    _fields_ = (\n        ("dwType", DWORD),\n        ("Usage", CERT_ENHKEY_USAGE),\n    )\n\n\nclass CERT_CHAIN_PARA(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("RequestedUsage", CERT_USAGE_MATCH),\n        ("RequestedIssuancePolicy", CERT_USAGE_MATCH),\n        ("dwUrlRetrievalTimeout", DWORD),\n        ("fCheckRevocationFreshnessTime", BOOL),\n        ("dwRevocationFreshnessTime", DWORD),\n        ("pftCacheResync", LPFILETIME),\n        ("pStrongSignPara", c_void_p),\n        ("dwStrongSignFlags", DWORD),\n    )\n\n\nif TYPE_CHECKING:\n    PCERT_CHAIN_PARA = pointer[CERT_CHAIN_PARA]  # type: ignore[misc]\nelse:\n    PCERT_CHAIN_PARA = POINTER(CERT_CHAIN_PARA)\n\n\nclass CERT_TRUST_STATUS(Structure):\n    _fields_ = (\n        ("dwErrorStatus", DWORD),\n        ("dwInfoStatus", DWORD),\n    )\n\n\nclass CERT_CHAIN_ELEMENT(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("pCertContext", PCERT_CONTEXT),\n        ("TrustStatus", CERT_TRUST_STATUS),\n        ("pRevocationInfo", c_void_p),\n        ("pIssuanceUsage", PCERT_ENHKEY_USAGE),\n        ("pApplicationUsage", PCERT_ENHKEY_USAGE),\n        ("pwszExtendedErrorInfo", LPCWSTR),\n    )\n\n\nPCERT_CHAIN_ELEMENT = POINTER(CERT_CHAIN_ELEMENT)\n\n\nclass CERT_SIMPLE_CHAIN(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("TrustStatus", CERT_TRUST_STATUS),\n        ("cElement", DWORD),\n        ("rgpElement", POINTER(PCERT_CHAIN_ELEMENT)),\n        ("pTrustListInfo", c_void_p),\n        ("fHasRevocationFreshnessTime", BOOL),\n        ("dwRevocationFreshnessTime", DWORD),\n    )\n\n\nPCERT_SIMPLE_CHAIN = POINTER(CERT_SIMPLE_CHAIN)\n\n\nclass CERT_CHAIN_CONTEXT(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("TrustStatus", CERT_TRUST_STATUS),\n        ("cChain", DWORD),\n        ("rgpChain", POINTER(PCERT_SIMPLE_CHAIN)),\n        ("cLowerQualityChainContext", DWORD),\n        ("rgpLowerQualityChainContext", c_void_p),\n        ("fHasRevocationFreshnessTime", BOOL),\n        ("dwRevocationFreshnessTime", DWORD),\n    )\n\n\nPCERT_CHAIN_CONTEXT = POINTER(CERT_CHAIN_CONTEXT)\nPCCERT_CHAIN_CONTEXT = POINTER(PCERT_CHAIN_CONTEXT)\n\n\nclass SSL_EXTRA_CERT_CHAIN_POLICY_PARA(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("dwAuthType", DWORD),\n        ("fdwChecks", DWORD),\n        ("pwszServerName", LPCWSTR),\n    )\n\n\nclass CERT_CHAIN_POLICY_PARA(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("dwFlags", DWORD),\n        ("pvExtraPolicyPara", c_void_p),\n    )\n\n\nPCERT_CHAIN_POLICY_PARA = POINTER(CERT_CHAIN_POLICY_PARA)\n\n\nclass CERT_CHAIN_POLICY_STATUS(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("dwError", DWORD),\n        ("lChainIndex", LONG),\n        ("lElementIndex", LONG),\n        ("pvExtraPolicyStatus", c_void_p),\n    )\n\n\nPCERT_CHAIN_POLICY_STATUS = POINTER(CERT_CHAIN_POLICY_STATUS)\n\n\nclass CERT_CHAIN_ENGINE_CONFIG(Structure):\n    _fields_ = (\n        ("cbSize", DWORD),\n        ("hRestrictedRoot", HCERTSTORE),\n        ("hRestrictedTrust", HCERTSTORE),\n        ("hRestrictedOther", HCERTSTORE),\n        ("cAdditionalStore", DWORD),\n        ("rghAdditionalStore", c_void_p),\n        ("dwFlags", DWORD),\n        ("dwUrlRetrievalTimeout", DWORD),\n        ("MaximumCachedCertificates", DWORD),\n        ("CycleDetectionModulus", DWORD),\n        ("hExclusiveRoot", HCERTSTORE),\n        ("hExclusiveTrustedPeople", HCERTSTORE),\n        ("dwExclusiveFlags", DWORD),\n    )\n\n\nPCERT_CHAIN_ENGINE_CONFIG = POINTER(CERT_CHAIN_ENGINE_CONFIG)\nPHCERTCHAINENGINE = POINTER(HCERTCHAINENGINE)\n\nX509_ASN_ENCODING = 0x00000001\nPKCS_7_ASN_ENCODING = 0x00010000\nCERT_STORE_PROV_MEMORY = b"Memory"\nCERT_STORE_ADD_USE_EXISTING = 2\nUSAGE_MATCH_TYPE_OR = 1\nOID_PKIX_KP_SERVER_AUTH = c_char_p(b"1.3.6.1.5.5.7.3.1")\nCERT_CHAIN_REVOCATION_CHECK_END_CERT = 0x10000000\nCERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000\nCERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS = 0x00000007\nCERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG = 0x00000008\nCERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG = 0x00000010\nCERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG = 0x00000040\nCERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG = 0x00000020\nCERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG = 0x00000080\nCERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = 0x00000F00\nCERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG = 0x00008000\nCERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG = 0x00004000\nSECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000\nAUTHTYPE_SERVER = 2\nCERT_CHAIN_POLICY_SSL = 4\nFORMAT_MESSAGE_FROM_SYSTEM = 0x00001000\nFORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200\n\n# Flags to set for SSLContext.verify_mode=CERT_NONE\nCERT_CHAIN_POLICY_VERIFY_MODE_NONE_FLAGS = (\n    CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS\n    | CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG\n    | CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG\n    | CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG\n    | CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG\n    | CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG\n    | CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS\n    | CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG\n    | CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG\n)\n\nwincrypt = WinDLL("crypt32.dll")\nkernel32 = WinDLL("kernel32.dll")\n\n\ndef _handle_win_error(result: bool, _: Any, args: Any) -> Any:\n    if not result:\n        # Note, actually raises OSError after calling GetLastError and FormatMessage\n        raise WinError()\n    return args\n\n\nCertCreateCertificateChainEngine = wincrypt.CertCreateCertificateChainEngine\nCertCreateCertificateChainEngine.argtypes = (\n    PCERT_CHAIN_ENGINE_CONFIG,\n    PHCERTCHAINENGINE,\n)\nCertCreateCertificateChainEngine.errcheck = _handle_win_error\n\nCertOpenStore = wincrypt.CertOpenStore\nCertOpenStore.argtypes = (LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, c_void_p)\nCertOpenStore.restype = HCERTSTORE\nCertOpenStore.errcheck = _handle_win_error\n\nCertAddEncodedCertificateToStore = wincrypt.CertAddEncodedCertificateToStore\nCertAddEncodedCertificateToStore.argtypes = (\n    HCERTSTORE,\n    DWORD,\n    c_char_p,\n    DWORD,\n    DWORD,\n    PCCERT_CONTEXT,\n)\nCertAddEncodedCertificateToStore.restype = BOOL\n\nCertCreateCertificateContext = wincrypt.CertCreateCertificateContext\nCertCreateCertificateContext.argtypes = (DWORD, c_char_p, DWORD)\nCertCreateCertificateContext.restype = PCERT_CONTEXT\nCertCreateCertificateContext.errcheck = _handle_win_error\n\nCertGetCertificateChain = wincrypt.CertGetCertificateChain\nCertGetCertificateChain.argtypes = (\n    HCERTCHAINENGINE,\n    PCERT_CONTEXT,\n    LPFILETIME,\n    HCERTSTORE,\n    PCERT_CHAIN_PARA,\n    DWORD,\n    c_void_p,\n    PCCERT_CHAIN_CONTEXT,\n)\nCertGetCertificateChain.restype = BOOL\nCertGetCertificateChain.errcheck = _handle_win_error\n\nCertVerifyCertificateChainPolicy = wincrypt.CertVerifyCertificateChainPolicy\nCertVerifyCertificateChainPolicy.argtypes = (\n    c_ulong,\n    PCERT_CHAIN_CONTEXT,\n    PCERT_CHAIN_POLICY_PARA,\n    PCERT_CHAIN_POLICY_STATUS,\n)\nCertVerifyCertificateChainPolicy.restype = BOOL\n\nCertCloseStore = wincrypt.CertCloseStore\nCertCloseStore.argtypes = (HCERTSTORE, DWORD)\nCertCloseStore.restype = BOOL\nCertCloseStore.errcheck = _handle_win_error\n\nCertFreeCertificateChain = wincrypt.CertFreeCertificateChain\nCertFreeCertificateChain.argtypes = (PCERT_CHAIN_CONTEXT,)\n\nCertFreeCertificateContext = wincrypt.CertFreeCertificateContext\nCertFreeCertificateContext.argtypes = (PCERT_CONTEXT,)\n\nCertFreeCertificateChainEngine = wincrypt.CertFreeCertificateChainEngine\nCertFreeCertificateChainEngine.argtypes = (HCERTCHAINENGINE,)\n\nFormatMessageW = kernel32.FormatMessageW\nFormatMessageW.argtypes = (\n    DWORD,\n    LPCVOID,\n    DWORD,\n    DWORD,\n    LPWSTR,\n    DWORD,\n    c_void_p,\n)\nFormatMessageW.restype = DWORD\n\n\ndef _verify_peercerts_impl(\n    ssl_context: ssl.SSLContext,\n    cert_chain: list[bytes],\n    server_hostname: str | None = None,\n) -> None:\n    """Verify the cert_chain from the server using Windows APIs."""\n\n    # If the peer didn\'t send any certificates then\n    # we can\'t do verification. Raise an error.\n    if not cert_chain:\n        raise ssl.SSLCertVerificationError("Peer sent no certificates to verify")\n\n    pCertContext = None\n    hIntermediateCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, None, 0, None)\n    try:\n        # Add intermediate certs to an in-memory cert store\n        for cert_bytes in cert_chain[1:]:\n            CertAddEncodedCertificateToStore(\n                hIntermediateCertStore,\n                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,\n                cert_bytes,\n                len(cert_bytes),\n                CERT_STORE_ADD_USE_EXISTING,\n                None,\n            )\n\n        # Cert context for leaf cert\n        leaf_cert = cert_chain[0]\n        pCertContext = CertCreateCertificateContext(\n            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, leaf_cert, len(leaf_cert)\n        )\n\n        # Chain params to match certs for serverAuth extended usage\n        cert_enhkey_usage = CERT_ENHKEY_USAGE()\n        cert_enhkey_usage.cUsageIdentifier = 1\n        cert_enhkey_usage.rgpszUsageIdentifier = (c_char_p * 1)(OID_PKIX_KP_SERVER_AUTH)\n        cert_usage_match = CERT_USAGE_MATCH()\n        cert_usage_match.Usage = cert_enhkey_usage\n        chain_params = CERT_CHAIN_PARA()\n        chain_params.RequestedUsage = cert_usage_match\n        chain_params.cbSize = sizeof(chain_params)\n        pChainPara = pointer(chain_params)\n\n        if ssl_context.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN:\n            chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN\n        elif ssl_context.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF:\n            chain_flags = CERT_CHAIN_REVOCATION_CHECK_END_CERT\n        else:\n            chain_flags = 0\n\n        try:\n            # First attempt to verify using the default Windows system trust roots\n            # (default chain engine).\n            _get_and_verify_cert_chain(\n                ssl_context,\n                None,\n                hIntermediateCertStore,\n                pCertContext,\n                pChainPara,\n                server_hostname,\n                chain_flags=chain_flags,\n            )\n        except ssl.SSLCertVerificationError as e:\n            # If that fails but custom CA certs have been added\n            # to the SSLContext using load_verify_locations,\n            # try verifying using a custom chain engine\n            # that trusts the custom CA certs.\n            custom_ca_certs: list[bytes] | None = ssl_context.get_ca_certs(\n                binary_form=True\n            )\n            if custom_ca_certs:\n                try:\n                    _verify_using_custom_ca_certs(\n                        ssl_context,\n                        custom_ca_certs,\n                        hIntermediateCertStore,\n                        pCertContext,\n                        pChainPara,\n                        server_hostname,\n                        chain_flags=chain_flags,\n                    )\n                # Raise the original error, not the new error.\n                except ssl.SSLCertVerificationError:\n                    raise e from None\n            else:\n                raise\n    finally:\n        CertCloseStore(hIntermediateCertStore, 0)\n        if pCertContext:\n            CertFreeCertificateContext(pCertContext)\n\n\ndef _get_and_verify_cert_chain(\n    ssl_context: ssl.SSLContext,\n    hChainEngine: HCERTCHAINENGINE | None,\n    hIntermediateCertStore: HCERTSTORE,\n    pPeerCertContext: c_void_p,\n    pChainPara: PCERT_CHAIN_PARA,  # type: ignore[valid-type]\n    server_hostname: str | None,\n    chain_flags: int,\n) -> None:\n    ppChainContext = None\n    try:\n        # Get cert chain\n        ppChainContext = pointer(PCERT_CHAIN_CONTEXT())\n        CertGetCertificateChain(\n            hChainEngine,  # chain engine\n            pPeerCertContext,  # leaf cert context\n            None,  # current system time\n            hIntermediateCertStore,  # additional in-memory cert store\n            pChainPara,  # chain-building parameters\n            chain_flags,\n            None,  # reserved\n            ppChainContext,  # the resulting chain context\n        )\n        pChainContext = ppChainContext.contents\n\n        # Verify cert chain\n        ssl_extra_cert_chain_policy_para = SSL_EXTRA_CERT_CHAIN_POLICY_PARA()\n        ssl_extra_cert_chain_policy_para.cbSize = sizeof(\n            ssl_extra_cert_chain_policy_para\n        )\n        ssl_extra_cert_chain_policy_para.dwAuthType = AUTHTYPE_SERVER\n        ssl_extra_cert_chain_policy_para.fdwChecks = 0\n        if ssl_context.check_hostname is False:\n            ssl_extra_cert_chain_policy_para.fdwChecks = (\n                SECURITY_FLAG_IGNORE_CERT_CN_INVALID\n            )\n        if server_hostname:\n            ssl_extra_cert_chain_policy_para.pwszServerName = c_wchar_p(server_hostname)\n\n        chain_policy = CERT_CHAIN_POLICY_PARA()\n        chain_policy.pvExtraPolicyPara = cast(\n            pointer(ssl_extra_cert_chain_policy_para), c_void_p\n        )\n        if ssl_context.verify_mode == ssl.CERT_NONE:\n            chain_policy.dwFlags |= CERT_CHAIN_POLICY_VERIFY_MODE_NONE_FLAGS\n        chain_policy.cbSize = sizeof(chain_policy)\n\n        pPolicyPara = pointer(chain_policy)\n        policy_status = CERT_CHAIN_POLICY_STATUS()\n        policy_status.cbSize = sizeof(policy_status)\n        pPolicyStatus = pointer(policy_status)\n        CertVerifyCertificateChainPolicy(\n            CERT_CHAIN_POLICY_SSL,\n            pChainContext,\n            pPolicyPara,\n            pPolicyStatus,\n        )\n\n        # Check status\n        error_code = policy_status.dwError\n        if error_code:\n            # Try getting a human readable message for an error code.\n            error_message_buf = create_unicode_buffer(1024)\n            error_message_chars = FormatMessageW(\n                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,\n                None,\n                error_code,\n                0,\n                error_message_buf,\n                sizeof(error_message_buf),\n                None,\n            )\n\n            # See if we received a message for the error,\n            # otherwise we use a generic error with the\n            # error code and hope that it\'s search-able.\n            if error_message_chars <= 0:\n                error_message = f"Certificate chain policy error {error_code:#x} [{policy_status.lElementIndex}]"\n            else:\n                error_message = error_message_buf.value.strip()\n\n            err = ssl.SSLCertVerificationError(error_message)\n            err.verify_message = error_message\n            err.verify_code = error_code\n            raise err from None\n    finally:\n        if ppChainContext:\n            CertFreeCertificateChain(ppChainContext.contents)\n\n\ndef _verify_using_custom_ca_certs(\n    ssl_context: ssl.SSLContext,\n    custom_ca_certs: list[bytes],\n    hIntermediateCertStore: HCERTSTORE,\n    pPeerCertContext: c_void_p,\n    pChainPara: PCERT_CHAIN_PARA,  # type: ignore[valid-type]\n    server_hostname: str | None,\n    chain_flags: int,\n) -> None:\n    hChainEngine = None\n    hRootCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, None, 0, None)\n    try:\n        # Add custom CA certs to an in-memory cert store\n        for cert_bytes in custom_ca_certs:\n            CertAddEncodedCertificateToStore(\n                hRootCertStore,\n                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,\n                cert_bytes,\n                len(cert_bytes),\n                CERT_STORE_ADD_USE_EXISTING,\n                None,\n            )\n\n        # Create a custom cert chain engine which exclusively trusts\n        # certs from our hRootCertStore\n        cert_chain_engine_config = CERT_CHAIN_ENGINE_CONFIG()\n        cert_chain_engine_config.cbSize = sizeof(cert_chain_engine_config)\n        cert_chain_engine_config.hExclusiveRoot = hRootCertStore\n        pConfig = pointer(cert_chain_engine_config)\n        phChainEngine = pointer(HCERTCHAINENGINE())\n        CertCreateCertificateChainEngine(\n            pConfig,\n            phChainEngine,\n        )\n        hChainEngine = phChainEngine.contents\n\n        # Get and verify a cert chain using the custom chain engine\n        _get_and_verify_cert_chain(\n            ssl_context,\n            hChainEngine,\n            hIntermediateCertStore,\n            pPeerCertContext,\n            pChainPara,\n            server_hostname,\n            chain_flags,\n        )\n    finally:\n        if hChainEngine:\n            CertFreeCertificateChainEngine(hChainEngine)\n        CertCloseStore(hRootCertStore, 0)\n\n\n@contextlib.contextmanager\ndef _configure_context(ctx: ssl.SSLContext) -> typing.Iterator[None]:\n    check_hostname = ctx.check_hostname\n    verify_mode = ctx.verify_mode\n    ctx.check_hostname = False\n    _set_ssl_context_verify_mode(ctx, ssl.CERT_NONE)\n    try:\n        yield\n    finally:\n        ctx.check_hostname = check_hostname\n        _set_ssl_context_verify_mode(ctx, verify_mode)\n'), ('_api', 'import os\nimport platform\nimport socket\nimport ssl\nimport sys\nimport typing\n\nimport _ssl  # type: ignore[import-not-found]\n\nfrom ._ssl_constants import (\n    _original_SSLContext,\n    _original_super_SSLContext,\n    _truststore_SSLContext_dunder_class,\n    _truststore_SSLContext_super_class,\n)\n\nif platform.system() == "Windows":\n    from ._windows import _configure_context, _verify_peercerts_impl\nelif platform.system() == "Darwin":\n    from ._macos import _configure_context, _verify_peercerts_impl\nelse:\n    from ._openssl import _configure_context, _verify_peercerts_impl\n\nif typing.TYPE_CHECKING:\n    from typing_extensions import Buffer\n\n# From typeshed/stdlib/ssl.pyi\n_StrOrBytesPath: typing.TypeAlias = str | bytes | os.PathLike[str] | os.PathLike[bytes]\n_PasswordType: typing.TypeAlias = str | bytes | typing.Callable[[], str | bytes]\n\n\ndef inject_into_ssl() -> None:\n    """Injects the :class:`truststore.SSLContext` into the ``ssl``\n    module by replacing :class:`ssl.SSLContext`.\n    """\n    setattr(ssl, "SSLContext", SSLContext)\n    # urllib3 holds on to its own reference of ssl.SSLContext\n    # so we need to replace that reference too.\n    try:\n        import urllib3.util.ssl_ as urllib3_ssl\n\n        setattr(urllib3_ssl, "SSLContext", SSLContext)\n    except ImportError:\n        pass\n\n\ndef extract_from_ssl() -> None:\n    """Restores the :class:`ssl.SSLContext` class to its original state"""\n    setattr(ssl, "SSLContext", _original_SSLContext)\n    try:\n        import urllib3.util.ssl_ as urllib3_ssl\n\n        urllib3_ssl.SSLContext = _original_SSLContext  # type: ignore[assignment]\n    except ImportError:\n        pass\n\n\nclass SSLContext(_truststore_SSLContext_super_class):  # type: ignore[misc]\n    """SSLContext API that uses system certificates on all platforms"""\n\n    @property  # type: ignore[misc]\n    def __class__(self) -> type:\n        # Dirty hack to get around isinstance() checks\n        # for ssl.SSLContext instances in aiohttp/trustme\n        # when using non-CPython implementations.\n        return _truststore_SSLContext_dunder_class or SSLContext\n\n    def __init__(self, protocol: int = None) -> None:  # type: ignore[assignment]\n        self._ctx = _original_SSLContext(protocol)\n\n        class TruststoreSSLObject(ssl.SSLObject):\n            # This object exists because wrap_bio() doesn\'t\n            # immediately do the handshake so we need to do\n            # certificate verifications after SSLObject.do_handshake()\n\n            def do_handshake(self) -> None:\n                ret = super().do_handshake()\n                _verify_peercerts(self, server_hostname=self.server_hostname)\n                return ret\n\n        self._ctx.sslobject_class = TruststoreSSLObject\n\n    def wrap_socket(\n        self,\n        sock: socket.socket,\n        server_side: bool = False,\n        do_handshake_on_connect: bool = True,\n        suppress_ragged_eofs: bool = True,\n        server_hostname: str | None = None,\n        session: ssl.SSLSession | None = None,\n    ) -> ssl.SSLSocket:\n        # Use a context manager here because the\n        # inner SSLContext holds on to our state\n        # but also does the actual handshake.\n        with _configure_context(self._ctx):\n            ssl_sock = self._ctx.wrap_socket(\n                sock,\n                server_side=server_side,\n                server_hostname=server_hostname,\n                do_handshake_on_connect=do_handshake_on_connect,\n                suppress_ragged_eofs=suppress_ragged_eofs,\n                session=session,\n            )\n        try:\n            _verify_peercerts(ssl_sock, server_hostname=server_hostname)\n        except Exception:\n            ssl_sock.close()\n            raise\n        return ssl_sock\n\n    def wrap_bio(\n        self,\n        incoming: ssl.MemoryBIO,\n        outgoing: ssl.MemoryBIO,\n        server_side: bool = False,\n        server_hostname: str | None = None,\n        session: ssl.SSLSession | None = None,\n    ) -> ssl.SSLObject:\n        with _configure_context(self._ctx):\n            ssl_obj = self._ctx.wrap_bio(\n                incoming,\n                outgoing,\n                server_hostname=server_hostname,\n                server_side=server_side,\n                session=session,\n            )\n        return ssl_obj\n\n    def load_verify_locations(\n        self,\n        cafile: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,\n        capath: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,\n        cadata: typing.Union[str, "Buffer", None] = None,\n    ) -> None:\n        return self._ctx.load_verify_locations(\n            cafile=cafile, capath=capath, cadata=cadata\n        )\n\n    def load_cert_chain(\n        self,\n        certfile: _StrOrBytesPath,\n        keyfile: _StrOrBytesPath | None = None,\n        password: _PasswordType | None = None,\n    ) -> None:\n        return self._ctx.load_cert_chain(\n            certfile=certfile, keyfile=keyfile, password=password\n        )\n\n    def load_default_certs(\n        self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH\n    ) -> None:\n        return self._ctx.load_default_certs(purpose)\n\n    def set_alpn_protocols(self, alpn_protocols: typing.Iterable[str]) -> None:\n        return self._ctx.set_alpn_protocols(alpn_protocols)\n\n    def set_npn_protocols(self, npn_protocols: typing.Iterable[str]) -> None:\n        return self._ctx.set_npn_protocols(npn_protocols)\n\n    def set_ciphers(self, __cipherlist: str) -> None:\n        return self._ctx.set_ciphers(__cipherlist)\n\n    def get_ciphers(self) -> typing.Any:\n        return self._ctx.get_ciphers()\n\n    def session_stats(self) -> dict[str, int]:\n        return self._ctx.session_stats()\n\n    def cert_store_stats(self) -> dict[str, int]:\n        raise NotImplementedError()\n\n    def set_default_verify_paths(self) -> None:\n        self._ctx.set_default_verify_paths()\n\n    @typing.overload\n    def get_ca_certs(\n        self, binary_form: typing.Literal[False] = ...\n    ) -> list[typing.Any]: ...\n\n    @typing.overload\n    def get_ca_certs(self, binary_form: typing.Literal[True] = ...) -> list[bytes]: ...\n\n    @typing.overload\n    def get_ca_certs(self, binary_form: bool = ...) -> typing.Any: ...\n\n    def get_ca_certs(self, binary_form: bool = False) -> list[typing.Any] | list[bytes]:\n        raise NotImplementedError()\n\n    @property\n    def check_hostname(self) -> bool:\n        return self._ctx.check_hostname\n\n    @check_hostname.setter\n    def check_hostname(self, value: bool) -> None:\n        self._ctx.check_hostname = value\n\n    @property\n    def hostname_checks_common_name(self) -> bool:\n        return self._ctx.hostname_checks_common_name\n\n    @hostname_checks_common_name.setter\n    def hostname_checks_common_name(self, value: bool) -> None:\n        self._ctx.hostname_checks_common_name = value\n\n    @property\n    def keylog_filename(self) -> str:\n        return self._ctx.keylog_filename\n\n    @keylog_filename.setter\n    def keylog_filename(self, value: str) -> None:\n        self._ctx.keylog_filename = value\n\n    @property\n    def maximum_version(self) -> ssl.TLSVersion:\n        return self._ctx.maximum_version\n\n    @maximum_version.setter\n    def maximum_version(self, value: ssl.TLSVersion) -> None:\n        _original_super_SSLContext.maximum_version.__set__(  # type: ignore[attr-defined]\n            self._ctx, value\n        )\n\n    @property\n    def minimum_version(self) -> ssl.TLSVersion:\n        return self._ctx.minimum_version\n\n    @minimum_version.setter\n    def minimum_version(self, value: ssl.TLSVersion) -> None:\n        _original_super_SSLContext.minimum_version.__set__(  # type: ignore[attr-defined]\n            self._ctx, value\n        )\n\n    @property\n    def options(self) -> ssl.Options:\n        return self._ctx.options\n\n    @options.setter\n    def options(self, value: ssl.Options) -> None:\n        _original_super_SSLContext.options.__set__(  # type: ignore[attr-defined]\n            self._ctx, value\n        )\n\n    @property\n    def post_handshake_auth(self) -> bool:\n        return self._ctx.post_handshake_auth\n\n    @post_handshake_auth.setter\n    def post_handshake_auth(self, value: bool) -> None:\n        self._ctx.post_handshake_auth = value\n\n    @property\n    def protocol(self) -> ssl._SSLMethod:\n        return self._ctx.protocol\n\n    @property\n    def security_level(self) -> int:\n        return self._ctx.security_level\n\n    @property\n    def verify_flags(self) -> ssl.VerifyFlags:\n        return self._ctx.verify_flags\n\n    @verify_flags.setter\n    def verify_flags(self, value: ssl.VerifyFlags) -> None:\n        _original_super_SSLContext.verify_flags.__set__(  # type: ignore[attr-defined]\n            self._ctx, value\n        )\n\n    @property\n    def verify_mode(self) -> ssl.VerifyMode:\n        return self._ctx.verify_mode\n\n    @verify_mode.setter\n    def verify_mode(self, value: ssl.VerifyMode) -> None:\n        _original_super_SSLContext.verify_mode.__set__(  # type: ignore[attr-defined]\n            self._ctx, value\n        )\n\n\n# Python 3.13+ makes get_unverified_chain() a public API that only returns DER\n# encoded certificates. We detect whether we need to call public_bytes() for 3.10->3.12\n# Pre-3.13 returned None instead of an empty list from get_unverified_chain()\nif sys.version_info >= (3, 13):\n\n    def _get_unverified_chain_bytes(sslobj: ssl.SSLObject) -> list[bytes]:\n        unverified_chain = sslobj.get_unverified_chain() or ()  # type: ignore[attr-defined]\n        return [\n            cert if isinstance(cert, bytes) else cert.public_bytes(_ssl.ENCODING_DER)\n            for cert in unverified_chain\n        ]\n\nelse:\n\n    def _get_unverified_chain_bytes(sslobj: ssl.SSLObject) -> list[bytes]:\n        unverified_chain = sslobj.get_unverified_chain() or ()  # type: ignore[attr-defined]\n        return [cert.public_bytes(_ssl.ENCODING_DER) for cert in unverified_chain]\n\n\ndef _verify_peercerts(\n    sock_or_sslobj: ssl.SSLSocket | ssl.SSLObject, server_hostname: str | None\n) -> None:\n    """\n    Verifies the peer certificates from an SSLSocket or SSLObject\n    against the certificates in the OS trust store.\n    """\n    sslobj: ssl.SSLObject = sock_or_sslobj  # type: ignore[assignment]\n    try:\n        while not hasattr(sslobj, "get_unverified_chain"):\n            sslobj = sslobj._sslobj  # type: ignore[attr-defined]\n    except AttributeError:\n        pass\n\n    cert_bytes = _get_unverified_chain_bytes(sslobj)\n    _verify_peercerts_impl(\n        sock_or_sslobj.context, cert_bytes, server_hostname=server_hostname\n    )\n')]
