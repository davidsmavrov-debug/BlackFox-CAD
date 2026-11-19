# SPDX-License-Identifier: GPL-3.0-or-later
"""
BlackFox 3D Inspector v1.2.0 — read-only developer diagnostics
Verified with IngeTrazo 0.6.2.1 source and PySide6.

Install this file in the user plugins folder:
Extensions -> Open plugins folder
Then restart IngeTrazo and run Extensions -> 3D Inspector -> 3D Inspector.

The inspector deliberately uses defensive runtime introspection. It reads the
document; it does not modify geometry, groups, components, layers or history.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import inspect
from itertools import islice
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QLabel,
    QHBoxLayout,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
)



MAX_ITEMS = 30
MAX_DEPTH = 3
MAX_TEXT = 180


def _safe_repr(value: Any, limit: int = MAX_TEXT) -> str:
    try:
        text = repr(value)
    except Exception as exc:
        text = f"<repr failed: {type(exc).__name__}>"
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _public_fields(obj: Any) -> list[tuple[str, Any]]:
    """Return readable instance fields without invoking arbitrary methods."""
    found: dict[str, Any] = {}

    try:
        data = vars(obj)
    except Exception:
        data = {}

    if isinstance(data, dict):
        for name, value in data.items():
            if isinstance(name, str) and not name.startswith("_"):
                found[name] = value

    # Include slots and useful properties exposed by the runtime type.
    try:
        names = dir(obj)
    except Exception:
        names = []

    for name in names:
        if not isinstance(name, str) or name.startswith("_") or name in found:
            continue
        if name in {
            "parent", "children", "deleteLater", "destroyed",
            "signalsBlocked", "thread", "metaObject",
        }:
            continue
        try:
            value = getattr(obj, name)
        except Exception:
            continue
        if callable(value):
            continue
        # Avoid walking Qt internals or arbitrary large object graphs.
        if type(value).__module__.startswith(("PySide", "shiboken")):
            continue
        found[name] = value

    return list(found.items())


def _items(value: Any) -> list[Any] | None:
    if value is None or isinstance(value, (str, bytes, dict)):
        return None
    try:
        if isinstance(value, Iterable):
            return list(value)
    except Exception:
        pass
    return None


def _fmt_collection(name: str, value: Any) -> str:
    items = _items(value)
    if items is None:
        return f"{name}: {_safe_repr(value)}"
    return f"{name}: {len(items)} item(s)"


def _describe_object(obj: Any, title: str, depth: int = 0) -> list[str]:
    pad = "  " * depth
    lines = [f"{pad}{title}: {type(obj).__module__}.{type(obj).__name__}"]
    if depth >= MAX_DEPTH:
        return lines

    for name, value in _public_fields(obj):
        items = _items(value)
        if items is not None:
            lines.append(f"{pad}  {name}: {len(items)} item(s)")
            if name in {"vertices", "edges", "faces", "groups", "layers"}:
                for index, item in enumerate(items[:MAX_ITEMS]):
                    lines.append(
                        f"{pad}    [{index}] "
                        f"{type(item).__name__}: {_safe_repr(item, 110)}"
                    )
                if len(items) > MAX_ITEMS:
                    lines.append(f"{pad}    ... {len(items) - MAX_ITEMS} more")
        else:
            lines.append(f"{pad}  {name} = {_safe_repr(value)}")
    return lines


def _inspect_mesh(mesh: Any, label: str) -> list[str]:
    lines = [f"\n[{label}] {type(mesh).__module__}.{type(mesh).__name__}"]
    for attr in ("vertices", "edges", "faces"):
        try:
            collection = getattr(mesh, attr)
            count = len(collection)
            lines.append(f"  {attr}: {count}")
            if attr == "vertices":
                for i, vertex in enumerate(list(collection)[:10]):
                    try:
                        position = vertex.position
                    except Exception:
                        position = "<no .position>"
                    lines.append(
                        f"    vertex[{i}] type={type(vertex).__name__} "
                        f"position={_safe_repr(position)}"
                    )
            elif attr == "edges":
                for i, edge in enumerate(list(collection)[:8]):
                    fields = []
                    for field in ("v0", "v1"):
                        try:
                            fields.append(f"{field}={_safe_repr(getattr(edge, field))}")
                        except Exception:
                            pass
                    lines.append(f"    edge[{i}] " + ", ".join(fields))
            elif attr == "faces":
                for i, face in enumerate(list(collection)[:8]):
                    try:
                        loop = face.loop
                        loop_info = f"loop={_safe_repr(loop)}"
                    except Exception:
                        loop_info = "loop=<unavailable>"
                    try:
                        holes = face.hole_loops
                        hole_info = f" holes={_safe_repr(holes)}"
                    except Exception:
                        hole_info = ""
                    lines.append(f"    face[{i}] {loop_info}{hole_info}")
        except Exception as exc:
            lines.append(f"  {attr}: unavailable ({type(exc).__name__}: {exc})")
    return lines



def _edge_attribute_report(edge: Any) -> list[str]:
    """Inspect one edge without traversing arbitrary object relationships."""
    lines: list[str] = []
    try:
        names = [n for n in dir(edge) if isinstance(n, str) and not n.startswith("_")]
    except Exception:
        names = []

    # Always show the Python-visible API, including methods. This is useful
    # when a native curve object exposes behavior rather than stored fields.
    if names:
        lines.append("    public API: " + ", ".join(names[:100]))
        if len(names) > 100:
            lines.append(f"      ... {len(names) - 100} more names")

    keywords = (
        "curve", "arc", "circle", "radius", "center", "centre", "angle",
        "bulge", "control", "spline", "poly", "geometry", "point",
        "start", "end", "vertex", "v0", "v1", "type", "length",
        "hidden", "smooth", "crease", "id", "uuid",
    )
    shown = set()

    # Instance storage first.
    try:
        instance_fields = vars(edge)
    except Exception:
        instance_fields = {}

    if isinstance(instance_fields, dict):
        for name, value in instance_fields.items():
            if isinstance(name, str) and not name.startswith("_"):
                lines.append(f"    field {name} = {_safe_repr(value)}")
                shown.add(name)

    # Then read relevant public properties, but never invoke methods.
    for name in names:
        if name in shown or not any(word in name.lower() for word in keywords):
            continue
        try:
            value = getattr(edge, name)
        except Exception as exc:
            lines.append(f"    property {name}: <raises {type(exc).__name__}>")
            continue
        if callable(value):
            continue
        lines.append(f"    property {name} = {_safe_repr(value)}")
        shown.add(name)

    if not shown:
        lines.append("    No readable curve/geometry-related data fields found.")
    return lines


def _inspect_edge_diagnostics(mesh: Any, label: str) -> list[str]:
    """Report edge classes, API and a tail sample likely to include new test edges."""
    lines = [f"\nEDGE DIAGNOSTICS — {label}"]
    try:
        edges = list(mesh.edges)
    except Exception as exc:
        return lines + [f"  Could not read edges: {type(exc).__name__}: {exc}"]

    lines.append(f"  Total edges: {len(edges)}")

    # Count edge classes across the entire mesh.
    counts: dict[str, int] = {}
    for edge in edges:
        type_name = f"{type(edge).__module__}.{type(edge).__name__}"
        counts[type_name] = counts.get(type_name, 0) + 1
    lines.append("  Edge type counts:")
    for type_name, count in sorted(counts.items()):
        lines.append(f"    {type_name}: {count}")

    if not edges:
        return lines

    # Inspect one representative edge's API in detail.
    sample = edges[-1]
    lines.append(f"\n  EDGE CLASS/API SAMPLE (edge[{len(edges)-1}])")
    lines.append(f"    repr: {_safe_repr(sample, 300)}")
    lines.extend(_edge_attribute_report(sample))

    # The benchmark objects were added after the original solids. Meshes
    # commonly append newly-created edges, so inspect a generous tail window.
    tail_count = min(80, len(edges))
    start = len(edges) - tail_count
    lines.append(
        f"\n  LAST {tail_count} EDGES (indices {start}..{len(edges)-1})"
    )
    for index in range(start, len(edges)):
        edge = edges[index]
        parts = [f"  edge[{index}] {type(edge).__module__}.{type(edge).__name__}"]
        for attr in ("v0", "v1"):
            try:
                vertex = getattr(edge, attr)
                try:
                    position = vertex.position
                except Exception:
                    position = "<no position>"
                parts.append(f"{attr}={_safe_repr(position, 120)}")
            except Exception:
                pass
        lines.append("    " + " | ".join(parts))
        # Detailed attributes on the last 12 edges, to keep the report usable.
        if index >= len(edges) - 12:
            lines.extend(_edge_attribute_report(edge))

    # Also report the edge class/API for the first edge for comparison.
    if len(edges) > 1:
        first = edges[0]
        lines.append("\n  FIRST EDGE COMPARISON")
        lines.append(f"    repr: {_safe_repr(first, 300)}")
        lines.extend(_edge_attribute_report(first))

    return lines



def _inspect_topology(scene: Any) -> list[str]:
    """Bounded, read-only investigation of curve IDs, topology and mesh internals."""
    from collections import Counter, defaultdict
    lines = ["", "CURVES / TOPOLOGY / LAYERS / DEFERRED MESH"]
    try:
        mesh = scene.loose_mesh
        edges = list(mesh.edges)
    except Exception as exc:
        return lines + [f"Loose edges unavailable: {exc}"]

    def val(obj, attr):
        try:
            return getattr(obj, attr)
        except Exception as exc:
            return f"<unavailable: {type(exc).__name__}>"

    def position(vertex):
        p = val(vertex, "position")
        return _safe_repr(p, 130)

    def storage(obj, label):
        lines.append(f"  {label}: {type(obj).__module__}.{type(obj).__name__}")
        try:
            d = vars(obj)
            lines.append("    instance keys: " + ", ".join(str(k) for k in list(d)[:100]))
            for k, v in list(d.items())[:50]:
                if any(term in str(k).lower() for term in ("curve", "arc", "circle", "layer", "edge", "mesh", "base", "source", "defer")):
                    lines.append(f"    {k}: {type(v).__name__} {_safe_repr(v, 130)}")
        except Exception as exc:
            lines.append(f"    vars unavailable: {type(exc).__name__}")
        try:
            names = dir(obj)
            relevant = [n for n in names if any(term in n.lower() for term in
                ("curve", "arc", "circle", "layer", "edge", "mesh", "base", "source", "defer"))]
            lines.append("    relevant API: " + ", ".join(relevant[:100]))
        except Exception:
            pass

    lines.append("\n  MESH STORAGE / REGISTRY")
    storage(mesh, "scene.loose_mesh")
    try:
        storage(scene.mesh, "scene.mesh")
    except Exception:
        pass
    lines.append("\n  CURVE IDENTIFIERS (ALL LOOSE EDGES)")
    groups = defaultdict(list)
    layers = Counter()
    for i, edge in enumerate(edges):
        curve = val(edge, "curve")
        key = f"{type(curve).__name__}: {_safe_repr(curve, 80)}"
        groups[key].append(i)
        layer = val(edge, "layer")
        layers[f"{type(layer).__name__}: {_safe_repr(layer, 100)}"] += 1
    lines.append(f"  Distinct curve values: {len(groups)}")
    for key, indices in sorted(groups.items(), key=lambda kv: kv[1][0])[:80]:
        spans = []
        start = prev = indices[0]
        for i in indices[1:]:
            if i != prev + 1:
                spans.append(f"{start}-{prev}" if start != prev else str(start))
                start = i
            prev = i
        spans.append(f"{start}-{prev}" if start != prev else str(start))
        lines.append(f"  {key}: {len(indices)} edge(s); ranges={', '.join(spans[:30])}")
    lines.append("  EDGE LAYER DISTRIBUTION")
    for key, count in layers.most_common(30):
        lines.append(f"    {key}: {count}")

    # Sample recent edges for their IDs, layers and
    # connectivity without assuming that a numeric curve ID is a curve object.
    lines.append("\n  LAST 60 EDGE CURVE/LAYER/CONNECTIVITY DETAILS")
    start = max(0, len(edges) - 60)
    for i in range(start, len(edges)):
        e = edges[i]
        a, b = val(e, "v0"), val(e, "v1")
        lines.append(f"  [{i}] curve={_safe_repr(val(e,'curve'),70)} layer={_safe_repr(val(e,'layer'),70)} "
                     f"v0={position(a)} v1={position(b)}")
    lines.append("\n  CURVE-ID GROUP TOPOLOGY (TAIL-INTERSECTING GROUPS)")
    for key, indices in sorted(groups.items(), key=lambda kv: kv[1][0]):
        if indices[-1] < start:
            continue
        if len(indices) > 250:
            lines.append(f"  {key}: {len(indices)} edges; topology skipped (large group)")
            continue
        degree = Counter()
        for i in indices:
            e = edges[i]
            for attr in ("v0", "v1"):
                vertex = val(e, attr)
                degree[id(vertex)] += 1
        degree_counts = Counter(degree.values())
        lines.append(f"  {key}: {len(indices)} edges; vertex degrees={dict(sorted(degree_counts.items()))}; "
                     f"open endpoints={degree_counts.get(1, 0)}")

    lines.append("\n  GROUP / COMPONENT DEFERRED MESH STORAGE")
    try:
        seen = set()
        for i, group in enumerate(list(scene.groups)[:20]):
            gm = val(group, "mesh")
            if id(gm) in seen:
                lines.append(f"  group[{i}] shares previously inspected mesh")
                continue
            seen.add(id(gm))
            storage(gm, f"group[{i}].mesh")
            storage(group, f"group[{i}]")
    except Exception as exc:
        lines.append(f"  group inspection error: {type(exc).__name__}: {exc}")
    return lines

def _colour_details(value: Any) -> str:
    """Describe actual colour data; avoid bogus Qt-method errors on None/dicts."""
    parts = [f"type={type(value).__module__}.{type(value).__name__}",
             f"repr={_safe_repr(value, 250)}"]
    if value is None or isinstance(value, (dict, list, tuple, str, int, float, bool)):
        return "; ".join(parts)
    for method in ("name", "getRgb", "getRgbF", "red", "green", "blue", "alpha"):
        try:
            candidate = getattr(value, method, None)
            if callable(candidate):
                parts.append(f"{method}()={_safe_repr(candidate(), 150)}")
        except Exception:
            pass
    for attr in ("r", "g", "b", "a", "rgb", "rgba", "hex", "value"):
        try:
            result = getattr(value, attr)
            if not callable(result):
                parts.append(f"{attr}={_safe_repr(result, 150)}")
        except Exception:
            pass
    return "; ".join(parts)


def _inspect_layer(layer: Any, index: int) -> list[str]:
    lines = [f"\nLayer [{index}] {type(layer).__module__}.{type(layer).__name__}"]
    try:
        names = [n for n in dir(layer) if isinstance(n, str) and not n.startswith("_")]
        lines.append("  public API: " + ", ".join(names[:150]))
    except Exception as exc:
        lines.append(f"  public API unavailable: {exc}")
    try:
        data = vars(layer)
        lines.append("  instance storage: " + _safe_repr(data, 1000))
    except Exception:
        lines.append("  instance storage unavailable")
    for name, value in _public_fields(layer):
        lines.append(f"  {name}: {_colour_details(value) if any(k in name.lower() for k in ('col', 'rgb', 'rgba', 'paint', 'material')) else _safe_repr(value, 250)}")
    return lines


def _inspect_colour_sources(scene: Any) -> list[str]:
    lines = ["", "LAYER COLOUR STORAGE DIAGNOSTICS"]
    for owner_name, owner in (("scene", scene), ("scene.layers", getattr(scene, "layers", None))):
        if owner is None:
            continue
        lines.append(f"  {owner_name}: {type(owner).__module__}.{type(owner).__name__}")
        try:
            names = [n for n in dir(owner) if isinstance(n, str) and
                     any(k in n.lower() for k in ('layer', 'col', 'rgb', 'palette', 'style', 'material'))]
            lines.append("    matching API: " + ", ".join(names[:150]))
            for name in names[:80]:
                if name.startswith('_'):
                    continue
                try:
                    value = getattr(owner, name)
                    if not callable(value):
                        lines.append(f"    {name}: {_colour_details(value)}")
                except Exception as exc:
                    lines.append(f"    {name}: <{type(exc).__name__}>")
        except Exception as exc:
            lines.append(f"    inspection failed: {type(exc).__name__}: {exc}")
    return lines




def _inspect_guides(scene: Any) -> list[str]:
    """Read-only diagnostics for Tape Measure guides and point candidates."""
    lines = ["", "GUIDE / CONSTRUCTION POINT DIAGNOSTICS"]
    try:
        guides = list(scene.guides)
    except Exception as exc:
        return lines + [f"  Guides unavailable: {type(exc).__name__}: {exc}"]
    lines.append(f"  scene.guides: {len(guides)} item(s)")
    for index, guide in enumerate(guides[:MAX_ITEMS]):
        lines.append(f"\n  GUIDE [{index}] {type(guide).__module__}.{type(guide).__name__}")
        lines.append(f"    repr: {_safe_repr(guide, 400)}")
        try:
            data = vars(guide)
            lines.append(f"    instance storage: {_safe_repr(data, 2000)}")
        except Exception as exc:
            lines.append(f"    instance storage unavailable: {type(exc).__name__}")
        try:
            names = [n for n in dir(guide) if isinstance(n, str) and not n.startswith('_')]
            lines.append("    public API: " + ", ".join(names[:150]))
        except Exception as exc:
            lines.append(f"    public API unavailable: {type(exc).__name__}")
        for name, value in _public_fields(guide):
            lines.append(f"    {name}: {type(value).__name__} = {_safe_repr(value, 350)}")
    if len(guides) > MAX_ITEMS:
        lines.append(f"  ... {len(guides) - MAX_ITEMS} additional guides omitted")
    return lines



def _inspect_annotation_collection(scene: Any, name: str) -> list[str]:
    """Read annotations without assuming an IngeTrazo storage schema."""
    lines = ["", f"{name.upper()} DIAGNOSTICS"]
    try:
        collection = getattr(scene, name)
    except Exception as exc:
        return lines + [f"  scene.{name} unavailable: {type(exc).__name__}: {exc}"]
    try:
        objects = list(collection.items()) if isinstance(collection, dict) else list(collection)
    except Exception as exc:
        return lines + [f"  scene.{name} not iterable: {type(exc).__name__}: {exc}",
                        f"  raw: {_safe_repr(collection, 500)}"]
    lines.append(f"  scene.{name}: {len(objects)} item(s)")
    for index, entry in enumerate(objects[:MAX_ITEMS]):
        if isinstance(collection, dict):
            key, obj = entry
            lines.append(f"    dictionary key: {_safe_repr(key, 300)}")
        else:
            obj = entry
        lines.append(f"\n  {name}[{index}]: {type(obj).__module__}.{type(obj).__name__}")
        lines.append(f"    repr: {_safe_repr(obj, 600)}")
        try:
            lines.append(f"    instance storage: {_safe_repr(vars(obj), 2400)}")
        except Exception as exc:
            lines.append(f"    instance storage unavailable: {type(exc).__name__}")
        try:
            names = [n for n in dir(obj) if isinstance(n, str) and not n.startswith('_')]
            lines.append("    public API: " + ", ".join(names[:180]))
        except Exception:
            pass
        for field, value in _public_fields(obj):
            if any(word in field.lower() for word in ('color', 'colour', 'material', 'paint')):
                detail = _colour_details(value)
            else:
                detail = _safe_repr(value, 600)
            lines.append(f"    {field}: {type(value).__name__} = {detail}")
    if len(objects) > MAX_ITEMS:
        lines.append(f"  ... {len(objects) - MAX_ITEMS} more item(s)")
    return lines


def _inspect_styles_and_materials(scene: Any) -> list[str]:
    lines = ["", "DIMENSION STYLE / TEXT STYLE / MATERIAL SOURCES"]
    keywords = ('dimension', 'text', 'annotation', 'material', 'texture', 'paint', 'style', 'font')
    for label, owner in (("scene", scene),
                         ("scene.loose_mesh", getattr(scene, 'loose_mesh', None))):
        if owner is None:
            continue
        try:
            names = [n for n in dir(owner) if not n.startswith('_')
                     and any(k in n.lower() for k in keywords)]
        except Exception:
            names = []
        lines.append(f"  {label} matching attributes: {', '.join(names[:120]) or '<none>'}")
        for name in names[:60]:
            try:
                value = getattr(owner, name)
                if callable(value):
                    continue
                lines.append(f"    {name}: {type(value).__module__}.{type(value).__name__} = {_safe_repr(value, 1000)}")
                if not isinstance(value, (str, int, float, bool, list, tuple, dict, type(None))):
                    for field, detail in _public_fields(value)[:45]:
                        lines.append(f"      {field} = {_safe_repr(detail, 400)}")
            except Exception as exc:
                lines.append(f"    {name}: <{type(exc).__name__}: {exc}>")
    # Sample face/group assignments without traversing the entire model.
    for label, objects in (("loose faces", getattr(getattr(scene, 'loose_mesh', None), 'faces', [])),
                           ("groups", getattr(scene, 'groups', []))):
        try:
            samples = list(objects)[:8]
        except Exception:
            continue
        lines.append(f"  {label} material/texture/color fields (first {len(samples)}):")
        for i, obj in enumerate(samples):
            fields = [(k, v) for k, v in _public_fields(obj)
                      if any(t in k.lower() for t in ('material', 'texture', 'paint', 'color', 'colour'))]
            lines.append(f"    [{i}] " + ("; ".join(f"{k}={_safe_repr(v, 250)}" for k, v in fields) or '<none>'))
    return lines

def _inspect_survey_points(scene: Any) -> list[str]:
    """Read-only, bounded inspection of georeferenced survey point storage."""
    lines = ["", "SURVEY / GEO_POINTS DIAGNOSTICS"]
    try:
        points = getattr(scene, "geo_points")
    except Exception as exc:
        return lines + [f"  geo_points unavailable: {type(exc).__name__}: {exc}"]
    if isinstance(points, dict):
        try:
            entries = list(points.items())[:MAX_ITEMS + 1]
        except Exception as exc:
            return lines + [f"  Cannot read mapping: {type(exc).__name__}: {exc}"]
    else:
        try:
            entries = list(points[:MAX_ITEMS + 1])
        except Exception:
            try:
                from itertools import islice
                entries = list(islice(iter(points), MAX_ITEMS + 1))
            except Exception as exc:
                return lines + [f"  Cannot iterate points: {type(exc).__name__}: {exc}"]
    try:
        count = len(points)
    except Exception:
        count = f"at least {len(entries)}"
    lines.append(f"  scene.geo_points: {count} item(s)")
    for i, entry in enumerate(entries[:MAX_ITEMS]):
        if isinstance(points, dict):
            key, obj = entry
            lines.append(f"  key[{i}]: {_safe_repr(key, 300)}")
        else:
            obj = entry
        lines.append(f"  POINT [{i}] {type(obj).__module__}.{type(obj).__name__}")
        lines.append(f"    repr: {_safe_repr(obj, 1000)}")
        if isinstance(obj, dict):
            fields = list(obj.items())
        elif isinstance(obj, (tuple, list)):
            fields = [(f"[{j}]", val) for j, val in enumerate(obj[:40])]
        else:
            try:
                lines.append(f"    instance storage: {_safe_repr(vars(obj), 1800)}")
            except (TypeError, AttributeError):
                pass
            fields = _public_fields(obj)
            try:
                names = [n for n in dir(obj) if isinstance(n, str) and not n.startswith("_")]
                lines.append("    public API: " + ", ".join(names[:100]))
            except Exception:
                pass
        for field, value in fields[:60]:
            lines.append(f"    {field}: {type(value).__name__} = {_safe_repr(value, 700)}")
            if str(field).lower() in ("position", "pos", "coord", "coords", "coordinate", "coordinates", "point", "xyz"):
                if not isinstance(value, (str, int, float, tuple, list, dict, type(None))):
                    for subfield, subvalue in _public_fields(value)[:15]:
                        lines.append(f"      {subfield}: {_safe_repr(subvalue, 250)}")
    if len(entries) > MAX_ITEMS:
        lines.append("  ... additional points omitted")
    lines += ["", "GEOREFERENCE / DATUM DIAGNOSTICS"]
    try:
        datum = getattr(scene, "georef", None)
        lines.append(f"  scene.georef: {type(datum).__module__}.{type(datum).__name__}")
        lines.append(f"  repr: {_safe_repr(datum, 900)}")
        if datum is not None:
            try:
                lines.append(f"  instance storage: {_safe_repr(vars(datum), 1800)}")
            except (TypeError, AttributeError):
                pass
            for field, value in _public_fields(datum)[:60]:
                lines.append(f"  {field}: {type(value).__name__} = {_safe_repr(value, 600)}")
    except Exception as exc:
        lines.append(f"  datum inspection failed: {type(exc).__name__}: {exc}")
    return lines


def _inspect_texture_mapping(scene: Any) -> list[str]:
    """Read-only texture diagnostics; never invoke material or geometry methods."""
    lines = ["", "V1.1 — TEXTURE / FACE MAPPING DIAGNOSTICS"]
    materials = getattr(scene, "materials", None)
    if isinstance(materials, dict):
        lines.append(f"  scene.materials: {len(materials)} material(s)")
        for key, material in list(materials.items())[:MAX_ITEMS]:
            lines.append(f"  material[{_safe_repr(key, 200)}]:")
            for attr in ("name", "color", "texture", "opacity", "finish"):
                try:
                    value = getattr(material, attr)
                    if not callable(value):
                        lines.append(f"    {attr}: {_safe_repr(value, 1500)}")
                except Exception as exc:
                    lines.append(f"    {attr}: <{type(exc).__name__}>")
        if len(materials) > MAX_ITEMS:
            lines.append(f"  ... {len(materials) - MAX_ITEMS} more materials omitted")
    else:
        lines.append("  scene.materials: unavailable or not a dictionary")

    sources = [("scene.loose_mesh", getattr(scene, "loose_mesh", None))]
    try:
        groups = list(scene.groups)
    except Exception:
        groups = []
    for i, group in enumerate(groups[:MAX_ITEMS]):
        try:
            name = getattr(group, "name", None)
            mesh = getattr(group, "mesh", None)
            lines.append(f"  group[{i}] name={_safe_repr(name, 200)} material={_safe_repr(getattr(group, 'material', None), 250)}")
            sources.append((f"group[{i}].mesh", mesh))
        except Exception as exc:
            lines.append(f"  group[{i}] unavailable: {type(exc).__name__}: {exc}")
    if len(groups) > MAX_ITEMS:
        lines.append(f"  ... {len(groups) - MAX_ITEMS} additional groups omitted")

    for label, mesh in sources:
        if mesh is None:
            continue
        try:
            faces = list(mesh.faces)
        except Exception as exc:
            lines.append(f"  {label}.faces unavailable: {type(exc).__name__}: {exc}")
            continue
        lines.append(f"  {label}: {len(faces)} face(s)")
        for i, face in enumerate(faces[:MAX_ITEMS]):
            lines.append(f"    face[{i}] {type(face).__module__}.{type(face).__name__}")
            try:
                attrs = face.attrs
                lines.append(f"      attrs: {_safe_repr(attrs, 2500)}")
                if isinstance(attrs, dict):
                    for key in ("mat", "back", "texture"):
                        if key in attrs:
                            lines.append(f"      attrs[{key!r}]: {_safe_repr(attrs[key], 2000)}")
                    texture = attrs.get("texture")
                    if isinstance(texture, dict):
                        for key in ("path", "sw", "sh", "uvw", "planar"):
                            if key in texture:
                                lines.append(f"        texture[{key!r}]: {_safe_repr(texture[key], 1500)}")
            except Exception as exc:
                lines.append(f"      attrs unavailable: {type(exc).__name__}: {exc}")
            try:
                lines.append(f"      loop: {_safe_repr(face.loop, 800)}")
            except Exception:
                pass
        if len(faces) > MAX_ITEMS:
            lines.append(f"    ... {len(faces) - MAX_ITEMS} more faces omitted")
    lines.append("  Read-only inspection; UVW and back-face semantics not inferred.")
    return lines


def _collect_report(scene: Any) -> str:
    lines = [
        "INGETRAZO 3D INSPECTOR",
        "Read-only runtime report",
        "=======================",
        "",
        f"Scene type: {type(scene).__module__}.{type(scene).__name__}",
    ]

    # Scene-level fields: list names and types, not the entire application graph.
    lines += ["", "SCENE FIELDS"]
    for name, value in _public_fields(scene):
        items = _items(value)
        if items is not None:
            lines.append(f"  {name}: {len(items)} item(s)")
        elif isinstance(value, (str, int, float, bool, type(None))):
            lines.append(f"  {name} = {_safe_repr(value)}")
        else:
            lines.append(f"  {name}: {type(value).__module__}.{type(value).__name__}")

    # Loose mesh is the scene geometry source documented by IngeTrazo.
    lines += ["", "LOOSE GEOMETRY"]
    try:
        loose_mesh = scene.loose_mesh
        lines += _inspect_mesh(loose_mesh, "scene.loose_mesh")
        lines += _inspect_edge_diagnostics(loose_mesh, "scene.loose_mesh")
    except Exception as exc:
        lines.append(f"Could not inspect scene.loose_mesh: {type(exc).__name__}: {exc}")

    lines += _inspect_topology(scene)

    # Layers.
    lines += ["", "LAYERS"]
    try:
        layers = list(scene.layers)
        lines.append(f"scene.layers: {len(layers)}")
        for index, layer in enumerate(layers):
            lines += _inspect_layer(layer, index)
    except Exception as exc:
        lines.append(f"Could not inspect scene.layers: {type(exc).__name__}: {exc}")

    lines += _inspect_colour_sources(scene)
    lines += _inspect_guides(scene)
    lines += _inspect_survey_points(scene)
    for collection_name in ("dimensions", "text_labels", "texts", "text_entities", "annotations"):
        lines += _inspect_annotation_collection(scene, collection_name)
    lines += _inspect_styles_and_materials(scene)
    lines += _inspect_texture_mapping(scene)

    lines += [
        "",
        "END OF REPORT",
        "No document data was modified.",
    ]
    return "\n".join(lines)



def _inspect_catenary_compatibility(scene, viewport):
    """Read-only probes for BlackFox Catenary integration and quick upgrades."""
    import inspect
    lines = ["", "CATENARY API WATCH", "Read-only runtime checks (no geometry created)."]

    def describe(label, obj, methods):
        lines.append(f"{label}: {type(obj).__module__}.{type(obj).__name__}" if obj is not None
                     else f"{label}: unavailable")
        if obj is None:
            return
        for method in methods:
            try:
                member = getattr(obj, method, None)
                if member is None:
                    lines.append(f"  {method}: MISSING")
                    continue
                try:
                    sig = str(inspect.signature(member))
                except (TypeError, ValueError):
                    sig = "(signature unavailable)"
                lines.append(f"  {method}{sig}: {'callable' if callable(member) else 'attribute'}")
            except Exception as exc:
                lines.append(f"  {method}: ERROR {type(exc).__name__}: {exc}")

    mesh = getattr(scene, 'mesh', None)
    describe('scene.mesh', mesh, ('add_edge', 'vertex', 'vertex_at', 'tag_curve',
                                  'curve_edges', 'next_curve_id', 'resplit_curves',
                                  'add_edges_welded'))
    describe('viewport', viewport, ('set_active_tool', 'notify_scene_changed',
                                    'flash_status', 'update', 'world_to_screen'))
    describe('viewport.history', getattr(viewport, 'history', None), ('execute', 'undo', 'redo'))
    try:
        from core.history import SnapshotImport
        describe('core.history.SnapshotImport', SnapshotImport, ('__init__',))
    except Exception as exc:
        lines.append(f"SnapshotImport import failed: {type(exc).__name__}: {exc}")
    try:
        from tools.base import Tool
        describe('tools.base.Tool', Tool, ('on_activate', 'on_deactivate', 'on_click',
                                           'on_hover', 'on_cancel', 'rubber_band_lines'))
    except Exception as exc:
        lines.append(f"Tool import failed: {type(exc).__name__}: {exc}")
    try:
        from tools.select import SelectTool
        describe('tools.select.SelectTool', SelectTool, ('__init__',))
    except Exception as exc:
        lines.append(f"SelectTool import failed: {type(exc).__name__}: {exc}")
    try:
        from views.extension_api import ExtensionApp, API_VERSION
        lines.append(f"Extension API_VERSION: {API_VERSION!r}")
        describe('views.extension_api.ExtensionApp', ExtensionApp,
                 ('add_menu', 'add_menu_action', 'add_overlay'))
    except Exception as exc:
        lines.append(f"ExtensionApp import failed: {type(exc).__name__}: {exc}")

    if mesh is not None:
        edges = getattr(mesh, 'edges', ())
        try:
            count = len(edges)
            lines.append(f"mesh.edges count: {count}")
            curves = {}
            for edge in edges:
                cid = getattr(edge, 'curve', None)
                if cid is not None:
                    curves[cid] = curves.get(cid, 0) + 1
            lines.append(f"Tagged curves: {len(curves)}")
            lines.append(f"Curve segment counts (up to 15): {list(curves.items())[:15]!r}")
            if count:
                edge = edges[-1]
                describe('last edge', edge, ('a', 'b', 'v0', 'v1', 'curve', 'soft'))
        except Exception as exc:
            lines.append(f"Curve inspection failed: {type(exc).__name__}: {exc}")
    lines.append('CATENARY WATCH END — no changes made.')
    return lines

def _describe_fields(owner, names):
    lines = []
    for name in names:
        try:
            value = getattr(owner, name)
        except AttributeError:
            continue
        except Exception as exc:
            lines.append(f"  {name}: unavailable ({type(exc).__name__})")
        else:
            if not callable(value):
                lines.append(f"  {name}: {_safe_repr(value)}")
    return lines


def _inspect_view(scene, viewport):
    lines = ["CAMERA"]
    lines += _describe_fields(getattr(viewport, "camera", None), (
        "projection_mode", "target", "eye", "distance", "yaw", "pitch",
        "roll", "fov_deg", "ortho_height", "up",
    ))
    lines += ["", "DOCUMENT VIEW STATE"]
    lines += _describe_fields(scene, ("camera_home", "units", "animation",
                                      "show_section_planes", "show_section_cuts"))
    for title, field, names in (
        ("SAVED VIEWS", "saved_views", ("name", "target", "distance", "yaw", "pitch",
                                        "perspective", "projection_mode", "fov_deg", "ortho_height")),
        ("SECTION PLANES", "section_planes", ("name", "symbol", "point", "normal",
                                              "active", "hidden", "uid")),
    ):
        items = getattr(scene, field, None) or ()
        lines += ["", f"{title} ({len(items)})"]
        for index, item in enumerate(islice(items, MAX_ITEMS), 1):
            lines.append(f"  [{index}] {type(item).__name__}")
            lines += _describe_fields(item, names)
        if len(items) > MAX_ITEMS:
            lines.append(f"  … {len(items) - MAX_ITEMS} more")
    return "\n".join(lines)


def _inspect_placements(scene):
    from PySide6.QtGui import QVector3D

    lines = ["PLACEMENTS", "Matrices are row-major. Coordinates are in metres."]
    mesh_labels = {}
    count = 0

    def walk(groups, parent_matrix=None, path=(), ancestors=frozenset()):
        for index, group in enumerate(groups, 1):
            current = (*path, index)
            cycle = id(group) in ancestors
            local = getattr(group, "xform", None)
            world = local if parent_matrix is None else (
                parent_matrix if local is None else parent_matrix * local
            )
            yield current, group, local, world, cycle
            if cycle or len(current) >= MAX_DEPTH + 8:
                continue
            yield from walk(getattr(group, "children", ()) or (), world,
                            current, ancestors | {id(group)})

    for path, group, local, world, cycle in islice(walk(getattr(scene, "groups", ())), MAX_ITEMS + 1):
        count += 1
        if count > MAX_ITEMS:
            lines.append(f"  … showing the first {MAX_ITEMS} placements")
            break
        name = getattr(group, "name", "")
        lines.append(f"\n{'.'.join(map(str, path))}  {name!r}")
        if cycle:
            lines.append("  Cycle detected")
            continue
        if len(path) >= MAX_DEPTH + 8 and getattr(group, "children", ()):
            lines.append("  Deeper children omitted")
        lines += _describe_fields(group, ("uid", "component", "layer", "hidden", "locked", "billboard", "ifc", "material"))
        mesh = getattr(group, "mesh", None)
        if mesh is not None:
            label = mesh_labels.setdefault(id(mesh), len(mesh_labels) + 1)
            counts = ", ".join(f"{len(getattr(mesh, key, ()))} {key}"
                               for key in ("vertices", "edges", "faces"))
            lines.append(f"  Mesh {label}: {counts} (matching labels share a mesh)")
        if local is not None:
            lines.append(f"  Local matrix: {tuple(local.row(i).toTuple() for i in range(4))}")
        if world is not None:
            origin = world.map(QVector3D())
            basis = [world.map(axis) - origin for axis in
                     (QVector3D(1, 0, 0), QVector3D(0, 1, 0), QVector3D(0, 0, 1))]
            lines.append(f"  World origin: {origin.toTuple()}")
            lines.append(f"  World axes: {[axis.toTuple() for axis in basis]}")
            lines.append(f"  World axis lengths: {[axis.length() for axis in basis]}")
            lines.append(f"  World determinant: {world.determinant():.6g}")
    if count == 0:
        lines.append("  No groups or components.")
    selection = getattr(scene, "selection", ()) or ()
    lines += ["", f"SELECTION ({len(selection)})"]
    lines.extend(f"  {name}: {total}" for name, total in
                 sorted(Counter(type(item).__name__ for item in selection).items()))
    for item in islice(selection, MAX_ITEMS):
        lines.append(f"  {type(item).__name__}")
        lines += _describe_fields(item, ("name", "layer", "position", "a", "b", "curve"))
    return "\n".join(lines)


def _inspect_api(scene, viewport):
    from importlib import import_module

    lines = ["EXTENSION API", "Signatures are inspected without calling the methods."]
    for module_name, class_name, members in (
        ("views.extension_api", "ExtensionApp", ("scene", "viewport", "add_menu",
            "add_menu_action", "add_panel", "add_overlay", "add_snap_provider",
            "on_document_changed", "document_data", "set_document_data")),
        ("core.scene", "Scene", ("loose_mesh", "selection", "set_active_section",
            "visible_groups", "iter_groups")),
        ("core.group", "Group", ("mesh", "xform", "component", "children", "is_component")),
        ("core.mesh", "Mesh", ("add_face", "add_edge", "vertex_at", "find_edge", "tag_curve")),
        ("core.layers", "Layer", ("name", "visible", "color", "opacity")),
        ("core.saved_views", "SavedView", ("capture", "apply", "to_dict", "from_dict")),
        ("core.section", "SectionPlane", ("point", "normal", "side", "to_dict", "from_dict")),
        ("core.camera", "OrbitCamera", ("projection_mode", "position", "target", "set_projection")),
    ):
        lines.append(f"\n{module_name}.{class_name}")
        try:
            module = import_module(module_name)
            cls = getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            lines.append(f"  Unavailable: {exc}")
            continue
        if hasattr(module, "API_VERSION"):
            lines.append(f"  API version: {module.API_VERSION}")
        for name in ("__init__", *members):
            member = inspect.getattr_static(cls, name, None)
            if isinstance(member, (staticmethod, classmethod)):
                member = member.__func__
            if callable(member):
                try:
                    signature = str(inspect.signature(member))
                except (TypeError, ValueError):
                    signature = " (signature unavailable)"
                lines.append(f"  {name}{signature}")
            elif member is not None or name in getattr(cls, "__dataclass_fields__", {}):
                lines.append(f"  {name}: attribute")
            else:
                lines.append(f"  {name}: unavailable on class")
    lines.extend(_inspect_catenary_compatibility(scene, viewport))
    plugin_data = getattr(scene, "plugin_data", None)
    if isinstance(plugin_data, dict):
        lines += ["", f"DOCUMENT EXTENSION DATA ({len(plugin_data)} keys)"]
        for key in islice(plugin_data, MAX_ITEMS):
            lines.append(f"  {_safe_repr(key)}: {type(plugin_data[key]).__name__}")
        if len(plugin_data) > MAX_ITEMS:
            lines.append(f"  … {len(plugin_data) - MAX_ITEMS} more")
    return "\n".join(lines)


class InspectorDialog(QDialog):
    def __init__(self, viewport, parent=None):
        super().__init__(parent or viewport.window())
        self._viewport = viewport
        self.setWindowTitle("BlackFox 3D Inspector v1.2.0")
        self.resize(900, 720)

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        self.sections = {}
        for title in ("Scene", "Placements & selection", "Camera & views", "Developer APIs"):
            output = QPlainTextEdit()
            output.setReadOnly(True)
            output.setLineWrapMode(QPlainTextEdit.NoWrap)
            self.tabs.addTab(output, title)
            self.sections[title] = output
        layout.addWidget(self.tabs)

        buttons = QHBoxLayout()
        for label, handler in (
            ("Refresh", self.refresh), ("Copy report", self.copy_report),
            ("Export to TXT", self.export_report), ("Close", self.close),
        ):
            button = QPushButton(label)
            button.clicked.connect(handler)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self):
        scene = getattr(self._viewport, "scene", None)
        if scene is None:
            for output in self.sections.values():
                output.setPlainText("No active IngeTrazo document.")
            return
        reports = (
            lambda: _collect_report(scene),
            lambda: _inspect_placements(scene),
            lambda: _inspect_view(scene, self._viewport),
            lambda: _inspect_api(scene, self._viewport),
        )
        for output, report in zip(self.sections.values(), reports):
            try:
                output.setPlainText(report())
            except Exception as exc:
                output.setPlainText(f"Section unavailable: {type(exc).__name__}: {exc}")

    def report_text(self):
        return "\n\n".join(f"=== {title} ===\n{output.toPlainText()}"
                           for title, output in self.sections.items()) + "\n"

    def copy_report(self):
        QApplication.clipboard().setText(self.report_text())

    def export_report(self):
        dialog = QFileDialog(self, "Export inspector report to TXT")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setNameFilter("Text files (*.txt)")
        dialog.setDefaultSuffix("txt")
        dialog.selectFile("BlackFox_3D_Inspector_Report.txt")
        if dialog.exec() == QDialog.Accepted:
            paths = dialog.selectedFiles()
            if not paths:
                return
            try:
                Path(paths[0]).write_text(self.report_text(), encoding="utf-8")
            except OSError as exc:
                QMessageBox.warning(self, "Could not export inspector report", str(exc))


class IngeTrazo3DInspector:
    name = "3D Inspector v1.2.0"
    shortcut = None
    description = (
        "Read-only inspection of scene geometry, placements, views, textures, and extension APIs."
    )
    uses_snap = False

    def on_activate(self, viewport):
        if viewport is not None:
            InspectorDialog(viewport, parent=viewport.window()).exec()

    def on_deactivate(self, viewport):
        pass


def _show_about(parent):
    """About dialog matching the BlackFox DXF Exporter and Catenary style."""
    from PySide6.QtCore import Qt

    dialog = QDialog(parent)
    dialog.setWindowTitle("About BlackFox 3D Inspector")
    dialog.setMinimumWidth(460)
    layout = QVBoxLayout(dialog)
    label = QLabel(dialog)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setOpenExternalLinks(True)
    label.setText("""
        <h2>BlackFox 3D Inspector</h2>
        <p><b>Version 1.2.0</b> &middot; November 2026</p>
        <p>A free and open-source, read-only diagnostic extension for IngeTrazo.</p>
        <p>Inspect geometry, groups, components, layers, materials, guides,
        annotations, survey points and face-level texture mapping. Includes Catenary API Watch for
        monitoring the interfaces used by BlackFox Catenary.</p>
        <p>Refresh, copy, or explicitly export a report to TXT without modifying the model.</p>
        <p><b>Project creator:</b> David Mavrov<br>
        <b>Development assistance:</b> ChatGPT (OpenAI)</p>
        <p><b>License:</b> GNU General Public License v3.0 or later
        (GPL-3.0-or-later).<br>
        You may use, study, modify, share and sell this software under
        the terms of the license. Distributed derivative versions must
        respect the applicable GPL requirements.</p>
        <p><b>Third-party software:</b><br>
        IngeTrazo &mdash; GPL-3.0-or-later<br>
        PySide6 / Qt for Python &mdash; LGPLv3, GPLv3 or commercial licensing</p>
        <p><b>Source code and license:</b> <a href="https://github.com/davidsmavrov-debug/BlackFox-CAD">BlackFox-CAD on GitHub</a><br>
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
    """Register only the submenu; avoid duplicate automatic Tool registration."""
    sub = app.add_menu("3D Inspector")
    sub.addAction("3D Inspector", lambda: IngeTrazo3DInspector().on_activate(app.viewport))
    sub.addSeparator()
    sub.addAction("About…", lambda: _show_about(app.window))
