# SPDX-License-Identifier: MIT
"""BlackFox Catenary v1.0.0 — IngeTrazo extension.

Install this single file in Extensions > Open plugins folder, then restart.
Interactive click-pick and XYZ entry share the same catenary solver.
"""
import math

from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QDoubleSpinBox,
                               QFormLayout, QLabel, QMessageBox, QSpinBox, QVBoxLayout)
from PySide6.QtGui import QVector3D
from PySide6.QtCore import Qt
from tools.base import Tool
from core.history import SnapshotImport


def catenary_points(a, b, length, segments=64):
    a, b = tuple(map(float, a)), tuple(map(float, b))
    dx, dy, dz = (b[i] - a[i] for i in range(3))
    h = math.hypot(dx, dy)
    straight = math.hypot(h, dz)
    if h < 1e-10:
        raise ValueError('Endpoints must have different XY positions.')
    if length < straight - 1e-9:
        raise ValueError('Cable length cannot be shorter than the distance between points.')
    if length <= straight + 1e-9:
        return [tuple(a[j] + (b[j]-a[j])*i/segments for j in range(3))
                for i in range(segments+1)]
    ratio = math.sqrt((length-dz)*(length+dz))/h
    def sinhc(u):
        if u > 700: return float('inf')
        if u < 1e-5: return 1 + u*u/6 + u**4/120
        return math.sinh(u)/u
    lo, hi = 0.0, 1.0
    while sinhc(hi) < ratio: hi *= 2
    for _ in range(90):
        mid = (lo+hi)/2
        if sinhc(mid) < ratio: lo = mid
        else: hi = mid
    u = (lo+hi)/2
    k = h/(2*u)
    v = math.atanh(dz/length)
    base = math.cosh(v-u)
    points = []
    for i in range(segments+1):
        t = i/segments
        z = a[2] + k*(math.cosh((2*t-1)*u+v)-base)
        points.append((a[0]+dx*t, a[1]+dy*t, z))
    points[0], points[-1] = a, b
    return points


def xyz_dialog(viewport):
    dlg = QDialog(getattr(viewport, 'window', lambda: None)())
    dlg.setWindowTitle('BlackFox Catenary (X, Y, Z)')
    layout = QFormLayout(dlg)
    layout.addRow(QLabel('Coordinates and length use IngeTrazo model units.'))
    boxes = {}
    for key, default in [('A X', 0), ('A Y', 0), ('A Z', 0),
                         ('B X', 10), ('B Y', 0), ('B Z', 0),
                         ('Cable length', 12)]:
        spin = QDoubleSpinBox(dlg)
        spin.setDecimals(5)
        spin.setRange(-100000000, 100000000)
        if key == 'Cable length': spin.setRange(0.00001, 100000000)
        spin.setValue(default)
        layout.addRow(key, spin)
        boxes[key] = spin
    count = QSpinBox(dlg)
    count.setRange(8, 512)
    count.setValue(64)
    layout.addRow('Segments', count)
    buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=dlg)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addRow(buttons)
    while dlg.exec() == QDialog.Accepted:
        a = tuple(boxes[f'A {axis}'].value() for axis in 'XYZ')
        b = tuple(boxes[f'B {axis}'].value() for axis in 'XYZ')
        try:
            pts = catenary_points(a, b, boxes['Cable length'].value(), count.value())
            create_cable(viewport, pts)
            viewport.flash_status('BlackFox Catenary: cable created', 3000)
            break
        except Exception as exc:
            QMessageBox.warning(dlg, 'BlackFox Catenary', str(exc))



def create_cable(viewport, pts):
    def mutate(scene):
        mesh = scene.mesh
        curve_points = [QVector3D(*p) for p in pts]
        for p, q in zip(curve_points, curve_points[1:]):
            mesh.add_edge(p, q)
        if mesh.tag_curve(curve_points, closed=False) is None:
            raise RuntimeError('Could not group cable into one curve.')
    viewport.history.execute(SnapshotImport(mutate))
    viewport.notify_scene_changed()


def activate_click_catenary(app):
    """Local tool class avoids IngeTrazo auto-registering a duplicate menu item."""
    class ClickCatenaryTool(Tool):
        name = 'Catenary'
        description = 'Click two endpoints, then enter the cable length.'
        uses_snap = True

        def __init__(self):
            self.start_point = None
            self.hover_point = None

        def on_activate(self, viewport):
            self.start_point = None
            viewport.flash_status('Catenary: click first endpoint', 3000)

        def on_deactivate(self, viewport):
            self.start_point = None
            self.hover_point = None

        def on_hover(self, ctx):
            self.hover_point = QVector3D(ctx.world)
            ctx.viewport.update()

        def rubber_band_lines(self):
            if self.start_point is not None and self.hover_point is not None:
                return [(self.start_point, self.hover_point)]
            return []

        def on_click(self, ctx):
            p = QVector3D(ctx.world)
            if self.start_point is None:
                self.start_point = p
                ctx.viewport.flash_status('Catenary: click second endpoint', 3000)
                return
            a = self.start_point
            b = p
            straight = (b - a).length()
            if straight < 1e-8 or math.hypot(b.x()-a.x(), b.y()-a.y()) < 1e-8:
                QMessageBox.warning(ctx.viewport.window(), 'Catenary',
                                    'Endpoints must be different and have different XY positions.')
                return
            from PySide6.QtWidgets import QInputDialog
            length, ok = QInputDialog.getDouble(ctx.viewport.window(), 'Catenary',
                'Cable length (model units):', straight * 1.2,
                straight, 100000000, 5)
            if not ok:
                return
            try:
                pts = catenary_points(a.toTuple(), b.toTuple(), length, 64)
                create_cable(ctx.viewport, pts)
                self.start_point = None
                self.hover_point = None
                ctx.viewport.flash_status('Catenary created — click first endpoint', 2500)
            except Exception as exc:
                QMessageBox.warning(ctx.viewport.window(), 'Catenary', str(exc))
            ctx.viewport.update()

        def on_cancel(self, viewport):
            self.start_point = None
            self.hover_point = None
            from tools.select import SelectTool
            viewport.set_active_tool(SelectTool())


    app.viewport.set_active_tool(ClickCatenaryTool())

def show_about(parent):
    """About dialog styled consistently with BlackFox 3D DXF Exporter."""
    dialog = QDialog(parent)
    dialog.setWindowTitle('About BlackFox Catenary')
    dialog.setMinimumWidth(460)
    layout = QVBoxLayout(dialog)
    label = QLabel(dialog)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setOpenExternalLinks(True)
    label.setText("""
        <h2>BlackFox Catenary</h2>
        <p><b>Version 1.0.0</b> &middot; October 2026</p>
        <p>A free and open-source extension for creating gravity-aligned
        catenary curves in IngeTrazo.</p>
        <p><b>Catenary</b> &mdash; click two endpoints and enter cable length.<br>
        <b>Catenary (X, Y, Z)</b> &mdash; specify precise endpoints and cable length.</p>
        <p>Creates native welded edges grouped as one selectable curve.</p>
        <p><b>Project creator:</b> David Mavrov<br>
        <b>Development assistance:</b> ChatGPT (OpenAI)</p>
        <p><b>License:</b> MIT License.<br>
        You may use, study, modify, share and sell this software under the
        license terms, retaining the required copyright and license notices.</p>
        <p><b>Third-party software:</b><br>
        IngeTrazo &mdash; GPL-3.0-or-later<br>
        PySide6 / Qt for Python &mdash; LGPLv3, GPLv3 or commercial licensing</p>
        <p><b>Source code and license:</b> <a href="https://github.com/davidsmavrov-debug/BlackFox-CAD">BlackFox-CAD on GitHub</a><br>
        <b>Support us at:</b> <a href="https://ko-fi.com/davidmavrov">https://ko-fi.com/davidmavrov</a></p>
        <p><small>Independent community extension; not an official IngeTrazo
        product. Provided without warranty, to the extent permitted by law.
        See the MIT license text for the full terms.</small></p>
    """)
    layout.addWidget(label)
    buttons = QDialogButtonBox(QDialogButtonBox.Close, parent=dialog)
    buttons.rejected.connect(dialog.reject)
    buttons.accepted.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.exec()


def setup(app):
    from PySide6.QtWidgets import QMessageBox
    sub = app.add_menu('Catenary')
    sub.addAction('Catenary', lambda: activate_click_catenary(app))
    sub.addAction('Catenary (X, Y, Z)', lambda: xyz_dialog(app.viewport))
    sub.addSeparator()
    sub.addAction('About…', lambda: show_about(app.window))
