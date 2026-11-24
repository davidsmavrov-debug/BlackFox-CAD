# BlackFox CAD Exporter v1.0.2

![BlackFox CAD Exporter](blackfox_cad_exporter.png)

Free and open-source IngeTrazo extension for importing CAD and mesh files and exporting 3D geometry to DXF and DWG.

## Install

Place `BlackFox_CAD_Exporter_v1_0_2.py` in IngeTrazo's **Extensions > Open plugins folder**, then restart IngeTrazo. If you already have an older version installed, remove its Python file from the plugins folder before restarting. The image is for the extension's GitHub/catalog listing; it does not need to be installed alongside the Python file.

## Import and export

Use **3D CAD Exporter > Open 3D CAD** to open a file as a new drawing.

Use **3D CAD Exporter > Import 3D CAD** to import DXF, DWG, OBJ, STL, COLLADA,
FBX, glTF or GLB into the current drawing. Confirm the suggested units in
IngeTrazo's standard import dialog. Undo removes the import in one step.

Use IngeTrazo's native **Tools > Guide Point** to place points by clicking
or by entering `x;y;z`. The exporter writes model guide points as DXF
`POINT` entities. CAD points in model space import as native guide points.

Repeated and nested CAD blocks import as native components with shared
geometry and separate placements. New tags use the source layer's color,
visibility and lock state. The DXF/DWG exporter retains the hierarchy
for those imported components. IngeTrazo segments analytic curves into
selectable contours and skips some annotations and objects. Model-space CAD
points import as guide points. Points within block definitions and paper
space stay in the standalone converter workflow. IngeTrazo reports
large-coordinate recentering in the import status.

Both DXF and DWG offer R12, R13, R14, R2000, R2004, R2007, R2010, R2013
and R2018. Older formats can omit entities and metadata they cannot represent.

## Converter

The first Open, Import, or Export prompts before downloading
[BlackFox DWG Converter v1.2.6](https://github.com/davidsmavrov-debug/blackfox-dwg-converter/releases/tag/v1.2.6).
The extension detects the native architecture on Windows, Linux, and macOS
and selects the matching x64 or ARM64 archive. The prompt shows the source,
platform, and download size. The extension checks its embedded release
manifest, archive size and SHA-256, and executable architecture.

The converter and its notices are kept outside the plugins folder.

```text
<IngeTrazo user-data>/extension-data/blackfox_cad_exporter/bin/<version>/<target>/
```

Replacing the Python extension leaves this cache available. A verified
archive can repair its executable offline. An older converter release
uses a separate cache and the extension obtains the compatible release on demand.

## Credits and licenses

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- Additional ideas, including suggesting AcadRust: Gemini (Google)
- AcadRust: Hakan AK, Mozilla Public License 2.0 (MPL-2.0); see the license and notices bundled with the converter
- BlackFox CAD Exporter: GPL-3.0-or-later
- PySide6 / Qt for Python: LGPLv3, GPLv3 or commercial licensing

## Verification status

On Windows x64 with IngeTrazo 0.6.3, both engines passed R13 and R14 DXF and
DWG export/read-back, native geometry and annotation exchange, nested
components, mesh imports, and import undo/redo. The converter installer
was tested against GitHub over HTTPS, including declined consent, persistent
reuse, offline repair, and manifest rejection.

Run `python tests/ingetrazo_integration.py <IngeTrazo-source> <converter>`
with `INGETRAZO_RUST=0` and `INGETRAZO_RUST=1` to check both engines. Add
`--mesh-fixtures <converter-source>/tests/roundtrip.py` for the mesh formats.
Run `python tests/converter_installation.py <IngeTrazo-source>` to check
platform selection and installation using an isolated cache.
