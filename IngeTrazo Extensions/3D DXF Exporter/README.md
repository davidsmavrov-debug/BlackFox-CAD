# BlackFox CAD Exporter v1.0.1

![BlackFox CAD Exporter](blackfox_cad_exporter.png)

Free and open-source IngeTrazo extension for importing CAD and mesh files and exporting 3D geometry to DXF and DWG.

## Install

Place `BlackFox_CAD_Exporter_v1_0_1.py` in IngeTrazo's **Extensions > Open plugins folder**, then restart IngeTrazo. The extension requires `ezdxf` in IngeTrazo's Python environment. The image is for the extension's GitHub/catalog listing; it does not need to be installed alongside the Python file.

## Import and export

Use **3D CAD Exporter > Import 3D CAD** to import DXF, DWG, OBJ, STL, COLLADA,
FBX, glTF or GLB into the current drawing. Confirm the suggested units in
IngeTrazo's standard import dialog. Undo removes the import in one step.

Use IngeTrazo's native **Point** tool to place guide points by clicking
or by entering `x;y;z`. The exporter writes model guide points as DXF
`POINT` entities. CAD points in model space import as native guide points.

Repeated and nested CAD blocks import as native components with shared
geometry and separate placements. The DXF/DWG exporter retains the hierarchy
for those imported components. IngeTrazo segments analytic curves into
selectable contours and skips some annotations and objects. Model-space CAD
points import as guide points. Points within block definitions and paper
space stay in the standalone converter workflow. IngeTrazo reports
large-coordinate recentering in the import status.

## Converter

The first CAD import or DWG export prompts before downloading the native
BlackFox converter. The prompt shows the asset source, platform and size.
The installer checks the release metadata, archive size and SHA-256, and
the executable architecture. The converter and its notices are retained
in a versioned cache outside the plugins folder:

```text
<IngeTrazo user-data>/extension-data/blackfox_cad_exporter/bin/<version>/<target>/
```

Replacing the Python extension leaves this cache intact. A cached
release archive can restore its executable offline. A verified v1.0.0
archive in the old plugin location can migrate for legacy DWG export.

CAD import requires the bidirectional converter. The local development
source keeps the published v1.0.0 DWG export fallback until a release
build embeds metadata for the new platform archives.

## Credits and licenses

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- Additional ideas, including suggesting AcadRust: Gemini (Google)
- AcadRust: Hakan AK, Mozilla Public License 2.0 (MPL-2.0); see the license and notices bundled with the converter
- BlackFox CAD Exporter: GPL-3.0-or-later
- ezdxf: MIT; PySide6 / Qt for Python: LGPLv3, GPLv3 or commercial licensing

## Publishing the image

For a GitHub repository README, keep `blackfox_cad_exporter.png` next to this README so the Markdown image reference resolves. The IngeTrazo extension catalog may require its own metadata or submission process; bundling the PNG does not automatically update that external listing.

## Verification status

On Windows x86-64 with IngeTrazo 0.6.3, both the Python and Rust engines
passed the native Point workflow, DXF and DWG point round-trips, repeated
imports, mirrored and tilted nested components, mesh imports, confirmed
unit conversion, project saving and reopening, and import undo/redo. Tests also covered initial consent, persistent reuse,
cache repair, version selection, and migration. The new converter
download was tested with local test transport. The published v1.0.0
download was tested over HTTPS.

To reproduce the local integration check with both engines, run
`python tests/ingetrazo_integration.py <IngeTrazo-source> <converter>`
once with `INGETRAZO_RUST=0` and once with `INGETRAZO_RUST=1`.
The tests use an isolated profile and an offscreen window. Add
`--mesh-fixtures <converter-source>/tests/roundtrip.py` to exercise all
six mesh input formats.
