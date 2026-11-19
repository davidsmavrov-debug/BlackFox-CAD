<div align="center">

![BlackFox 3D Inspector logo](screenshots/blackfox_3d_inspector.png)

# BlackFox 3D Inspector

**Version 1.2.0 · Free and open-source diagnostic extension for IngeTrazo**

</div>

BlackFox 3D Inspector gives extension developers and CAD users a read-only report of the active model and the IngeTrazo APIs available at runtime. Copy or save the report to share with a collaborator or an AI assistant.

## Features

- **Scene** shows mesh topology, curves, layers, materials, texture mapping, guides, annotations, and survey data where available.
- **Placements & selection** shows nested groups and components, shared meshes, local transforms, world axes, and selected entities.
- **Camera & views** shows the current camera, saved views, scene transitions, and section planes.
- **Developer APIs** shows method signatures, available fields, document extension-data keys, and Catenary compatibility checks.

**Refresh** regenerates the report. **Copy report** copies all four tabs. **Export to TXT** opens a save dialog and writes the full report as UTF-8 after you choose a destination.

## Installation

1. [Download BlackFox_3D_Inspector_v1_2_0.py](https://github.com/davidsmavrov-debug/BlackFox-CAD/releases/download/inspector-v1.2.0/BlackFox_3D_Inspector_v1_2_0.py).
2. In IngeTrazo, choose **Extensions → Open plugins folder**.
3. Place the Python file there. Move out or disable any earlier Inspector version to avoid duplicate menus.
4. Restart IngeTrazo and choose **Extensions → 3D Inspector → 3D Inspector**.

## Verification

Tested with IngeTrazo 0.6.2.1 source and PySide6. The checks covered nested transforms, shared meshes, selection, saved views, API reporting, copy, and TXT export. Inspection left the test model untouched. Opening the inspector, refreshing, copying, and canceling the save dialog created no report files.

## Project and credits

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- Support: [Ko-fi](https://ko-fi.com/davidmavrov)

BlackFox 3D Inspector is an independent community extension.

## License

GNU General Public License v3.0 or later. See the [repository license](https://github.com/davidsmavrov-debug/BlackFox-CAD/blob/main/LICENSE).
