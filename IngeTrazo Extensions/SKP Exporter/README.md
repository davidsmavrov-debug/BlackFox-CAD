# BlackFox SKP Exporter v1.0.2

![BlackFox SKP Exporter](blackfox_skp_exporter.png)

Free and open-source IngeTrazo extension for opening, importing, and exporting SKP models.

## Install

Download [BlackFox_SKP_EXPORTER_1.0.2.py](https://github.com/davidsmavrov-debug/BlackFox-CAD/releases/download/skp-exporter-v1.0.2/BlackFox_SKP_EXPORTER_1.0.2.py). Place it directly in IngeTrazo's **Extensions > Open plugins folder**, then restart IngeTrazo. For a manual upgrade, move the previous standalone file or earlier `BlackFoxSKP` package out of the plugins folder before installing the new file.

## Nested groups and components

On IngeTrazo 0.6.3, nested SKP groups and components keep their original tree. A component's own geometry stays on its definition, so editing geometry or moving a nested part in one copy updates the matching copies. Standalone groups remain independent.

The Windows benchmark preserved 5 roots, 15 hierarchy nodes, 194 faces, and 492 edges on both the Python and Rust engines. Linked edits, save and reopen, and import undo and redo were verified on both engines.

## SKP converter

Choose **Open SKP**, **Import SKP**, **Export SKP**, or **Export Selected** from **Extensions > SKP Exporter**. If the converter is missing, BlackFox asks permission to download the matching [converter v1.0.0](https://github.com/davidsmavrov-debug/blackfox-skp-exporter/releases/tag/v1.0.0). The prompt shows the platform, version, download size, and destination. BlackFox verifies the executable's size, SHA-256, and architecture before installation and reuses the verified copy.

The converter is stored outside the replaceable plugins directory, under `<IngeTrazo user data>/extension-data/blackfox_skp_exporter/bin/<converter-version>/<target>/`. IngeTrazo uses `%APPDATA%\ingetrazo` on Windows and `$XDG_DATA_HOME/ingetrazo` on Linux and macOS (`~/.local/share/ingetrazo` by default). A compatible cached converter is verified and reused. If an old copy is still present after the update, BlackFox verifies it against the pinned manifest and installs it in the new location. If no verified copy is available, the next SKP command asks before downloading.

## Credits and licenses

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- [skpwright](https://github.com/hew3d/skpwright): Kurt Granroth and contributors, GPL-3.0-only
- BlackFox SKP Exporter: GPL-3.0-only
- Embedded truststore Windows backend: MIT

## Verification status

The standalone extension's first-run download and SKP command prompts were verified on Windows. Native converter smoke tests passed on Windows, Linux, and macOS on x86-64 and ARM64. The file-dialog tests also passed on all three operating systems.

The earlier ZIP remains available in the [v1.0.0 release](https://github.com/davidsmavrov-debug/BlackFox-CAD/releases/tag/skp-exporter-v1.0.0). Use the standalone Python file for new installations.

## Known limitations

- **SketchUp versions.** Basic geometry fixtures passed for all 21 offered versions, covering SketchUp 3–8 and 2013–2027. The 2021–2027 export options use a shared SKP container. Compatibility with each corresponding SketchUp application remains unverified.
- **Round-trip fidelity.** The nested hierarchy import path requires an empty tab for **Import SKP**. **Open SKP** can create that tab for you. The hierarchy path has limited support for materials, annotations, section settings, and cameras. BlackFox approximates texture mappings that IngeTrazo cannot represent exactly.
- **IFC classifications.** The IFC2x3 and IFC4 SKP benchmarks preserved their classification metadata through export and re-import. Other schemas, class combinations, and authoring workflows have limited verification.
- **Large models.** IngeTrazo stays responsive while the converter reads the file. Building a very large scene can still briefly pause the interface.

## Support

[Support David Mavrov on Ko-fi](https://ko-fi.com/davidmavrov)
