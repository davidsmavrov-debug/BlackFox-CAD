# BlackFox CAD Exporter v1.0.1

![BlackFox CAD Exporter](blackfox_cad_exporter.png)

Free and open-source IngeTrazo extension for exporting 3D CAD geometry to DXF and DWG.

## Install

Place `BlackFox_CAD_Exporter_v1_0_1.py` in IngeTrazo's **Extensions > Open plugins folder**, then restart IngeTrazo. The extension requires `ezdxf` in IngeTrazo's Python environment. The image is for the extension's GitHub/catalog listing; it does not need to be installed alongside the Python file.

## DWG converter

The first DWG export prompts for permission before downloading the matching platform converter from the [BlackFox Rust converter v1.0.0 release](https://github.com/davidsmavrov-debug/blackfox-dwg-rust-test/releases/tag/v1.0.0). The prompt shows the exact download URL, platform, and approximate size. The archive is SHA-256 verified and cached; subsequent DWG exports reuse the verified local executable. Cancelling does not download anything or create the DWG.

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

Python syntax compilation and isolated converter-cache, offline-recovery, and download-cancellation tests passed. Live IngeTrazo 0.6.0 UI testing, actual HTTPS downloading, DWG conversion and CAD application opening are not yet verified for this build.
