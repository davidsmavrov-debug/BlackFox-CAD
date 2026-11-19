# BlackFox SKP Exporter v1.0.0

Free and open-source IngeTrazo extension for opening, importing, and exporting SketchUp SKP files.

## Install

Download [BlackFoxSKP_1.0.0.zip](https://github.com/davidsmavrov-debug/BlackFox-CAD/releases/download/skp-exporter-v1.0.0/BlackFoxSKP_1.0.0.zip). Open IngeTrazo's **Extensions > Open plugins folder**, extract the `BlackFoxSKP` folder there, and restart IngeTrazo. On Windows the folder is `%APPDATA%\ingetrazo\plugins\BlackFoxSKP`.

Open, import, or export a model from **Extensions > SKP Exporter**.

## SKP converter

The first SKP operation asks before downloading the matching [BlackFox converter v1.0.0](https://github.com/davidsmavrov-debug/blackfox-skp-exporter/releases/tag/v1.0.0). The prompt shows the download URL, platform, size, and destination. BlackFox verifies the executable's size, SHA-256, and architecture before installing it. Later operations reuse the verified copy.

## Credits and licenses

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- [skpwright](https://github.com/hew3d/skpwright): Kurt Granroth and contributors, GPL-3.0-only
- BlackFox SKP Exporter: GPL-3.0-only
- Bundled truststore: MIT

## Verification status

The extension and first-run download were tested on Windows. Native converter smoke tests passed on Windows, Linux, and macOS, on x86-64 and ARM64. The file-dialog tests also passed on all three operating systems.

Some nested SKP files use an import path that preserves hierarchy and geometry with limited support for materials, annotations, sections, and cameras.
