# BlackFox SKP Exporter v1.0.0

![BlackFox SKP Exporter](blackfox_skp_exporter.png)

Free and open-source IngeTrazo extension for opening, importing, and exporting SketchUp SKP models.

## Install

Download [BlackFox_SKP_EXPORTER_1.0.0.py](https://github.com/davidsmavrov-debug/BlackFox-CAD/releases/download/skp-exporter-v1.0.0/BlackFox_SKP_EXPORTER_1.0.0.py). Place it directly in IngeTrazo's **Extensions > Open plugins folder**, then restart IngeTrazo. If you installed the earlier ZIP, move its `BlackFoxSKP` package out of the plugins folder before installing the standalone file.

## SKP converter

Choose **Open SKP**, **Import SKP**, **Export SKP**, or **Export Selected** from **Extensions > SKP Exporter**. If the converter is missing, BlackFox asks permission to download the matching [converter v1.0.0](https://github.com/davidsmavrov-debug/blackfox-skp-exporter/releases/tag/v1.0.0). The prompt shows the platform, version, download size, and destination. BlackFox verifies the executable's size, SHA-256, and architecture before installation and reuses the verified copy.

On Windows the executable goes in `%APPDATA%\ingetrazo\plugins\BlackFoxSKP\BlackFoxSKP.exe`. Canceling leaves the converter uninstalled and lets you retry on the next SKP command.

## Credits and licenses

- Project creator: David Mavrov
- Development assistance: ChatGPT (OpenAI)
- [skpwright](https://github.com/hew3d/skpwright): Kurt Granroth and contributors, GPL-3.0-only
- BlackFox SKP Exporter: GPL-3.0-only
- Embedded truststore Windows backend: MIT

## Verification status

The standalone extension's first-run download and SKP command prompts were verified on Windows. Native converter smoke tests passed on Windows, Linux, and macOS on x86-64 and ARM64. The file-dialog tests also passed on all three operating systems.

The earlier ZIP is retained as a release asset. Use the standalone Python file for a new installation.
