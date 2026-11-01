# BlackFox CAD Exporter

Version 1.0.0

A free and open-source DXF/DWG export extension for IngeTrazo.

## Installation

1. Download `BlackFox_CAD_Exporter_v1_0_0.py` from the release.
2. In IngeTrazo, open **Extensions > Open plugins folder**.
3. Copy the Python file into that folder.
4. Restart IngeTrazo.

The extension requires `ezdxf` in IngeTrazo's Python environment.

## Features

- Export 3D CAD geometry to DXF and DWG.
- Preserve supported layers and drawing structure.
- Export supported groups, components, and annotations.
- Select DXF/DWG output versions.
- Export the complete model or selected geometry.
- Automatically download the DWG converter when needed.
- Verify downloaded and cached converter binaries using SHA-256.

## DWG converter

DWG export uses BlackFox DWG Converter v1.0.1.

On the first DWG export, the extension downloads the appropriate executable
from the project's GitHub release and installs it in a versioned `BlackFoxDWG`
directory beside the extension.

An internet connection is required for the initial download. Subsequent
exports can use the verified local executable.

Converter builds are available for Windows x64, Linux x64/ARM64,
and macOS x64/ARM64.

## Compatibility

End-to-end testing has been completed on Windows with:

- IngeTrazo 0.5.10.1
- IngeTrazo 0.5.11

Linux and macOS converter builds are available, but complete IngeTrazo
integration has not yet been verified on those platforms.

## Limitations

- Export support depends on the geometry and features implemented in IngeTrazo.
- Some IngeTrazo functionality is still under development.
- Layout/paper-space export is not included in this release.
- Not all CAD entity types or drawing properties are supported.

## License

GPL-3.0-or-later. See the repository's LICENSE file.

## Source code

https://github.com/davidsmavrov-debug/BlackFox-CAD

## Third-party acknowledgments

DWG conversion is implemented using [ACadSharp](https://github.com/DomCR/ACadSharp),
an open-source .NET library developed by Albert Domenech.

BlackFox DWG Converter uses ACadSharp version 3.8.35.

ACadSharp is licensed under the MIT License. Its original copyright
and license notice are available in the upstream repository:
https://github.com/DomCR/ACadSharp/blob/master/LICENSE

BlackFox provides the IngeTrazo integration, DXF export functionality,
conversion workflow, and automatic converter installation.
