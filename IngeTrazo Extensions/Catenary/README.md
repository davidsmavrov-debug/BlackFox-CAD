BlackFox Catenary

<img width="1200" height="750" alt="blackfox_catenary" src="https://github.com/user-attachments/assets/09b064f1-557d-4706-9ae6-e7885435a20a" />

Version 1.0.0 | Free & Open Source | MIT License

A free, open-source extension for IngeTrazo that creates mathematically calculated catenary curves between two specified endpoints.

Designed for architects, engineers, designers, and anyone working with suspended cables, tensile structures, and gravity-driven geometry.

Features

Interactive Catenary — select two endpoints directly in the 3D viewport and enter the desired cable length.

Catenary (X, Y, Z) — enter precise 3D endpoint coordinates and cable length.

Accurate mathematical solver — calculates a gravity-aligned catenary accounting for different endpoint elevations.

Adjustable resolution — choose between 8 and 512 segments in coordinate-entry mode.

Native IngeTrazo geometry — generates connected edges grouped into one selectable curve.

Undo support — integrates with IngeTrazo's document history.

Input validation — checks endpoint positions and cable length before generating geometry.

Installation

Download BlackFox_Catenary_v1_0_0.py from the repository or GitHub Releases.

Launch IngeTrazo.

Navigate to Extensions → Open plugins folder.

Copy the downloaded Python file into the plugins folder.

Restart IngeTrazo.

No additional Python packages are required beyond the dependencies supplied with IngeTrazo.

Usage

Interactive Catenary

Navigate to Extensions → Catenary → Catenary.

Click the first endpoint in the viewport.

Click the second endpoint.

Enter the desired cable length.

Confirm to generate the catenary.

Coordinate-Based Catenary

Navigate to Extensions → Catenary → Catenary (X, Y, Z).

Enter the X, Y, Z coordinates of both endpoints.

Enter the desired cable length.

Select the number of segments.

Click OK to generate the curve.

All coordinates and lengths use the current IngeTrazo model units.

Mathematical Method

The extension calculates a classical catenary under uniform gravitational loading per unit cable length.

The solver accounts for the horizontal separation, vertical elevation difference, and specified cable length.

The resulting geometry is discretized into straight segments and inserted as native IngeTrazo geometry.

Limitations: The extension is a geometric form-generation tool, not a structural analysis package. It does not calculate cable tension, material stresses, wind loads, or support reactions.

The endpoints must have different horizontal (XY) positions, and the specified cable length must be at least the straight-line distance between them.

Compatibility

Developed for IngeTrazo v0.5.11.

Compatibility with other versions has not yet been verified.

License

Copyright © 2026 David Mavrov.

Licensed under the MIT License.

You may use, copy, modify, distribute, and sell this software subject to the license terms, including retaining the required copyright and license notices.

This is an independent community extension and is not an official IngeTrazo product.

The software is provided without warranty.

Credits

Project creator: David Mavrov
Development assistance: ChatGPT (OpenAI)

Source Code

https://github.com/davidsmavrov-debug/BlackFox-CAD

Support the Project

BlackFox develops accessible CAD and engineering tools for the community.

If you find this extension useful and would like to support further development:

Support us at: https://ko-fi.com/davidmavrov
