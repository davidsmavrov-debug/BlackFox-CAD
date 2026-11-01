using ACadSharp;
using ACadSharp.IO;

if (args.Length != 3)
{
    Console.WriteLine("Usage: BlackFoxDWG <input.dxf> <output.dwg> <2010|2013|2018>");
    return 1;
}

string input = args[0];
string output = args[1];

if (!File.Exists(input))
{
    Console.Error.WriteLine("Input DXF not found.");
    return 2;
}

ACadVersion version = args[2] switch
{
    "2010" => ACadVersion.AC1024,
    "2013" => ACadVersion.AC1027,
    "2018" => ACadVersion.AC1032,
    _ => throw new ArgumentException("Supported DWG versions: 2010, 2013, 2018")
};

try
{
    Console.WriteLine($"Reading {input}");
    CadDocument drawing = DxfReader.Read(input);

    // Repair a missing current dimension-style reference.
    // Preserve the original style whenever it resolves correctly.
    string requestedStyle = drawing.Header.CurrentDimensionStyleName;

    try
    {
        _ = drawing.Header.CurrentDimensionStyle;
    }
    catch (KeyNotFoundException)
    {
        Console.WriteLine(
            $"Warning: Dimension style '{requestedStyle}' is missing. Trying Standard.");

        drawing.Header.CurrentDimensionStyleName = "Standard";

        // Verify that Standard actually exists.
        _ = drawing.Header.CurrentDimensionStyle;
    }

    drawing.Header.Version = version;

    Console.WriteLine($"Writing DWG {args[2]}");
    DwgWriter.Write(output, drawing);

    Console.WriteLine($"SUCCESS: {output}");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Conversion failed: {ex}");
    return 3;
}
