Soundvision to DXF converter v11 - Windows build package

Build on Windows:
1. Install Python 3.11+ from python.org and enable the Python launcher.
2. Double-click build_windows.bat.
3. The script creates an isolated virtual environment, installs dependencies,
   runs the self-test, and only then builds the standalone EXE.
4. Result: dist\Soundvision to DXF converter.exe

The final EXE does not require Python to be installed on the destination PC.

App workflow:
- Choose .xmlp or .xmls
- Select Faces / Outlines / Vertices
- Convert
- Receive a success/error dialog
- Return to the file chooser for the next conversion
- Cancel the file chooser to quit
