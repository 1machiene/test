from __future__ import annotations

import sys
import traceback
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import soundvision_core as core

from cryptography.hazmat.primitives import padding as _test_padding
from cryptography.hazmat.primitives.ciphers import Cipher as _TestCipher, algorithms as _test_algorithms, modes as _test_modes

APP_NAME = "Soundvision to DXF converter"


def choose_export_options(parent: tk.Tk) -> tuple[bool, bool, bool] | None:
    result: dict[str, tuple[bool, bool, bool] | None] = {"value": None}

    win = tk.Toplevel(parent)
    win.title(APP_NAME)
    win.resizable(False, False)
    win.transient(parent)
    win.grab_set()

    faces = tk.BooleanVar(value=True)
    outlines = tk.BooleanVar(value=True)
    points = tk.BooleanVar(value=False)

    frame = ttk.Frame(win, padding=18)
    frame.grid(row=0, column=0, sticky="nsew")
    ttk.Label(frame, text="What should be exported to the DXF?").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
    ttk.Checkbutton(frame, text="3D Faces (3DFACE)", variable=faces).grid(row=1, column=0, columnspan=2, sticky="w")
    ttk.Checkbutton(frame, text="3D Outlines (Polylines)", variable=outlines).grid(row=2, column=0, columnspan=2, sticky="w")
    ttk.Checkbutton(frame, text="Vertices", variable=points).grid(row=3, column=0, columnspan=2, sticky="w")

    def ok() -> None:
        if not any((faces.get(), outlines.get(), points.get())):
            messagebox.showwarning(APP_NAME, "Select at least one export option.", parent=win)
            return
        result["value"] = (faces.get(), outlines.get(), points.get())
        win.destroy()

    def cancel() -> None:
        result["value"] = None
        win.destroy()

    ttk.Button(frame, text="Cancel", command=cancel).grid(row=4, column=0, sticky="e", padx=(0, 8), pady=(14, 0))
    ttk.Button(frame, text="Export", command=ok).grid(row=4, column=1, sticky="e", pady=(14, 0))
    win.protocol("WM_DELETE_WINDOW", cancel)

    win.update_idletasks()
    x = parent.winfo_screenwidth() // 2 - win.winfo_reqwidth() // 2
    y = parent.winfo_screenheight() // 2 - win.winfo_reqheight() // 2
    win.geometry(f"+{x}+{y}")
    parent.wait_window(win)
    return result["value"]


def convert_file(input_path: Path, options: tuple[bool, bool, bool]) -> tuple[Path, int, dict[str, int]]:
    export_faces, export_outlines, export_points = options
    output_path = input_path.with_name(input_path.stem + "_converted.dxf")

    clear_xml, _crypto_label = core.decrypt_soundvision(input_path)
    surfaces, source_counts = core.extract_geometry(clear_xml)
    if not surfaces:
        raise RuntimeError("No supported room geometry found.")
    core.validate_geometry(surfaces)
    count = core.write_dxf(
        surfaces,
        output_path,
        export_faces,
        export_outlines,
        export_points,
    )
    return output_path, count, source_counts



def run_bundled_self_test() -> int:
    """Headless end-to-end self-test intended for Windows CI and diagnostics."""
    root_xml = ET.Element("project")
    room = ET.SubElement(root_xml, "room_data")
    surfaces = ET.SubElement(room, "surfaces")
    surface = ET.SubElement(surfaces, "surface")
    ET.SubElement(surface, "name").text = "Bundled Windows Self Test"
    pts = ET.SubElement(surface, "points")
    for i, xyz in enumerate(((0, 0, 0), (10, 0, 0), (10, 5, 0), (0, 5, 0)), 1):
        point = ET.SubElement(pts, "point")
        ET.SubElement(point, "name").text = f"Point {i}"
        ET.SubElement(point, "position").text = f"{xyz[0]} {xyz[1]} {xyz[2]}"
    clear = ET.tostring(root_xml, encoding="utf-8", xml_declaration=True)

    _label, key, iv = core.CRYPTO_CANDIDATES[0]
    padder = _test_padding.PKCS7(128).padder()
    padded = padder.update(clear) + padder.finalize()
    enc = _TestCipher(_test_algorithms.AES(key), _test_modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "selftest.xmlp"
        src.write_bytes(ciphertext)
        decrypted, _ = core.decrypt_soundvision(src)
        if not decrypted.lstrip().startswith(b"<?xml"):
            raise RuntimeError("AES/XML self-test failed")
        surfaces_out, _counts = core.extract_geometry(decrypted)
        core.validate_geometry(surfaces_out)
        if not surfaces_out:
            raise RuntimeError("Geometry self-test returned no surfaces")
        dst = Path(tmp) / "selftest.dxf"
        count = core.write_dxf(surfaces_out, dst, True, True, False)
        if count < 1 or not dst.exists() or dst.stat().st_size == 0:
            raise RuntimeError("DXF write self-test failed")
        # Read the DXF back through ezdxf to catch packaging/runtime issues.
        doc = core.ezdxf.readfile(dst)
        if not list(doc.modelspace()):
            raise RuntimeError("DXF readback self-test failed")
    return 0


def main() -> int:
    root = tk.Tk()
    root.withdraw()

    while True:
        selected = filedialog.askopenfilename(
            parent=root,
            title="Select Soundvision .xmlp/.xmls file",
            filetypes=[
                ("Soundvision files", "*.xmlp *.xmls"),
                ("XMLP files", "*.xmlp"),
                ("XMLS files", "*.xmls"),
                ("All files", "*.*"),
            ],
        )
        if not selected:
            break

        options = choose_export_options(root)
        if options is None:
            continue

        input_path = Path(selected)
        try:
            output_path, count, counts = convert_file(input_path, options)
            messagebox.showinfo(
                APP_NAME,
                "Conversion completed successfully.\n\n"
                f"DXF patches: {count}\n"
                f"Native Surfaces: {counts['Surface']}\n"
                f"Balconies: {counts['Balcony']}\n"
                f"Revolutions: {counts['Revolution']}\n\n"
                f"Output:\n{output_path}",
                parent=root,
            )
        except Exception as exc:
            messagebox.showerror(
                APP_NAME,
                f"Conversion failed:\n\n{exc}",
                parent=root,
            )
            traceback.print_exc()

    root.destroy()
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        try:
            raise SystemExit(run_bundled_self_test())
        except Exception:
            traceback.print_exc()
            raise SystemExit(1)
    raise SystemExit(main())
