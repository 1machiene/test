from __future__ import annotations

import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

import ezdxf
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import soundvision_core as core
from windows_app import convert_file


def encrypt_project(clear: bytes) -> bytes:
    _, key, iv = core.CRYPTO_CANDIDATES[0]
    padder = padding.PKCS7(128).padder()
    padded = padder.update(clear) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def make_surface_xml() -> bytes:
    # Minimal structure based on Soundvision's encrypted XML containers.
    root = ET.Element("project")
    room = ET.SubElement(root, "room_data")
    surfaces = ET.SubElement(room, "surfaces")
    s = ET.SubElement(surfaces, "surface")
    ET.SubElement(s, "name").text = "Windows Self Test"
    pts = ET.SubElement(s, "points")
    for i, xyz in enumerate(((0,0,0),(10,0,0),(10,5,0),(0,5,0)), 1):
        p = ET.SubElement(pts, "point")
        ET.SubElement(p, "name").text = f"Point {i}"
        ET.SubElement(p, "position").text = f"{xyz[0]} {xyz[1]} {xyz[2]}"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def test_real_fixture(fixture: Path) -> None:
    clear, _ = core.decrypt_soundvision(fixture)
    surfaces, counts = core.extract_geometry(clear)
    assert surfaces, "fixture produced no geometry"
    core.validate_geometry(surfaces)
    assert sum(counts.values()) >= 1


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        p = td / "selftest.xmlp"
        p.write_bytes(encrypt_project(make_surface_xml()))

        # Crypto round trip must yield XML.
        clear, _ = core.decrypt_soundvision(p)
        assert clear.lstrip().startswith(b"<?xml")

        # Full converter path must create a readable DXF.
        out, count, _ = convert_file(p, (True, True, False))
        assert count >= 1
        assert out.exists() and out.stat().st_size > 0
        doc = ezdxf.readfile(out)
        entities = list(doc.modelspace())
        assert entities, "DXF contains no entities"

        # If CI fixtures are present, exercise real Soundvision files too.
        fixture_dir = Path(__file__).with_name("fixtures")
        if fixture_dir.exists():
            fixtures = list(fixture_dir.glob("*.xmlp")) + list(fixture_dir.glob("*.xmls"))
            for fixture in fixtures:
                test_real_fixture(fixture)
            print(f"Real fixtures tested: {len(fixtures)}")

    print("WINDOWS SELF-TEST: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
