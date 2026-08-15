#!/usr/bin/env python3
"""
Soundvision to DXF converter v11

Reads encrypted Soundvision .xmlp/.xmls files, decrypts them, extracts native
Surface, Balcony and Revolution room geometry and exports it to DXF.

Balcony and Revolution geometry (including circular Revolution mode and the
unchecked Revolution / Perpendicular length mode), both Depth/Height and
Angle/Distance profile coordinate systems, object translation and Init angle
handling are validated against Soundvision 2026.3.1 'Convert to Surfaces'
reference files.

Requirements:
    pip install ezdxf

Optional (recommended for portable decryption without an OpenSSL binary):
    pip install cryptography

macOS: if no input file is supplied, a Finder file chooser opens.
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

try:
    import ezdxf
except ImportError:
    print("ERROR: ezdxf is missing. Install it in PyCharm with: pip install ezdxf")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


# =============================================================================
# DXF EXPORT SETTINGS
# =============================================================================
# These three defaults can be changed directly:
EXPORT_FACES = True       # export actual 3D faces (3DFACE)
EXPORT_OUTLINES = True    # also export closed 3D outlines
EXPORT_POINTS = False     # export individual vertices
# =============================================================================


# -----------------------------------------------------------------------------
# Soundvision 2026.3.1 AES-256-CBC constants found in the application binary.
# Soundvision passes the ASCII bytes directly to EVP AES-256-CBC, i.e. AES uses
# the first 32 ASCII bytes of the 64-char key constant and the first 16 ASCII
# bytes of the 32-char IV constant.
#
# PROJECT is confirmed against the supplied 2026.3.1 .xmlp test files.
# GENERIC_XML is used by Soundvision's general encrypted XML reader and is kept
# as a fallback for .xmls / other encrypted XML containers.
# THIRD is another encrypted-file pair present in the binary, kept as fallback.
# -----------------------------------------------------------------------------

CRYPTO_CANDIDATES = [
    (
        "project (.xmlp)",
        b"1A30A6E3DDD33444266BE81ABFC62722",
        b"2FCC9B1869C112AF",
    ),
    (
        "generic encrypted XML (.xmls candidate)",
        b"D463D421C83764CF384D49F4647E2E37",
        b"F5EEE8E4EE2F4D11",
    ),
    (
        "alternate encrypted file",
        b"679281E5A112AB199F8297DD3F742AE4",
        b"622F5005137B24CD",
    ),
]


def choose_file_macos() -> Path | None:
    """Open a native macOS file chooser without requiring tkinter."""
    script = (
        'POSIX path of (choose file with prompt "Select Soundvision .xmlp/.xmls file" '
        'of type {"public.data"})'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return Path(result.stdout.strip())
    except FileNotFoundError:
        pass
    return None


def choose_export_options_macos() -> tuple[bool, bool, bool] | None:
    """Open the native macOS selector for faces, outlines and vertices."""
    items = [
        "3D Faces (3DFACE)",
        "3D Outlines (Polylines)",
        "Vertices",
    ]
    defaults = []
    if EXPORT_FACES:
        defaults.append(items[0])
    if EXPORT_OUTLINES:
        defaults.append(items[1])
    if EXPORT_POINTS:
        defaults.append(items[2])

    def apple_list(values):
        escaped = [v.replace('\\', '\\\\').replace('"', '\\"') for v in values]
        return "{" + ", ".join(f'"{v}"' for v in escaped) + "}"

    script = f"""
set picked to choose from list {apple_list(items)} with title "Soundvision to DXF converter" with prompt "What should be exported to the DXF?" default items {apple_list(defaults)} with multiple selections allowed and empty selection allowed
if picked is false then return "__CANCEL__"
set AppleScript's text item delimiters to "|"
return picked as text
"""

    result = subprocess.run(
        ["osascript", "-e", script],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None

    raw = result.stdout.strip()
    if raw == "__CANCEL__":
        return None

    selected = set(raw.split("|")) if raw else set()
    return (
        items[0] in selected,
        items[1] in selected,
        items[2] in selected,
    )


def get_export_options() -> tuple[bool, bool, bool]:
    if sys.platform == "darwin":
        selected = choose_export_options_macos()
        if selected is not None:
            return selected
    return EXPORT_FACES, EXPORT_OUTLINES, EXPORT_POINTS


def get_input_path() -> Path:
    if len(sys.argv) >= 2:
        return Path(sys.argv[1]).expanduser().resolve()

    if sys.platform == "darwin":
        selected = choose_file_macos()
        if selected:
            return selected.resolve()

    raw = input("Path to Soundvision file: ").strip().strip('"')
    return Path(raw).expanduser().resolve()


def openssl_path() -> str | None:
    """Return an OpenSSL executable if one is available."""
    return shutil.which("openssl")


def _try_decrypt_cryptography(
    ciphertext: bytes, key_ascii: bytes, iv_ascii: bytes
) -> bytes | None:
    """Decrypt AES-256-CBC/PKCS#7 using the Python cryptography package."""
    if not HAVE_CRYPTOGRAPHY:
        return None

    try:
        decryptor = Cipher(
            algorithms.AES(key_ascii),
            modes.CBC(iv_ascii),
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = crypto_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except Exception:
        return None


def _try_decrypt_openssl(
    ciphertext: bytes, key_ascii: bytes, iv_ascii: bytes
) -> bytes | None:
    """Decrypt AES-256-CBC/PKCS#7 with OpenSSL as a compatibility fallback."""
    exe = openssl_path()
    if not exe:
        return None

    cmd = [
        exe,
        "enc",
        "-d",
        "-aes-256-cbc",
        "-K",
        key_ascii.hex(),
        "-iv",
        iv_ascii.hex(),
    ]
    result = subprocess.run(cmd, input=ciphertext, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout


def try_decrypt(ciphertext: bytes, key_ascii: bytes, iv_ascii: bytes) -> bytes | None:
    """Decrypt a Soundvision encrypted XML container.

    Prefer in-process AES via ``cryptography``. This avoids relying on a
    particular OpenSSL installation and is also the path used by the packaged
    macOS application. OpenSSL remains as a fallback for existing Python setups.
    """
    clear = _try_decrypt_cryptography(ciphertext, key_ascii, iv_ascii)
    if clear is not None:
        return clear
    return _try_decrypt_openssl(ciphertext, key_ascii, iv_ascii)

def looks_like_xml(data: bytes) -> bool:
    stripped = data.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    return stripped.startswith(b"<?xml") or stripped.startswith(b"<")


def decrypt_soundvision(path: Path) -> tuple[bytes, str]:
    raw = path.read_bytes()

    # Allow plaintext XML as well; useful while debugging or if Soundvision ever
    # exposes an unencrypted variant.
    if looks_like_xml(raw):
        try:
            ET.fromstring(raw)
            return raw, "plaintext XML"
        except ET.ParseError:
            pass

    for label, key, iv in CRYPTO_CANDIDATES:
        clear = try_decrypt(raw, key, iv)
        if clear is None or not looks_like_xml(clear):
            continue
        try:
            ET.fromstring(clear)
        except ET.ParseError:
            continue
        return clear, label

    raise RuntimeError(
        "The file could not be decrypted as XML with any known "
        "Soundvision 2026.3.1 key."
    )


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def child_text(parent: ET.Element, name: str) -> str | None:
    for child in list(parent):
        if local_name(child.tag) == name:
            return (child.text or "").strip()
    return None


def find_child(parent: ET.Element, name: str) -> ET.Element | None:
    for child in list(parent):
        if local_name(child.tag) == name:
            return child
    return None


def parse_xyz(text: str) -> tuple[float, float, float]:
    values = text.replace(",", ".").split()
    if len(values) < 3:
        raise ValueError(f"Invalid position: {text!r}")

    # Soundvision serializes scene coordinates in its internal 3D frame.
    # The Properties panel / CAD-facing frame used by the user is:
    #   UI X = -internal X
    #   UI Y =  internal Z
    #   UI Z =  internal Y
    # This mapping is confirmed by the supplied 10 m / 20 m probe files.
    ix, iy, iz = float(values[0]), float(values[1]), float(values[2])
    return -ix, iz, iy


def parse_numbers(text: str) -> list[float]:
    return [float(v) for v in text.replace(",", ".").split()]


def parse_profile_points(element: ET.Element) -> list[tuple[float, float]]:
    """Read a Balcony/Revolution profile as normalized Depth/Height points.

    Soundvision stores native Balcony and Revolution profiles in one of two
    coordinate systems:

    * ``coordinate_system == 1``: Depth / Height. The two values in each
      ``<position>`` are already the local profile depth and height.

    * ``coordinate_system == 2``: Angle / Distance. The first value is an
      elevation angle in degrees and the second value is the distance from the
      Observer position. Soundvision converts these to Depth/Height as::

          depth  = observer_depth  + distance * cos(angle)
          height = observer_height + distance * sin(angle)

    The Angle/Distance conversion is validated against Soundvision 2026.3.1
    ``Convert to Surfaces`` reference projects for both Balcony and Revolution.
    Returning a single normalized representation keeps all downstream geometry
    generation identical for both UI coordinate modes.
    """
    points_node = find_child(element, "points")
    if points_node is None:
        return []

    try:
        coordinate_system = int(child_text(element, "coordinate_system") or "1")
    except ValueError as exc:
        raise ValueError("Invalid Soundvision profile coordinate_system value") from exc

    if coordinate_system not in (1, 2):
        raise ValueError(
            f"Unsupported Soundvision profile coordinate system: {coordinate_system}. "
            "Supported values are 1 (Depth/Height) and 2 (Angle/Distance)."
        )

    observer_depth = 0.0
    observer_height = 0.0
    if coordinate_system == 2:
        observer_values = parse_numbers(child_text(element, "observer") or "0 0")
        if observer_values:
            observer_depth = observer_values[0]
        if len(observer_values) >= 2:
            observer_height = observer_values[1]

    result: list[tuple[float, float]] = []
    for point_node in list(points_node):
        if local_name(point_node.tag) != "point":
            continue
        position = child_text(point_node, "position")
        if not position:
            continue
        values = parse_numbers(position)
        if len(values) < 2:
            continue

        if coordinate_system == 2:
            angle_deg, distance = values[0], values[1]
            angle_rad = math.radians(angle_deg)
            depth = observer_depth + distance * math.cos(angle_rad)
            height = observer_height + distance * math.sin(angle_rad)
            result.append((depth, height))
        else:
            # Depth/Height (coordinate_system == 1).
            result.append((values[0], values[1]))

    return result


def parse_init_transform(element: ET.Element) -> tuple[float, tuple[float, float, float]]:
    """Return object rotation in degrees and internal XYZ translation."""
    angle_text = child_text(element, "init_angle") or "0"
    pos_text = child_text(element, "init_position") or "0 0 0"
    angle = float(angle_text.replace(",", "."))
    p = parse_numbers(pos_text)
    while len(p) < 3:
        p.append(0.0)
    return angle, (p[0], p[1], p[2])


def apply_internal_transform(
    point: tuple[float, float, float],
    angle_deg: float,
    translation: tuple[float, float, float],
) -> tuple[float, float, float]:
    """Apply Soundvision object's local top-view rotation + translation.

    Verified against transformed Soundvision 2026.3.1 Balcony/Revolution
    reference projects, including non-zero Init X/Y/Z, 30 degree Init angle,
    multiple profile segments and different discretization values.
    """
    x, y, z = point
    a = math.radians(angle_deg)
    ca, sa = math.cos(a), math.sin(a)
    # Standard right-handed rotation around internal +Y (vertical).
    xr = x * ca + z * sa
    zr = -x * sa + z * ca
    tx, ty, tz = translation
    return xr + tx, y + ty, zr + tz


def internal_to_ui(point: tuple[float, float, float]) -> tuple[float, float, float]:
    """Convert Soundvision internal XYZ to the CAD/UI XYZ frame."""
    ix, iy, iz = point
    return -ix, iz, iy


def make_patch(
    name: str,
    internal_points: list[tuple[float, float, float]],
    angle_deg: float,
    translation: tuple[float, float, float],
    source_type: str,
) -> dict:
    transformed = [
        internal_to_ui(apply_internal_transform(p, angle_deg, translation))
        for p in internal_points
    ]
    return {
        "name": name,
        "points": transformed,
        "point_names": [f"Point {i}" for i in range(1, len(transformed) + 1)],
        "source_type": source_type,
    }


def extract_explicit_surfaces(root: ET.Element) -> list[dict]:
    """Extract ordinary Soundvision <surface> objects already stored as 3D points."""
    surfaces: list[dict] = []

    for element in root.iter():
        if local_name(element.tag) != "surface":
            continue

        points_node = find_child(element, "points")
        if points_node is None:
            # Ignore the parameter-only <psurfaces><surface> entries used by
            # native Balcony/Revolution objects.
            continue

        name = child_text(element, "name") or f"Surface {len(surfaces) + 1}"
        points: list[tuple[float, float, float]] = []
        point_names: list[str] = []

        for point_node in list(points_node):
            if local_name(point_node.tag) != "point":
                continue
            position = child_text(point_node, "position")
            if not position:
                continue
            try:
                xyz = parse_xyz(position)
            except ValueError:
                continue
            points.append(xyz)
            point_names.append(child_text(point_node, "name") or f"Point {len(points)}")

        if len(points) >= 3:
            surfaces.append(
                {
                    "name": name,
                    "points": points,
                    "point_names": point_names,
                    "source_type": "Surface",
                }
            )

    return surfaces


def generate_balcony(element: ET.Element) -> list[dict]:
    """Reconstruct a native Soundvision Balcony as the same quad patches
    produced by Soundvision's 'Convert to Surfaces' command.
    """
    name = child_text(element, "name") or "Balcony"
    profile = parse_profile_points(element)
    if len(profile) < 2:
        return []

    try:
        front_width = float((child_text(element, "front_width") or "0").replace(",", "."))
        rear_width = float((child_text(element, "rear_width") or "0").replace(",", "."))
        discretization = max(1, int(child_text(element, "discretization") or "1"))
    except ValueError:
        return []

    d0 = profile[0][0]
    d1 = profile[-1][0]
    depth_span = d1 - d0
    width_delta = rear_width - front_width
    eps = 1e-9

    # Soundvision has one important special case: a Balcony with
    # Discretization = 1 is converted to a single flat trapezoid, even when
    # front and rear widths differ. Only discretization values greater than 1
    # use the concentric-arc construction.
    curved = (
        discretization > 1
        and abs(width_delta) > eps
        and abs(depth_span) > eps
    )
    if curved:
        # Concentric-arc geometry. For two chord widths Wf/Wr separated by
        # radial distance D: sin(a/2)=(Wr-Wf)/(2D), R0=Wf/(2*sin(a/2)).
        sin_half = width_delta / (2.0 * depth_span)
        if abs(sin_half) > 1.0 + 1e-7:
            return []
        sin_half = max(-1.0, min(1.0, sin_half))
        total_angle = 2.0 * math.asin(sin_half)
        if abs(sin_half) < eps:
            curved = False
        else:
            base_radius = front_width / (2.0 * sin_half)

    angle_deg, translation = parse_init_transform(element)
    patches: list[dict] = []

    def local_point(depth: float, height: float, j: int) -> tuple[float, float, float]:
        t = j / discretization
        if curved:
            theta = -total_angle / 2.0 + total_angle * t
            radius = base_radius + (depth - d0)
            x = radius * math.sin(theta)
            z = radius * math.cos(theta) - base_radius
        else:
            # Parallel front/rear widths are the infinite-radius limit: a flat
            # strip subdivided across its width. Width is linearly interpolated
            # along profile depth so this also handles intermediate profile points.
            if abs(depth_span) > eps:
                u = (depth - d0) / depth_span
            else:
                u = 0.0
            width = front_width + (rear_width - front_width) * u
            x = -width / 2.0 + width * t
            z = depth - d0
        return x, height, z

    for profile_index in range(len(profile) - 1):
        da, ha = profile[profile_index]
        db, hb = profile[profile_index + 1]
        for segment in range(discretization):
            internal_points = [
                local_point(da, ha, segment),
                local_point(db, hb, segment),
                local_point(db, hb, segment + 1),
                local_point(da, ha, segment + 1),
            ]
            patches.append(
                make_patch(
                    f"{name} ({profile_index + 1}, {segment + 1})",
                    internal_points,
                    angle_deg,
                    translation,
                    "Balcony",
                )
            )

    return patches


def generate_revolution(element: ET.Element) -> list[dict]:
    """Reconstruct a native Soundvision Revolution as surface patches.

    Both Soundvision construction modes are supported:

    * Revolution enabled (circular_cone == 1):
      Each profile depth is used directly as a circular radius.

    * Revolution disabled (circular_cone == 0):
      Soundvision uses ``Perpendicular length`` to scale the perpendicular
      semi-axis of the outermost profile point. Intermediate profile depths
      are scaled proportionally, producing the same elliptical patches as
      Soundvision's ``Convert to Surfaces`` command.

    Both modes, including object translation, Init angle, multiple profile
    segments and discretization, are validated against Soundvision 2026.3.1
    reference projects supplied by the user.
    """
    name = child_text(element, "name") or "Revolution"
    profile = parse_profile_points(element)
    if len(profile) < 2:
        return []

    try:
        circular = int(child_text(element, "circular_cone") or "0")
        described_angle = float((child_text(element, "angle") or "0").replace(",", "."))
        discretization = max(1, int(child_text(element, "discretization") or "1"))
    except ValueError:
        return []

    perpendicular_scale = 1.0

    if circular != 1:
        try:
            perpendicular_length = float(
                (child_text(element, "length") or "0").replace(",", ".")
            )
        except ValueError:
            return []

        # In Soundvision's non-circular mode, Perpendicular length is the
        # perpendicular semi-axis at the last profile depth. Other profile
        # depths scale proportionally from the origin.
        reference_depth = profile[-1][0]

        # Normal Soundvision profiles end at a non-zero depth. Keep a robust
        # fallback for unusual profiles where the final point is at depth 0.
        if abs(reference_depth) < 1e-12:
            reference_depth = max((abs(depth) for depth, _ in profile), default=0.0)

        if abs(reference_depth) < 1e-12:
            return []

        perpendicular_scale = perpendicular_length / reference_depth

    total_angle = math.radians(described_angle)
    start_angle = -total_angle / 2.0
    angle_deg, translation = parse_init_transform(element)
    patches: list[dict] = []

    def local_point(depth: float, height: float, j: int) -> tuple[float, float, float]:
        theta = start_angle + total_angle * (j / discretization)

        if circular == 1:
            x = depth * math.sin(theta)
        else:
            x = depth * perpendicular_scale * math.sin(theta)

        z = depth * math.cos(theta)
        return x, height, z

    for profile_index in range(len(profile) - 1):
        depth_a, height_a = profile[profile_index]
        depth_b, height_b = profile[profile_index + 1]

        for segment in range(discretization):
            internal_points = [
                local_point(depth_a, height_a, segment),
                local_point(depth_b, height_b, segment),
                local_point(depth_b, height_b, segment + 1),
                local_point(depth_a, height_a, segment + 1),
            ]
            patches.append(
                make_patch(
                    f"{name} ({profile_index + 1}, {segment + 1})",
                    internal_points,
                    angle_deg,
                    translation,
                    "Revolution",
                )
            )

    return patches


def extract_geometry(xml_data: bytes) -> tuple[list[dict], dict[str, int]]:
    root = ET.fromstring(xml_data)
    geometry = extract_explicit_surfaces(root)
    counts = {"Surface": len(geometry), "Balcony": 0, "Revolution": 0}

    for element in root.iter():
        tag = local_name(element.tag)
        if tag == "balcony":
            generated = generate_balcony(element)
            geometry.extend(generated)
            if generated:
                counts["Balcony"] += 1
        elif tag == "revolution":
            generated = generate_revolution(element)
            geometry.extend(generated)
            if generated:
                counts["Revolution"] += 1

    return geometry, counts


def sanitize_layer_name(name: str, fallback: str) -> str:
    # DXF layer names may not contain these characters.
    cleaned = re.sub(r'[<>/\\":;?*|=,]', "_", name).strip()
    cleaned = cleaned[:200]
    return cleaned or fallback


def unique_layer_name(doc, desired: str) -> str:
    base = desired
    candidate = base
    i = 2
    while candidate in doc.layers:
        candidate = f"{base}_{i}"
        i += 1
    return candidate


def _project_polygon_to_2d(points: list[tuple[float, float, float]]) -> list[tuple[float, float]]:
    """Project an approximately planar 3D polygon onto its dominant 2D plane."""
    nx = ny = nz = 0.0
    for i, (x1, y1, z1) in enumerate(points):
        x2, y2, z2 = points[(i + 1) % len(points)]
        nx += (y1 - y2) * (z1 + z2)
        ny += (z1 - z2) * (x1 + x2)
        nz += (x1 - x2) * (y1 + y2)

    ax, ay, az = abs(nx), abs(ny), abs(nz)
    if ax >= ay and ax >= az:
        return [(y, z) for x, y, z in points]
    if ay >= az:
        return [(x, z) for x, y, z in points]
    return [(x, y) for x, y, z in points]


def _signed_area_2d(points: list[tuple[float, float]]) -> float:
    return 0.5 * sum(
        x1 * y2 - x2 * y1
        for (x1, y1), (x2, y2) in zip(points, points[1:] + points[:1])
    )


def _point_in_triangle(p, a, b, c, eps=1e-12) -> bool:
    def cross(o, u, v):
        return (u[0] - o[0]) * (v[1] - o[1]) - (u[1] - o[1]) * (v[0] - o[0])

    c1 = cross(a, b, p)
    c2 = cross(b, c, p)
    c3 = cross(c, a, p)
    has_neg = c1 < -eps or c2 < -eps or c3 < -eps
    has_pos = c1 > eps or c2 > eps or c3 > eps
    return not (has_neg and has_pos)


def triangulate_polygon(points: list[tuple[float, float, float]]) -> list[tuple[int, int, int]]:
    """Ear-clipping triangulation. Preserves the original polygon orientation."""
    n = len(points)
    if n < 3:
        return []
    if n == 3:
        return [(0, 1, 2)]

    p2 = _project_polygon_to_2d(points)
    orientation = 1.0 if _signed_area_2d(p2) >= 0 else -1.0
    remaining = list(range(n))
    triangles: list[tuple[int, int, int]] = []
    eps = 1e-12

    def cross(a, b, c):
        return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])

    guard = 0
    while len(remaining) > 3 and guard < n * n:
        guard += 1
        ear_found = False
        m = len(remaining)
        for j in range(m):
            i_prev = remaining[(j - 1) % m]
            i_curr = remaining[j]
            i_next = remaining[(j + 1) % m]
            a, b, c = p2[i_prev], p2[i_curr], p2[i_next]

            if orientation * cross(a, b, c) <= eps:
                continue

            if any(
                _point_in_triangle(p2[k], a, b, c)
                for k in remaining
                if k not in (i_prev, i_curr, i_next)
            ):
                continue

            triangles.append((i_prev, i_curr, i_next))
            del remaining[j]
            ear_found = True
            break

        if not ear_found:
            # Degenerate/self-intersecting polygon: fall back to a fan so the
            # export still completes instead of dropping the surface entirely.
            return [(0, i, i + 1) for i in range(1, n - 1)]

    if len(remaining) == 3:
        triangles.append(tuple(remaining))
    return triangles


def _points_are_close(
    a: tuple[float, float, float],
    b: tuple[float, float, float],
    tolerance: float = 1e-9,
) -> bool:
    return math.dist(a, b) <= tolerance


def normalize_polygon_points(
    points: Iterable[tuple[float, float, float]],
    tolerance: float = 1e-9,
) -> list[tuple[float, float, float]]:
    """Remove redundant consecutive/closing vertices without changing shape.

    Soundvision Revolutions whose profile reaches the rotation axis naturally
    produce patches such as ``centre -> outer A -> outer B -> centre``. That is
    geometrically a triangle, but exporting all four vertices creates a
    degenerate DXF 3DFACE. Converting it to three unique vertices is cleaner for
    Vectorworks while preserving exactly the same geometry.
    """
    clean: list[tuple[float, float, float]] = []
    for point in points:
        if not clean or not _points_are_close(clean[-1], point, tolerance):
            clean.append(point)

    if len(clean) > 1 and _points_are_close(clean[0], clean[-1], tolerance):
        clean.pop()

    return clean


def validate_geometry(surfaces: Iterable[dict]) -> None:
    """Fail early if generated geometry contains non-finite or collapsed data.

    Soundvision's converted Surface coordinates are serialized from 32-bit
    floating-point values (the reference files use nine digits after the
    decimal point in scientific notation).  The converter intentionally keeps
    Python double-precision calculations instead of globally quantizing to
    float32: across the supplied Soundvision 2026.3.1 reference projects this
    gives the most consistent geometric match, while avoiding unnecessary
    precision loss in DXF.
    """
    for index, surface in enumerate(surfaces, start=1):
        name = surface.get("name", f"Surface {index}")
        points = list(surface.get("points", []))
        if not points:
            raise ValueError(f"{name}: no vertices were generated")
        for vertex_index, point in enumerate(points, start=1):
            if len(point) != 3 or not all(math.isfinite(v) for v in point):
                raise ValueError(
                    f"{name}: invalid vertex {vertex_index}: {point!r}"
                )
        if len(normalize_polygon_points(points)) < 3:
            raise ValueError(
                f"{name}: fewer than three unique vertices were generated"
            )


def write_dxf(surfaces: Iterable[dict], output_path: Path, export_faces: bool, export_outlines: bool, export_points: bool) -> int:
    surfaces = list(surfaces)
    doc = ezdxf.new("R2018")
    doc.header["$INSUNITS"] = 6  # metres
    msp = doc.modelspace()

    point_layer = "SV_POINTS"
    if export_points and point_layer not in doc.layers:
        doc.layers.add(point_layer)

    exported_count = 0

    for index, surface in enumerate(surfaces, start=1):
        desired = sanitize_layer_name(surface["name"], f"Surface_{index}")
        # Each Soundvision surface gets its own DXF layer. Vectorworks can map
        # these DXF layers to classes on import, retaining the surface names.
        layer = unique_layer_name(doc, f"SV_{desired}")
        doc.layers.add(layer)

        points = normalize_polygon_points(surface["points"])

        # Ignore a malformed/fully collapsed patch rather than writing an
        # invalid DXF entity. Valid Soundvision room patches always have at
        # least three unique vertices after redundant closing vertices are
        # removed.
        if len(points) < 3:
            continue

        if export_faces:
            if len(points) in (3, 4):
                msp.add_3dface(points, dxfattribs={"layer": layer})
            else:
                # DXF 3DFACE supports max. 4 vertices. Larger polygons are
                # triangulated; concave polygons are handled by ear clipping.
                for a, b, c in triangulate_polygon(points):
                    msp.add_3dface(
                        [points[a], points[b], points[c]],
                        dxfattribs={"layer": layer},
                    )

        if export_outlines:
            msp.add_polyline3d(points, close=True, dxfattribs={"layer": layer})

        if export_points:
            for p in points:
                msp.add_point(p, dxfattribs={"layer": point_layer})

        exported_count += 1

    doc.saveas(output_path)
    return exported_count


def main() -> int:
    input_path = get_input_path()
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}")
        return 1

    export_faces, export_outlines, export_points = get_export_options()
    if not any((export_faces, export_outlines, export_points)):
        print("Cancelled: No export option selected.")
        return 0

    output_path = input_path.with_name(input_path.stem + "_converted.dxf")

    print("\n" + "=" * 72)
    print("SOUNDVISION TO DXF CONVERTER")
    print("=" * 72)
    print(f"Input:  {input_path}")

    try:
        clear_xml, crypto_label = decrypt_soundvision(input_path)
    except Exception as exc:
        print(f"\nERROR while decrypting: {exc}")
        return 1

    print(f"Decrypt: OK ({crypto_label})")

    try:
        surfaces, source_counts = extract_geometry(clear_xml)
    except ET.ParseError as exc:
        print(f"ERROR: Decrypted XML could not be parsed: {exc}")
        return 1

    if not surfaces:
        print("ERROR: No supported room geometry found.")
        return 1

    try:
        validate_geometry(surfaces)
    except ValueError as exc:
        print(f"ERROR: Invalid generated geometry: {exc}")
        return 1

    print(f"DXF faces/patches: {len(surfaces)}")
    print(f"  native Surfaces:    {source_counts['Surface']}")
    print(f"  Balcony objects:    {source_counts['Balcony']}")
    print(f"  Revolution objects: {source_counts['Revolution']}")
    for i, s in enumerate(surfaces, start=1):
        print(f"  {i:3d}. [{s.get('source_type', 'Surface')}] {s['name']}  ({len(s['points'])} points)")

    print("Export options:")
    print(f"  3D Faces:    {'YES' if export_faces else 'NO'}")
    print(f"  3D Outlines: {'YES' if export_outlines else 'NO'}")
    print(f"  Vertices:    {'YES' if export_points else 'NO'}")

    count = write_dxf(surfaces, output_path, export_faces, export_outlines, export_points)

    print("\n" + "=" * 72)
    print("DONE")
    print("=" * 72)
    print(f"{count} DXF faces/patches exported")
    print(f"DXF: {output_path}")
    print("Units: metres")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
