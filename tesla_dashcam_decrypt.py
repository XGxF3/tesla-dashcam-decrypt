#!/usr/bin/env python3
"""
Tesla Dashcam Batch Decryptor
==============================
Decrypts Tesla 2026.20+ encrypted dashcam files locally.

Encryption scheme (reverse engineered from dashcam.tesla.com):
  - Each .mp4 is AES-128-CBC encrypted in 4096-byte pages
  - Each page IV is derived from MD5(MD5(file_key) + page_number)
  - The AES key is fetched from Tesla's API (tied to your account)
  - The file header contains the UUID and ownership metadata needed
    to request the per-file key

Usage:
  1. Get your Tesla auth token (see instructions below)
  2. Point the script at your TeslaCam USB folder
  3. Run it — decrypted MP4s land in the output folder

Getting your auth token:
  - Open dashcam.tesla.com in Chrome, log in
  - Open DevTools → Application → Cookies → dashcam.tesla.com
  - Copy the value of the cookie named "token" or "access_token"
  - Or: DevTools → Network → any /api/ request → Headers → Authorization: Bearer <TOKEN>
"""

import argparse
import base64
import hashlib
import json
import subprocess
import struct
import sys
import time
from pathlib import Path

import requests
from Crypto.Cipher import AES

# ── Constants ──────────────────────────────────────────────────────────────────

TESLA_API_BASE    = "https://dashcam.tesla.com"
DECRYPT_BATCH_URL = f"{TESLA_API_BASE}/api/1/decrypt/batch"

CHUNK_SIZE        = 4096          # bytes of ciphertext per chunk
HEADER_SIZE       = 16            # IV prepended to synthetic fixture chunks
FULL_CHUNK        = CHUNK_SIZE + HEADER_SIZE  # 4112 bytes total

# UUID is stored as a 16-byte binary at this offset in the encrypted file header
# (first 36 bytes appear to be a magic + UUID in the custom Tesla container)
UUID_OFFSET       = 4            # bytes into the file where the 16-byte UUID lives

# Real Tesla 2026.20 files contain API ownership metadata in a 4096-byte header
# block, and encrypted media ciphertext starts at the next 4096-byte boundary.
EXTENDED_HEADER_OFFSET = 0x1000
REAL_CIPHERTEXT_OFFSET = 0x2000
KEY_ID_OFFSET          = EXTENDED_HEADER_OFFSET
PUBLIC_KEY_OFFSET      = KEY_ID_OFFSET + 4
PUBLIC_KEY_SIZE        = 65
VIN_OFFSET             = PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE
VIN_SIZE               = 17
TIMESTAMP_SIZE         = 8
TIMESTAMP_OFFSET       = VIN_OFFSET + VIN_SIZE
WRAPPED_KEY_OFFSET     = TIMESTAMP_OFFSET + TIMESTAMP_SIZE
WRAPPED_KEY_SIZE       = 44


# ── Tesla API ──────────────────────────────────────────────────────────────────

def get_session(token: str) -> requests.Session:
    """Build an authenticated requests session."""
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Origin":        TESLA_API_BASE,
        "Referer":       f"{TESLA_API_BASE}/",
    })
    return s


def read_file_uuid(path: Path) -> str:
    """
    Read the 16-byte UUID from the encrypted file header and return
    it formatted as a lowercase hyphenated UUID string.
    """
    with open(path, "rb") as f:
        f.seek(UUID_OFFSET)
        raw = f.read(16)
    if len(raw) < 16:
        raise ValueError(f"File too short to contain UUID: {path}")
    # Interpret as UUID: 4-2-2-2-6 byte grouping (standard UUID layout)
    a = raw[0:4].hex()
    b = raw[4:6].hex()
    c = raw[6:8].hex()
    d = raw[8:10].hex()
    e = raw[10:16].hex()
    return f"{a}-{b}-{c}-{d}-{e}"


def _has_extended_header(path: Path) -> bool:
    """Return True for real Tesla files with the 0x1000 metadata block."""
    with open(path, "rb") as f:
        probe = f.read(EXTENDED_HEADER_OFFSET + 4)

    if probe.startswith(b"TSLC"):
        return False
    if len(probe) < EXTENDED_HEADER_OFFSET + 4:
        return False

    metadata_offset = struct.unpack(">I", probe[0x14:0x18])[0]
    return metadata_offset == EXTENDED_HEADER_OFFSET and probe[KEY_ID_OFFSET:KEY_ID_OFFSET + 4] != b"\x00" * 4


def _read_real_plaintext_size(path: Path) -> int:
    """Real Tesla files store the decrypted MP4 length as a big-endian uint64."""
    with open(path, "rb") as f:
        raw = f.read(8)
    if len(raw) != 8:
        raise ValueError(f"File too short to contain plaintext size: {path}")
    size = struct.unpack(">Q", raw)[0]
    if size <= 0:
        raise ValueError(f"Invalid plaintext size in encrypted header: {path}")
    return size


def read_file_header(path: Path) -> dict:
    """
    Read all fields needed for the decrypt API from the file header.
    Returns dict with keys: id, vin, key_id, timestamp, wrapped_key, public_key.
    Synthetic TSLC fixtures only contain the id, so they return that field alone.
    """
    file_id = read_file_uuid(path)
    header = {"id": file_id}

    if not _has_extended_header(path):
        return header

    with open(path, "rb") as f:
        f.seek(KEY_ID_OFFSET)
        key_id_raw = f.read(4)
        f.seek(PUBLIC_KEY_OFFSET)
        public_key_raw = f.read(PUBLIC_KEY_SIZE)
        f.seek(VIN_OFFSET)
        vin_raw = f.read(VIN_SIZE)
        f.seek(TIMESTAMP_OFFSET)
        timestamp_raw = f.read(TIMESTAMP_SIZE)
        f.seek(WRAPPED_KEY_OFFSET)
        wrapped_key_raw = f.read(WRAPPED_KEY_SIZE)

    if len(wrapped_key_raw) != WRAPPED_KEY_SIZE:
        raise ValueError(f"File too short to contain ownership metadata: {path}")

    vin = vin_raw.decode("ascii", errors="ignore").rstrip("\x00")
    if len(vin) != VIN_SIZE:
        raise ValueError(f"Invalid VIN in encrypted header: {path}")
    if not public_key_raw.startswith(b"\x04"):
        raise ValueError(f"Invalid public key in encrypted header: {path}")

    header.update({
        "vin": vin,
        "key_id": struct.unpack(">I", key_id_raw)[0],
        "timestamp": struct.unpack(">Q", timestamp_raw)[0],
        "wrapped_key": base64.b64encode(wrapped_key_raw).decode("ascii"),
        "public_key": base64.b64encode(public_key_raw).decode("ascii"),
    })
    return header


def _api_item_from_header(header: dict | str) -> dict:
    if isinstance(header, str):
        return {"id": header}

    required = ("id", "vin", "key_id", "timestamp", "wrapped_key", "public_key")
    if all(field in header for field in required):
        return {field: header[field] for field in required}
    return {"id": header["id"]}


def fetch_keys_batch(session: requests.Session, file_headers: list[dict] | list[str]) -> dict[str, bytes]:
    """
    POST to /api/1/decrypt/batch with file UUIDs and ownership metadata.
    Returns a dict mapping uuid -> raw AES key bytes.
    """
    payload = {"items": [_api_item_from_header(header) for header in file_headers]}
    resp = session.post(DECRYPT_BATCH_URL, json=payload, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    keys = {}
    for result in data.get("results", []):
        uid = result["id"]
        if result.get("error"):
            print(f"  [!] API error for {uid}: {result['error']}")
            continue
        raw_key = base64.b64decode(result["key"])
        keys[uid] = raw_key
    return keys


# ── Decryption ─────────────────────────────────────────────────────────────────

def decrypt_file(src: Path, dst: Path, key_bytes: bytes) -> int:
    """
    Decrypt a Tesla-encrypted .mp4 file.

    Real Tesla files use a two-page header followed by 4096-byte encrypted
    eCryptfs pages. Synthetic fixtures use a smaller IV-prefixed chunk format.

    Returns number of bytes written.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    if _has_extended_header(src):
        return _decrypt_real_file(src, dst, key_bytes)

    written = 0

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        # Synthetic fixtures start after 20 bytes.
        fin.seek(20)

        while True:
            chunk = fin.read(FULL_CHUNK)
            if not chunk:
                break

            if len(chunk) < HEADER_SIZE + 1:
                # Last chunk may be partial — write as-is (shouldn't happen)
                fout.write(chunk)
                written += len(chunk)
                break

            iv          = chunk[:HEADER_SIZE]
            ciphertext  = chunk[HEADER_SIZE:]

            cipher      = AES.new(key_bytes, AES.MODE_CBC, iv)
            plaintext   = cipher.decrypt(ciphertext)

            # Strip PKCS7 padding on the last block only
            if len(chunk) < FULL_CHUNK:
                pad_len = plaintext[-1]
                if 1 <= pad_len <= 16:
                    plaintext = plaintext[:-pad_len]

            fout.write(plaintext)
            written += len(plaintext)

    return written


def _decrypt_real_file(src: Path, dst: Path, key_bytes: bytes) -> int:
    """
    Decrypt a real Tesla 2026.20 encrypted clip.

    Tesla's browser decrypts the payload as 4096-byte eCryptfs pages. Each page
    uses AES-CBC with IV = md5(md5(file_key) + ascii(page_number) + zero padding).
    """
    target_size = _read_real_plaintext_size(src)
    root_iv = hashlib.md5(key_bytes).digest()
    written = 0

    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fin.seek(REAL_CIPHERTEXT_OFFSET)
        page = 0
        while written < target_size:
            encrypted_page = fin.read(CHUNK_SIZE)
            if not encrypted_page:
                break
            if len(encrypted_page) != CHUNK_SIZE:
                raise ValueError(f"Encrypted page is not 4096 bytes: {src}")

            iv_material = bytearray(32)
            iv_material[:len(root_iv)] = root_iv
            page_bytes = str(page).encode("ascii")
            iv_material[len(root_iv):len(root_iv) + len(page_bytes)] = page_bytes
            derived_iv = hashlib.md5(iv_material).digest()

            plaintext = AES.new(key_bytes, AES.MODE_CBC, derived_iv).decrypt(encrypted_page)
            remaining = target_size - written
            if remaining < len(plaintext):
                plaintext = plaintext[:remaining]
            fout.write(plaintext)
            written += len(plaintext)
            page += 1

    if written != target_size:
        raise ValueError(f"Decrypted output shorter than expected: {src}")
    return written


def remux_mp4(src: Path, dst: Path) -> None:
    """Losslessly remux an MP4 through ffmpeg to rewrite container metadata."""
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-i",
            str(src),
            "-c",
            "copy",
            "-movflags",
            "faststart",
            str(dst),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


# ── File discovery ─────────────────────────────────────────────────────────────

def find_encrypted_files(root: Path) -> list[Path]:
    """
    Walk a TeslaCam USB root and return all .mp4 files.
    Tesla still uses the .mp4 extension for encrypted files.
    """
    found = []
    for pattern in ("**/*.mp4", "**/*.MP4"):
        found.extend(root.glob(pattern))
    return sorted(set(found))


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Batch-decrypt Tesla 2026.20+ encrypted dashcam files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "input_dir",
        type=Path,
        help="Root of your TeslaCam USB drive (e.g. /Volumes/TESLA/TeslaCam)",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Where to write decrypted MP4 files (folder will be created)",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Your Tesla Bearer token from dashcam.tesla.com (see instructions above)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=20,
        help="How many files to request keys for per API call (default: 20)",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        default=True,
        help="Skip files that already exist in the output folder (default: on)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover files and fetch keys but don't write output",
    )
    parser.add_argument(
        "--remux",
        action="store_true",
        help="Losslessly remux each decrypted MP4 with ffmpeg after decryption",
    )
    args = parser.parse_args()

    if not args.input_dir.exists():
        sys.exit(f"Error: input directory not found: {args.input_dir}")

    print(f"\n🔍  Scanning {args.input_dir} for encrypted dashcam files…")
    all_files = find_encrypted_files(args.input_dir)
    if not all_files:
        sys.exit("No .mp4 files found. Check your input path.")

    print(f"    Found {len(all_files)} file(s)\n")

    # Filter out already-decrypted files
    to_process = []
    for src in all_files:
        rel  = src.relative_to(args.input_dir)
        dst  = args.output_dir / rel
        if args.skip_existing and dst.exists():
            print(f"  ⏭  Skipping (exists): {rel}")
            continue
        to_process.append((src, dst))

    if not to_process:
        print("Nothing to do — all files already decrypted.")
        return

    print(f"📋  {len(to_process)} file(s) to decrypt\n")

    session = get_session(args.token)

    # Process in batches
    total_ok  = 0
    total_err = 0

    for batch_start in range(0, len(to_process), args.batch_size):
        batch = to_process[batch_start : batch_start + args.batch_size]

        # 1. Read API metadata from each file header
        file_headers = {}
        for src, dst in batch:
            try:
                header = read_file_header(src)
                file_headers[header["id"]] = (header, src, dst)
            except Exception as e:
                print(f"  [!] Can't read header from {src.name}: {e}")
                total_err += 1

        if not file_headers:
            continue

        # 2. Fetch AES keys from Tesla API
        print(f"🔑  Fetching keys for {len(file_headers)} file(s)…")
        try:
            keys = fetch_keys_batch(session, [h for h, _, _ in file_headers.values()])
        except requests.HTTPError as e:
            print(f"  [!] API error: {e}")
            if e.response.status_code == 401:
                sys.exit("Token expired or invalid. Please get a fresh token from dashcam.tesla.com.")
            total_err += len(file_headers)
            continue

        # 3. Decrypt each file
        for uid, key_bytes in keys.items():
            _, src, dst = file_headers[uid]
            rel = src.relative_to(args.input_dir)
            print(f"  🔓  {rel}", end="", flush=True)

            if args.dry_run:
                print(" [dry-run, skipped]")
                total_ok += 1
                continue

            try:
                decrypt_dst = dst
                if args.remux:
                    decrypt_dst = dst.with_name(f".{dst.name}.decrypting")

                written = decrypt_file(src, decrypt_dst, key_bytes)
                if args.remux:
                    remux_tmp = dst.with_name(f".{dst.name}.remuxing")
                    try:
                        remux_mp4(decrypt_dst, remux_tmp)
                        remux_tmp.replace(dst)
                    finally:
                        if decrypt_dst.exists():
                            decrypt_dst.unlink()
                        if remux_tmp.exists():
                            remux_tmp.unlink()
                mb = written / 1_048_576
                print(f" → {dst.name} ({mb:.1f} MB) ✓")
                total_ok += 1
            except Exception as e:
                print(f" [ERROR: {e}]")
                total_err += 1
                if dst.exists():
                    dst.unlink()  # Remove partial output

    print(f"\n{'='*50}")
    print(f"✅  Done: {total_ok} decrypted, {total_err} failed")
    print(f"📁  Output: {args.output_dir}")


if __name__ == "__main__":
    main()
