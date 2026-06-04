# Decrypting Tesla's 2026.20 Dashcam Encryption

**Author:** [@XGxF3](https://github.com/XGxF3)  
**Repo:** [github.com/XGxF3/tesla-dashcam-decrypt](https://github.com/XGxF3/tesla-dashcam-decrypt)  
**Firmware:** Tesla 2026.20  
**Date:** June 2026

---

## Overview

Tesla added encryption to dashcam USB recordings in firmware 2026.20. This write-up documents the encryption scheme observed in the official browser viewer at `dashcam.tesla.com`, and provides a working Python tool to batch-decrypt an entire USB drive locally. The video bytes remain local; the tool only sends per-file metadata to Tesla's key endpoint.

---

## Background

Before this change, dashcam and Sentry clips on the USB drive were ordinary MP4 files. In 2026.20, the files on disk became encrypted containers that must be opened through Tesla's web viewer. The user-facing flow is to sign in at `dashcam.tesla.com`, drag encrypted clips into the page, and let the browser decrypt them one at a time.

That works for occasional viewing, but it is cumbersome for a USB drive containing hundreds of clips. The browser already performs the cryptographic work locally, so the practical goal was to reproduce that flow in a local batch tool without uploading video content.

---

## Methodology: Intercepting the Browser Viewer

### Tools Used

- Chrome DevTools (Network tab + Console)
- JavaScript `fetch()` API interception
- WebCrypto API hook (`crypto.subtle.decrypt`)
- Inspection of Tesla's shipped `encryptfs` browser bundle

### Step 1 - Network interception

The first step was to intercept browser requests made by the official viewer. Hooking `window.fetch` in DevTools showed that the page posts one or more file metadata records to `/api/1/decrypt/batch` and receives a base64 AES-128 file key for each item.

**Request:**

```json
POST https://dashcam.tesla.com/api/1/decrypt/batch
Authorization: Bearer YOUR_TESLA_TOKEN_HERE

{
  "items": [{
    "id":          "YOUR_FILE_UUID_HERE",
    "vin":         "YOUR_VIN_HERE",
    "key_id":      1,
    "timestamp":   YOUR_TIMESTAMP_HERE,
    "wrapped_key": "YOUR_WRAPPED_KEY_HERE",
    "public_key":  "YOUR_PUBLIC_KEY_HERE"
  }]
}
```

**Response:**

```json
{
  "results": [{
    "id":    "YOUR_FILE_UUID_HERE",
    "key":   "BASE64_AES_128_KEY_HERE",
    "error": null
  }]
}
```

The server returns a base64-encoded AES-128 key. The page messaging says that files never leave the device, and the observed behavior matches that: only UUIDs and ownership metadata are sent to Tesla; the encrypted video bytes are decrypted locally in the browser.

### Step 2 - WebCrypto hook

The browser uses WebCrypto for the cryptographic operations. A minimal DevTools hook can log the algorithms and key lengths without logging secret key material:

```js
(() => {
  const importKey = crypto.subtle.importKey.bind(crypto.subtle);
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);

  crypto.subtle.importKey = async (...args) => {
    const [format, keyData, algorithm, extractable, usages] = args;
    console.log("importKey", {
      format,
      algorithm,
      keyBytes: keyData?.byteLength,
      extractable,
      usages,
    });
    return importKey(...args);
  };

  crypto.subtle.decrypt = async (...args) => {
    const [algorithm, key, data] = args;
    console.log("decrypt", {
      name: algorithm?.name,
      ivBytes: algorithm?.iv?.byteLength,
      ciphertextBytes: data?.byteLength,
    });
    return decrypt(...args);
  };
})();
```

This confirmed AES-CBC with 16-byte keys. The remaining detail was how each page IV is derived.

### Step 3 - File header analysis

Hex-dumping real encrypted files showed two 4096-byte header pages followed by encrypted payload at `0x2000`. The first header page contains file-level eCryptfs metadata, including the decrypted plaintext size and format/version fields. The second header page contains the ownership metadata needed for the Tesla key request: `key_id`, public key, VIN, timestamp, and wrapped key.

Tesla ships the relevant browser code in an unminified `encryptfs` bundle. That bundle confirmed the field layout and the decryption loop: ciphertext is processed in 4096-byte pages, and each page IV is derived from the file key and page number.

---

## The Encryption Scheme

### File Layout

```text
Offset    Size     Field
0x0000    8        Plaintext MP4 size (uint64, big-endian)
0x0008    4        Magic word 1
0x000c    4        Magic word 2 (magic1 XOR magic2 identifies the container)
0x0010    4        Version / flags
0x0014    4        Page size / metadata offset (4096)
0x0018    2+       Extent/header metadata
0x0004    16       File id bytes used as API item id by this tool
0x1000    4        key_id (uint32, big-endian)
0x1004    65       public_key (uncompressed EC point, starts with 0x04)
0x1045    17       VIN (ASCII)
0x1056    8        timestamp (uint64, big-endian)
0x105e    44       wrapped_key (binary)
0x2000+   varies   Encrypted payload, 4096-byte eCryptfs-style pages
```

The exact purpose of every field in the first header page is not required for decryption. The batch decryptor uses it to identify real Tesla containers, read the plaintext size, and skip to the encrypted payload.

### Encryption Algorithm: eCryptfs-style paging

Tesla uses an eCryptfs-inspired scheme:

- **Cipher**: AES-128-CBC
- **Page size**: 4096 bytes
- **Per-page IV derivation**:

```text
iv = MD5( MD5(file_key) + ASCII(page_number) + zero_padding_to_32_bytes )
```

Where `page_number` is the zero-indexed page (`0`, `1`, `2`, ...) formatted as a decimal ASCII string (for example, `"0"`, `"1"`, `"2"`).

This means each 4096-byte page has a unique deterministic IV. The IV is not stored explicitly in the media payload.

---

## Working Decryptor

```python
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

```

---

## Usage

```bash
# Install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Get your token from dashcam.tesla.com (DevTools -> Network -> Authorization header)

# Decrypt entire USB drive
python tesla_dashcam_decrypt.py TeslaCam/ DecryptedClips/ --token "YOUR_TOKEN"

# With ffmpeg remux for QuickTime compatibility if needed
python tesla_dashcam_decrypt.py TeslaCam/ DecryptedClips/ --token "YOUR_TOKEN" --remux
```

---

## Results

The implementation was tested on 354 encrypted clips from a real Tesla running firmware 2026.20. All 354 decrypted successfully with 0 failures. The regenerated outputs were validated with `ffprobe`; all files reported sane duration/frame counts and the expected H.264 video stream metadata, and sample files played without the earlier H.264 decode errors.

---

## Notes on Security

Tesla's design keeps video content on the user's device: the browser sends file identifiers and ownership metadata to Tesla, receives a per-file key, and decrypts locally. That prevents someone who only has the USB drive from reading footage without also having access to the owner's Tesla account. This tool is intended for owners who want local access to their own footage without the one-at-a-time browser workflow.

---

## References

- [Tesla dashcam.tesla.com](https://dashcam.tesla.com)
- [eCryptfs page IV derivation](https://www.kernel.org/doc/html/latest/filesystems/ecryptfs.html)
- [pycryptodome](https://pycryptodome.readthedocs.io)
