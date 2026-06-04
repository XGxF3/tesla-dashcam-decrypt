# Tesla Dashcam Decryptor

Batch-decrypt Tesla 2026.20+ encrypted dashcam `.mp4` files locally.

Tesla's 2026.20 update encrypts all dashcam and Sentry Mode recordings on USB. This tool lets you decrypt an entire drive's worth of clips at once — no need to load files one-by-one in a browser.

## How it works

Reverse-engineered from `dashcam.tesla.com`:

- Each encrypted `.mp4` has a **unique UUID** embedded in its 20-byte header
- The tool posts those UUIDs to Tesla's API to retrieve **per-file AES-128-CBC keys**
- Files are decrypted in 4096-byte chunks (each chunk has its own 16-byte IV prepended)
- Your footage never leaves your machine — only the UUID list touches Tesla's servers

## Requirements

- Python 3.10+
- A Tesla account with 2026.20+ firmware
- A Bearer token from [dashcam.tesla.com](https://dashcam.tesla.com) (instructions below)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Getting your token

1. Open [dashcam.tesla.com](https://dashcam.tesla.com) and log in
2. Open DevTools → Network tab
3. Drop any encrypted clip into the page
4. Click any `/api/1/` request → Headers → copy the value after `Authorization: Bearer `

## Usage

```bash
source .venv/bin/activate

python tesla_dashcam_decrypt.py \
  /Volumes/TESLA/TeslaCam \
  ~/Desktop/TeslaCam_Decrypted \
  --token "YOUR_BEARER_TOKEN"
```

Options:
```
--token         Bearer token from dashcam.tesla.com (required)
--batch-size    Files per API call, default 20
--skip-existing Skip files already in output folder (default: on)
--dry-run       Fetch keys but don't write files
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v -m "not integration"
```

For integration tests with real clips, copy `.env.example` to `.env`, add your token, put encrypted clips in `EncryptedClips/`, then:
```bash
pytest tests/ -v -m integration
```

## Security notes

- Your token expires periodically — grab a fresh one each session
- `.env`, `EncryptedClips/`, and `DecryptedClips/` are all gitignored
- Never commit real clips or tokens

## License

MIT
