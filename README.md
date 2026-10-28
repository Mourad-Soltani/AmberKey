# AmberKey

**Offline CLI for forging high-entropy secrets with exact entropy scoring.**

Built by Mourad.Soltani

Generate cryptographically secure passwords, passphrases, hex keys, and base64 tokens entirely offline. Get exact entropy bits and strength labels. Perfect for developers, security-conscious users, and scripting.

## Features

- Password generation with customizable charsets (lower/upper/digits/symbols, exclude ambiguous)
- Passphrase from built-in wordlist
- Hex and URL-safe base64 secrets
- Analyze existing secrets for estimated entropy
- Exact entropy calculation (length × log2(charset size))
- Strength classification: weak / fair / strong / very-strong / excellent
- JSON output for scripting
- Stdlib only — no dependencies
- Health tests included

## Quick Start (30 seconds)

```bash
# No install needed
python amberkey.py password -l 24 --symbols --json

# Passphrase
python amberkey.py passphrase -w 7

# Analyze
echo -n "MySecret!" | python amberkey.py analyze --json
```

## Requirements

- Python 3.9+
- No external packages

## Buyer Notes

What you get:
- Complete source: amberkey.py (single-file CLI)
- Unit tests that verify generation, entropy, JSON
- MIT license
- This README

How to run:
1. Download and unzip
2. `python amberkey.py --help`
3. Generate or analyze

Signature: Mourad.Soltani

## License

MIT — see LICENSE
