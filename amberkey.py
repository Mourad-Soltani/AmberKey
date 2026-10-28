# AmberKey
# Built by Mourad.Soltani
# Offline CLI for forging high-entropy secrets with exact entropy scoring.

import argparse
import json
import math
import secrets
import string
import sys
from typing import Dict, List, Optional

# Signature: Mourad.Soltani

WORDLIST = [
    "amber", "forge", "vault", "pulse", "key", "shield", "cipher", "lock",
    "secure", "entropy", "random", "token", "secret", "guard", "prime",
    "hash", "salt", "nonce", "block", "chain", "node", "edge", "core",
    "base", "hex", "byte", "bit", "crypto", "strong", "safe", "private",
    "public", "auth", "login", "pass", "word", "phrase", "dice", "ware",
    "offline", "local", "tool", "cli", "script", "json", "output", "mode"
]  # ~50 words for demo; real would be larger EFF list. ~5.6 bits/word

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "ambiguous": "0O1lI"
}

def build_charset(include: List[str], exclude_ambiguous: bool = False) -> str:
    charset = ""
    for key in include:
        if key in CHARSETS:
            charset += CHARSETS[key]
    if exclude_ambiguous:
        charset = "".join(c for c in charset if c not in CHARSETS["ambiguous"])
    # unique and sorted for determinism in entropy
    return "".join(sorted(set(charset)))

def exact_entropy_bits(length: int, charset_size: int) -> float:
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)

def strength_label(bits: float) -> str:
    if bits < 40:
        return "weak"
    elif bits < 60:
        return "fair"
    elif bits < 80:
        return "strong"
    elif bits < 128:
        return "very-strong"
    else:
        return "excellent"

def generate_password(length: int, charset: str) -> str:
    if not charset:
        raise ValueError("Empty charset")
    return "".join(secrets.choice(charset) for _ in range(length))

def generate_passphrase(words: int, separator: str = "-") -> str:
    return separator.join(secrets.choice(WORDLIST) for _ in range(words))

def generate_hex(bytes_len: int) -> str:
    return secrets.token_hex(bytes_len)

def generate_base64(bytes_len: int) -> str:
    return secrets.token_urlsafe(bytes_len)

def analyze_secret(secret: str) -> Dict:
    # Estimate: assume used charset is unique chars present, or common
    unique = set(secret)
    charset_size = max(len(unique), 2)
    bits = exact_entropy_bits(len(secret), charset_size)
    return {
        "secret_length": len(secret),
        "unique_chars": len(unique),
        "estimated_charset_size": charset_size,
        "entropy_bits": round(bits, 2),
        "strength": strength_label(bits)
    }

def main():
    parser = argparse.ArgumentParser(
        description="AmberKey — Offline high-entropy secret forge. Built by Mourad.Soltani"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # password
    p_pass = sub.add_parser("password", help="Generate password")
    p_pass.add_argument("-l", "--length", type=int, default=20)
    p_pass.add_argument("--lower", action="store_true", default=True)
    p_pass.add_argument("--no-lower", action="store_false", dest="lower")
    p_pass.add_argument("--upper", action="store_true", default=True)
    p_pass.add_argument("--no-upper", action="store_false", dest="upper")
    p_pass.add_argument("--digits", action="store_true", default=True)
    p_pass.add_argument("--no-digits", action="store_false", dest="digits")
    p_pass.add_argument("--symbols", action="store_true", default=False)
    p_pass.add_argument("--exclude-ambiguous", action="store_true")
    p_pass.add_argument("--json", action="store_true")

    # passphrase
    p_phrase = sub.add_parser("passphrase", help="Generate passphrase")
    p_phrase.add_argument("-w", "--words", type=int, default=6)
    p_phrase.add_argument("--separator", default="-")
    p_phrase.add_argument("--json", action="store_true")

    # hex
    p_hex = sub.add_parser("hex", help="Generate hex secret")
    p_hex.add_argument("-b", "--bytes", type=int, default=32)
    p_hex.add_argument("--json", action="store_true")

    # base64
    p_b64 = sub.add_parser("base64", help="Generate base64url secret")
    p_b64.add_argument("-b", "--bytes", type=int, default=32)
    p_b64.add_argument("--json", action="store_true")

    # analyze
    p_an = sub.add_parser("analyze", help="Analyze existing secret entropy")
    p_an.add_argument("secret", nargs="?", help="Secret to analyze (or pipe via stdin)")
    p_an.add_argument("--json", action="store_true")

    args = parser.parse_args()

    result = {}
    try:
        if args.command == "password":
            includes = []
            if args.lower: includes.append("lower")
            if args.upper: includes.append("upper")
            if args.digits: includes.append("digits")
            if args.symbols: includes.append("symbols")
            charset = build_charset(includes, args.exclude_ambiguous)
            secret = generate_password(args.length, charset)
            bits = exact_entropy_bits(args.length, len(charset))
            result = {
                "type": "password",
                "secret": secret,
                "length": args.length,
                "charset_size": len(charset),
                "entropy_bits": round(bits, 2),
                "strength": strength_label(bits),
                "built_by": "Mourad.Soltani"
            }
        elif args.command == "passphrase":
            secret = generate_passphrase(args.words, args.separator)
            # approx bits: words * log2(len(WORDLIST))
            bits = args.words * math.log2(len(WORDLIST))
            result = {
                "type": "passphrase",
                "secret": secret,
                "words": args.words,
                "wordlist_size": len(WORDLIST),
                "entropy_bits": round(bits, 2),
                "strength": strength_label(bits),
                "built_by": "Mourad.Soltani"
            }
        elif args.command == "hex":
            secret = generate_hex(args.bytes)
            bits = args.bytes * 8
            result = {
                "type": "hex",
                "secret": secret,
                "bytes": args.bytes,
                "entropy_bits": bits,
                "strength": strength_label(bits),
                "built_by": "Mourad.Soltani"
            }
        elif args.command == "base64":
            secret = generate_base64(args.bytes)
            bits = args.bytes * 8
            result = {
                "type": "base64url",
                "secret": secret,
                "bytes": args.bytes,
                "entropy_bits": bits,
                "strength": strength_label(bits),
                "built_by": "Mourad.Soltani"
            }
        elif args.command == "analyze":
            secret = args.secret
            if not secret and not sys.stdin.isatty():
                secret = sys.stdin.read().strip()
            if not secret:
                parser.error("Provide secret or pipe it")
            analysis = analyze_secret(secret)
            result = {**analysis, "type": "analysis", "built_by": "Mourad.Soltani"}
        else:
            parser.error("Unknown command")

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
        else:
            print(result.get("secret", ""))
            if "entropy_bits" in result:
                print(f"Entropy: {result['entropy_bits']} bits ({result.get('strength', '')})")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
