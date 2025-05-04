#!/usr/bin/python3
import argparse
import re

# Map of hash length (hex) to type
HASH_LENGTHS = {
    32: "MD5",
    40: "SHA1",
    56: "SHA224",
    64: "SHA256",
    96: "SHA384",
    128: "SHA512"
}

# Map of prefix patterns to hash types (MCF or special encodings)
HASH_PREFIXES = {
    r"^\$1\$": "MD5-Crypt",
    r"^\$2[aby]?\$": "Blowfish (bcrypt)",
    r"^\$5\$": "SHA-256 Crypt",
    r"^\$6\$": "SHA-512 Crypt"
}

def identify_by_prefix(hash_str):
    for pattern, hash_type in HASH_PREFIXES.items():
        if re.match(pattern, hash_str):
            return hash_type
    return None

def identify_by_length(hash_str):
    clean_hash = re.sub(r'[^a-fA-F0-9]', '', hash_str)  # Remove non-hex characters
    return HASH_LENGTHS.get(len(clean_hash), None)

def identify_hash(hash_str):
    by_prefix = identify_by_prefix(hash_str)
    if by_prefix:
        return by_prefix

    by_length = identify_by_length(hash_str)
    if by_length:
        return by_length

    return "Plaintext/Unknown"

def main():
    parser = argparse.ArgumentParser(description="CheckHash")
    parser.add_argument("hash", help="The hash to identify")
    args = parser.parse_args()

    hash_input = args.hash.strip()
    hash_type = identify_hash(hash_input)

    print(f"Input hash: {hash_input}")
    print(f"Identified as: {hash_type}")

if __name__ == "__main__":
    main()