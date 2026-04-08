#!/usr/bin/env python3
"""Rewrite a Homebrew formula in place: bump version, URL paths, and sha256 lines.

Reads the formula path from argv[1], and the following env vars:
  VERSION              e.g. "0.10.0" (no leading v)
  SHA_MACOS_AARCH64
  SHA_MACOS_X86_64
  SHA_LINUX_AARCH64
  SHA_LINUX_X86_64

Assumptions about the formula:
  - Has `version "X.Y.Z"` somewhere
  - Has `url "...releases/download/vX.Y.Z/numa-<target>.tar.gz"` lines
  - May or may not already have `sha256 "..."` lines immediately after each url
"""
import os
import re
import sys

formula_path = sys.argv[1]
version = os.environ["VERSION"].lstrip("v")
shas = {
    "macos-aarch64": os.environ["SHA_MACOS_AARCH64"],
    "macos-x86_64": os.environ["SHA_MACOS_X86_64"],
    "linux-aarch64": os.environ["SHA_LINUX_AARCH64"],
    "linux-x86_64": os.environ["SHA_LINUX_X86_64"],
}

with open(formula_path) as f:
    content = f.read()

content = re.sub(r'version "[^"]*"', f'version "{version}"', content)
content = re.sub(
    r"releases/download/v[\d.]+/numa-",
    f"releases/download/v{version}/numa-",
    content,
)
content = re.sub(r'\n[ \t]*sha256 "[^"]*"', "", content)


def add_sha(match: re.Match) -> str:
    indent = match.group(1)
    target = match.group(2)
    if target not in shas:
        return match.group(0)
    return f'{match.group(0)}\n{indent}sha256 "{shas[target]}"'


content = re.sub(
    r'^([ \t]+)url "[^"]*numa-([\w-]+)\.tar\.gz"',
    add_sha,
    content,
    flags=re.MULTILINE,
)

with open(formula_path, "w") as f:
    f.write(content)
