"""Download a prebuilt antirea-core binary (no Rust toolchain needed).

Binaries are published by the release workflow for common platforms. This
module resolves the right asset for the host, downloads it into a per-user
cache, and makes it executable. Everything is standard library only.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
import urllib.request

REPO = "Ameya343/Anti-REA"


def host_triple() -> tuple[str, bool]:
    """Return (rust-target-triple, is_windows) for the current host."""
    m = platform.machine().lower()
    if m in ("arm64", "aarch64"):
        arch = "aarch64"
    elif m in ("x86_64", "amd64"):
        arch = "x86_64"
    else:
        arch = m
    if sys.platform.startswith("linux"):
        return f"{arch}-unknown-linux-gnu", False
    if sys.platform == "darwin":
        return f"{arch}-apple-darwin", False
    if sys.platform in ("win32", "cygwin"):
        return f"{arch}-pc-windows-msvc", True
    raise RuntimeError(f"unsupported platform: {sys.platform}/{m}")


def asset_name() -> str:
    triple, is_win = host_triple()
    return f"antirea-core-{triple}" + (".exe" if is_win else "")


def cache_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or \
            os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "antirea")


def installed_path() -> str:
    exe = "antirea-core.exe" if os.name == "nt" else "antirea-core"
    return os.path.join(cache_dir(), exe)


def download_url(tag: str = "latest") -> str:
    name = asset_name()
    if tag == "latest":
        return f"https://github.com/{REPO}/releases/latest/download/{name}"
    return f"https://github.com/{REPO}/releases/download/{tag}/{name}"


def install(tag: str = "latest") -> str:
    """Download the prebuilt core for this host into the cache. Returns path."""
    url = download_url(tag)
    dest = installed_path()
    os.makedirs(cache_dir(), exist_ok=True)
    tmp = dest + ".tmp"
    req = urllib.request.Request(url, headers={"User-Agent": "antirea-install"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as fh:
        shutil.copyfileobj(r, fh)
    os.replace(tmp, dest)
    if os.name != "nt":
        st = os.stat(dest)
        os.chmod(dest, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return dest
