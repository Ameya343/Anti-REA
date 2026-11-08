"""Prebuilt-core resolver logic (no network)."""

import os
import platform
import sys

from antirea import coreinstall


def test_asset_name_matches_host():
    name = coreinstall.asset_name()
    assert name.startswith("antirea-core-")
    assert name.endswith(".exe") == sys.platform.startswith("win")


def test_host_triple_known():
    triple, is_win = coreinstall.host_triple()
    assert any(k in triple for k in ("linux", "darwin", "windows"))
    assert is_win == sys.platform.startswith("win")
    assert triple.split("-")[0] in ("x86_64", "aarch64", platform.machine().lower())


def test_download_url_shapes():
    latest = coreinstall.download_url("latest")
    assert latest.endswith(coreinstall.asset_name())
    assert "/releases/latest/download/" in latest
    assert "/releases/download/v1.2.3/" in coreinstall.download_url("v1.2.3")


def test_installed_path_under_cache():
    p = coreinstall.installed_path()
    assert os.path.dirname(p) == coreinstall.cache_dir()
    assert os.path.basename(p).startswith("antirea-core")
