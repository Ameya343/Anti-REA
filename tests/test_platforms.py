"""Platform detection and platform-filtered config generation."""

import os

from antirea import configs, platforms

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "sample-app")


def test_detect_sample_is_electron_web_python():
    det = platforms.detect(SAMPLE)
    plats = set(det.platforms)
    assert "python" in plats          # two .py files
    assert "web" in plats             # package.json
    assert "electron" in plats        # electron in package.json


def test_configs_for_android_only():
    names = set(configs.configs_for(["android"]))
    assert "proguard-rules.pro" in names
    assert "network_security_config.xml" in names
    assert "okhttp-pinning.kt" in names
    assert "README.md" in names        # README always included
    assert "terser.config.json" not in names
    assert "native-hardening.md" not in names


def test_configs_for_electron_includes_js_and_fuses():
    names = set(configs.configs_for(["electron"]))
    assert "electron-fuses.js" in names
    assert "terser.config.json" in names          # web configs apply to electron
    assert "proguard-rules.pro" not in names


def test_write_configs_filtered(tmp_path):
    written = configs.write_configs(str(tmp_path), platforms=["ios"])
    base = {os.path.basename(p) for p in written}
    assert base == {"README.md", "apple-hardening.md"}
    assert (tmp_path / "apple-hardening.md").exists()


def test_write_all_configs(tmp_path):
    written = configs.write_configs(str(tmp_path))     # None => all
    assert len(written) == len(configs.CONFIGS)
