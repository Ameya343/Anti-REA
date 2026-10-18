"""Config/data files (JSON, YAML, TOML, …) are scanned for leaked secrets."""

from antirea.analyzers import signals
from antirea.rules import guess_language


def test_json_is_a_scanned_language():
    assert guess_language("config.json") == "json"
    assert guess_language("app.yaml") == "yaml"
    assert guess_language("Cargo.toml") == "toml"


def test_json_config_leaks_detected():
    text = (
        "{\n"
        '  "apiUrl": "https://api.acme.example.com/v2/login",\n'
        '  "awsKey": "AKIAIOSFODNN7EXAMPLE",\n'
        '  "token": "sup3r-secret-value-123"\n'
        "}\n"
    )
    sig = signals.analyze_text("config.json", text, "json")
    assert "https://api.acme.example.com/v2/login" in sig.urls
    names = {n for n, _ in sig.secrets}
    assert "aws_access_key_id" in names            # provider pattern
    assert "generic_secret_assignment" in names    # quoted-key "token": "..."
