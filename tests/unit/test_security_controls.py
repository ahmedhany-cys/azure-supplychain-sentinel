import json
import os
from pathlib import Path

import pytest

from sentinel.core.runner import run_tool
from sentinel.core.security import (
    SecurityError,
    ensure_allowed_root,
    load_json_bounded,
    redact,
    redact_json,
    resolve_within,
    safe_filename,
)

PEM = (
    "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBpZ1234567890abcdefghijklmnopqrs\n"
    "-----END EC PRIVATE KEY-----"
)


def test_resolve_within_blocks_traversal(tmp_path: Path):
    (tmp_path / "ok.txt").write_text("x")
    assert resolve_within(tmp_path, "ok.txt") == (tmp_path / "ok.txt").resolve()
    for evil in ["../etc/passwd", "/etc/passwd", "a/../../x"]:
        with pytest.raises(SecurityError):
            resolve_within(tmp_path, evil)


def test_resolve_within_blocks_symlink_escape(tmp_path: Path):
    base = tmp_path / "base"
    base.mkdir()
    (base / "link").symlink_to(tmp_path)
    with pytest.raises(SecurityError):
        resolve_within(base, "link/secret")


def test_allowed_roots(tmp_path: Path):
    inside = tmp_path / "proj"
    inside.mkdir()
    assert ensure_allowed_root(inside, [tmp_path]) == inside.resolve()
    with pytest.raises(SecurityError, match="allowed analysis root"):
        ensure_allowed_root("/", [tmp_path])


def test_bounded_json(tmp_path: Path):
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"x": "a" * 2000}))
    with pytest.raises(SecurityError, match="limit"):
        load_json_bounded(big, max_bytes=100)
    with pytest.raises(SecurityError):
        load_json_bounded(tmp_path)  # directories are not regular files


@pytest.mark.parametrize(
    "secret,leak",
    [
        (PEM, "MHcCAQEEIBpZ"),
        ("token ghp_" + "A" * 36, "ghp_AAAA"),
        ("github_pat_" + "B" * 30, "github_pat_BBB"),
        ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGH"),
        ("DefaultEndpointsProtocol=https;AccountKey=c2VjcmV0;EndpointSuffix=x", "c2VjcmV0"),
        ("COSIGN_PASSWORD=hunter2hunter2", "hunter2"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi"),
        ("https://x.blob.core.windows.net/c?sv=1&sig=abcdEFGH", "abcdEFGH"),
    ],
)
def test_redaction(secret, leak):
    assert leak not in redact(f"error while signing: {secret} (retrying)")


def test_redact_json_keeps_document_valid():
    doc = json.dumps({"log": f"tool printed {PEM}", "n": 1})
    out = redact_json(doc)
    assert "PRIVATE KEY" in out and "MHcCAQ" not in out
    assert json.loads(out)["n"] == 1


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("a b;rm -rf.tar.gz") == "a_b_rm_-rf.tar.gz"
    assert safe_filename("") == "upload.bin"
    assert safe_filename("....") == "upload.bin"


def test_runner_never_uses_a_shell(tmp_path: Path):
    marker = tmp_path / "pwned"
    result = run_tool(["echo", f"hello; touch {marker}"], timeout=5)
    assert result.ok
    assert b"; touch" in result.stdout
    assert not marker.exists()


def test_runner_timeout_and_missing_binary():
    slow = run_tool(["sleep", "5"], timeout=1)
    assert slow.timed_out and not slow.ok and slow.duration_s < 4
    missing = run_tool(["definitely-not-a-real-binary-xyz"], timeout=1)
    assert missing.not_found and not missing.ok


def test_runner_does_not_forward_secrets(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "super-secret-value")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "C" * 36)
    result = run_tool(["env"], timeout=5)
    out = result.stdout.decode()
    assert "super-secret-value" not in out and "GITHUB_TOKEN" not in out
    assert "PATH=" in out


def test_runner_redacts_stderr():
    result = run_tool(["sh", "-c", "echo 'password=topsecret123' >&2"], timeout=5)
    assert "topsecret123" not in result.stderr


def test_runner_rejects_non_list_argv():
    with pytest.raises(TypeError):
        run_tool("echo hi", timeout=1)  # type: ignore[arg-type]


def test_no_private_keys_committed():
    root = Path(__file__).resolve().parents[2]
    skip = {
        ".venv",
        ".git",
        "node_modules",
        ".sentinel",
        ".pytest_cache",
        ".terraform",
        "__pycache__",
        ".ruff_cache",
    }
    offenders = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix in {".key", ".pem", ".p12", ".pfx"}:
                offenders.append(path)
                continue
            if path.suffix in {".py", ".md"} or path.stat().st_size > 2_000_000:
                continue  # sources/docs may mention the PEM header in tests and examples
            try:
                if b"PRIVATE KEY-----" in path.read_bytes():
                    offenders.append(path)
            except OSError:
                continue
    assert offenders == []
