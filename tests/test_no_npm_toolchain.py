"""my-auth must not keep an npm toolchain for browser tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_repo_has_no_npm_toolchain() -> None:
    assert not (ROOT / "package.json").exists()
    assert not (ROOT / "package-lock.json").exists()
    assert not (ROOT / "playwright.config.js").exists()
    workflow = (
        ROOT / ".github" / "workflows" / "app-factory-compatibility.yml"
    ).read_text(encoding="utf-8")
    assert "npm ci" not in workflow
    assert "npx " not in workflow
    assert "setup-node" not in workflow
    assert "cache: npm" not in workflow
