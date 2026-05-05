from pathlib import Path

import pytest
from click.testing import CliRunner

from bzb.cli import cli


def test_persona_init_creates_directory(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli, ["persona", "init", "acme-corp", "--dest", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-corp/persona.yaml").is_file()
    assert (tmp_path / "acme-corp/canaries.yaml").is_file()
    assert (tmp_path / "acme-corp/narrative.md").is_file()


def test_persona_init_substitutes_slug(tmp_path: Path):
    runner = CliRunner()
    runner.invoke(cli, ["persona", "init", "acme-corp", "--dest", str(tmp_path)])
    persona_text = (tmp_path / "acme-corp/persona.yaml").read_text()
    assert "REPLACE_ME" not in persona_text
    assert "slug: acme-corp" in persona_text


def test_persona_init_refuses_existing_dest(tmp_path: Path):
    (tmp_path / "acme-corp").mkdir()
    runner = CliRunner()
    result = runner.invoke(
        cli, ["persona", "init", "acme-corp", "--dest", str(tmp_path)]
    )
    assert result.exit_code != 0
    assert "already exists" in (result.output + (result.stderr or ""))


@pytest.mark.parametrize(
    "bad_slug",
    [
        "../etc",
        "../../etc/passwd",
        "/absolute",
        "has space",
        "UpperCase",
        "ALLCAPS",
        "mixed-CASE-slug",
    ],
)
def test_persona_init_rejects_invalid_slug(tmp_path: Path, bad_slug: str):
    runner = CliRunner()
    result = runner.invoke(
        cli, ["persona", "init", bad_slug, "--dest", str(tmp_path)]
    )
    assert result.exit_code == 2
    assert "invalid slug" in (result.output + (result.stderr or ""))
