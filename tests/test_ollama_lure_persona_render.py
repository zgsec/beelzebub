"""Asserts ollama-11434.yaml renders cleanly against crestfield persona — no raw Jinja, no hardcoded persona strings, no blank-placeholder bugs."""
import subprocess
from pathlib import Path

REPO = Path("/home/dev/projects/beelzebub")
RENDERED = REPO / "out/crestfield-data-systems/placeholder/persona/lures/ollama-11434.yaml"
BASE_SRC = REPO / "configurations/services/ollama-11434.yaml"
OVERLAY_SRC = REPO / "personas/crestfield-data-systems/lures/ollama-11434.yaml"

def _render():
    subprocess.run(
        ["bzb", "persona", "render", "crestfield-data-systems", "placeholder"],
        cwd=REPO, check=True, capture_output=True,
    )

def test_renders_no_raw_jinja():
    _render()
    text = RENDERED.read_text()
    # ${request.*}, ${time.*}, ${session.*}, ${captured.*}, ${OLLAMA_CANARY_*}
    # are runtime substitutions resolved at sensor startup — fine to leave.
    # Raw {{ ... }} Jinja MUST be fully resolved at render time.
    assert "{{" not in text, f"unrendered Jinja in rendered output"

def test_no_hardcoded_in_source():
    """Source templates must not have hardcoded persona-coupled strings — they must
    reference coherence.world.* instead. Checks both base template and overlay."""
    for src_path in (BASE_SRC, OVERLAY_SRC):
        text = src_path.read_text()
        # These literals must be expressed via world references, not hardcoded
        forbidden = [
            "/home/aruiz",      # kubeconfig path — use world.people.platform_admin_2.kubeconfig_path
            "Denver",           # old default hq — use world.company.hq_city
            "CDF_ENV",          # env-var prefix — derive from world.org.dd_scope
            "persona.identity.hq",           # deprecated key that doesn't exist in base
            "persona.identity.internal_domain",  # deprecated — use world.company.internal_domain
            "persona.lure_content.platform_display_name",  # deprecated — use world.product.platform_display_name
            "persona.lure_content.db_app_user",             # deprecated — use world.org.aws_iam_user
        ]
        for needle in forbidden:
            assert needle not in text, f"hardcoded/deprecated {needle!r} in source {src_path.name}"

def test_hq_city_renders_to_boston():
    """The persona.identity.hq blank-placeholder bug must be fixed — Crestfield is in Boston."""
    text = RENDERED.read_text()
    assert "Boston" in text, "hq_city did not render to Boston"
    # And the wrong placeholder isn't there
    assert "infra team at  " not in text, "blank hq placeholder still rendering"
    assert "infra team at ()" not in text, "blank hq placeholder still rendering"
    # dd_scope-derived env var renders correctly
    assert "CRESTFIELD_PROD_ENV=production" in text, "dd_scope env var did not render correctly"
