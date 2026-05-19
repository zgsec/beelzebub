"""Every active persona must define a complete coherence.world block."""
import yaml
from pathlib import Path

REPO = Path("/home/dev/projects/beelzebub")

REQUIRED_PATHS = [
    ("coherence", "world", "company", "display_name"),
    ("coherence", "world", "company", "public_domain"),
    ("coherence", "world", "company", "internal_domain"),
    ("coherence", "world", "company", "hq_city"),
    ("coherence", "world", "product", "service_name"),
    ("coherence", "world", "product", "platform_display_name"),
    ("coherence", "world", "product", "platform_version"),
    ("coherence", "world", "org", "k8s_namespace"),
    ("coherence", "world", "org", "aws_iam_user"),
    ("coherence", "world", "org", "db_app_user"),
    ("coherence", "world", "org", "db_prod_name"),
    ("coherence", "world", "hosts", "gpu_worker_1", "hostname"),
    ("coherence", "world", "hosts", "db_primary", "hostname"),
    ("coherence", "world", "hosts", "docker_registry", "hostname"),
    ("coherence", "world", "hosts", "vault", "hostname"),
    ("coherence", "world", "ports", "ollama", "num"),
    ("coherence", "world", "ports", "mcp_litellm", "num"),
    ("coherence", "world", "watermark_passwords", "ollama"),
    ("coherence", "world", "watermark_passwords_ssh_regex"),
]


def _lookup(d, path):
    for k in path:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def test_all_personas_have_complete_world_block():
    for persona_dir in (REPO / "personas").iterdir():
        if not (persona_dir / "persona.yaml").exists():
            continue
        p = yaml.safe_load((persona_dir / "persona.yaml").read_text())
        for path in REQUIRED_PATHS:
            val = _lookup(p, path)
            assert val is not None and val != "", \
                f"{persona_dir.name} missing {'.'.join(path)}"
