"""Deterministic SHA256 over a directory tree."""
import hashlib
from pathlib import Path


def sha256_of_tree(root: Path) -> str:
    """SHA256 of every file in the tree, ordered lexicographically by relative path."""
    h = hashlib.sha256()
    root = Path(root).resolve()
    files: list[tuple[str, Path]] = []
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            files.append((rel, p))
    for rel, abs_path in sorted(files):
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(abs_path.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()
