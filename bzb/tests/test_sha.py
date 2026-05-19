from pathlib import Path

from bzb.render.sha import sha256_of_tree


def test_sha256_deterministic(tmp_path: Path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "x.yaml").write_text("hello\n")
    (a / "sub").mkdir()
    (a / "sub" / "y.txt").write_text("world\n")

    sha1 = sha256_of_tree(a)
    sha2 = sha256_of_tree(a)
    assert sha1 == sha2
    assert len(sha1) == 64


def test_sha256_changes_on_content_change(tmp_path: Path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "x.yaml").write_text("hello\n")
    sha_before = sha256_of_tree(a)
    (a / "x.yaml").write_text("hello world\n")
    assert sha256_of_tree(a) != sha_before


def test_sha256_path_independent(tmp_path: Path):
    """Identical content under different parent paths produces same SHA."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "x.yaml").write_text("hello\n")
    assert sha256_of_tree(a) == sha256_of_tree(b)
