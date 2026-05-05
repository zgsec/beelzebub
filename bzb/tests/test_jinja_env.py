import pytest
from jinja2 import UndefinedError

from bzb.render.jinja_env import make_env


def test_strict_undefined_raises():
    env = make_env()
    tmpl = env.from_string("{{ persona.does_not_exist }}")
    with pytest.raises(UndefinedError):
        tmpl.render(persona={"slug": "x"})


def test_normal_substitution_works():
    env = make_env()
    tmpl = env.from_string("hello {{ persona.slug }}")
    assert tmpl.render(persona={"slug": "world"}) == "hello world"


def test_no_html_autoescape():
    """We render text/yaml/conf, not HTML — autoescape would break things."""
    env = make_env()
    tmpl = env.from_string("{{ s }}")
    assert tmpl.render(s="<not-html>") == "<not-html>"
