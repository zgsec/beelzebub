"""Strict-undefined Jinja2 environment for renderer."""
from jinja2 import Environment, StrictUndefined


def make_env() -> Environment:
    return Environment(
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
        trim_blocks=False,
        lstrip_blocks=False,
    )
