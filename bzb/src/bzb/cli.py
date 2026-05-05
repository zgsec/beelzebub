"""bzb — honeynet persona deployment CLI."""
import click


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Deploy, rotate, and validate honeynet persona bundles."""


@cli.group()
def persona():
    """Persona bundle operations."""


@cli.group()
def rotate():
    """Rotate canaries or personas."""


@cli.group()
def aggregator():
    """Aggregator-side operations."""


@cli.group()
def test():
    """Validation: capture, replay, e2e."""


# Wire in subcommands
from bzb.commands.persona_init import persona_init
from bzb.commands.persona_render import persona_render
from bzb.commands.persona_validate import persona_validate

persona.add_command(persona_init)
persona.add_command(persona_render)
persona.add_command(persona_validate)


from bzb.commands.deploy import deploy
from bzb.commands.status import status
from bzb.commands.rotate import canary as rotate_canary
from bzb.commands.rotate import persona_cmd as rotate_persona
from bzb.commands.teardown import teardown

cli.add_command(deploy)
cli.add_command(status)
cli.add_command(teardown)

rotate.add_command(rotate_canary)
rotate.add_command(rotate_persona, name="persona")


if __name__ == "__main__":
    cli()
