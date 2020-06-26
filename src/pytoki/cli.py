import click

import pytoki


@click.command()
@click.version_option(version=pytoki.__version__)
def main():
    click.echo("Pytoki>")
