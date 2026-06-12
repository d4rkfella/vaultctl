import importlib.metadata

import typer

app = typer.Typer()


def _get_version() -> str:
    try:
        return importlib.metadata.version("vaultctl")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


@app.command()
def version() -> None:
    print(f"vaultctl {_get_version()}")  # noqa: T201
