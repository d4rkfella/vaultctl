import typer

app = typer.Typer()


@app.command()
def version() -> None:
    print("vaultctl 0.1.0")  # noqa: T201
