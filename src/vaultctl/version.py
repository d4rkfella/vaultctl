import typer

app = typer.Typer()


@app.command()
def version() -> None:
    print("vaultctl 0.2.1")  # noqa: T201
