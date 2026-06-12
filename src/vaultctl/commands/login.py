from pathlib import Path
from typing import Annotated, Literal

import hvac
import typer
from hvac.exceptions import InvalidRequest, VaultError
from rich.console import Console
from rich.table import Table

from vaultctl.options import (
    AddressOption,
    CACertOption,
    CAPathOption,
    SkipVerifyOption,
)


def format_lease_duration(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours}h{minutes}m{secs}s"


TOKEN_FILE = Path.home() / ".vault-token"

app = typer.Typer()


@app.command(help="Authenticate with Vault and optionally save the token.")
def login(  # noqa: C901, PLR0913
    ctx: typer.Context,  # noqa: ARG001
    address: AddressOption,
    *,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    skip_verify: SkipVerifyOption = False,
    method: Annotated[
        Literal["token", "userpass"],
        typer.Option(help="Auth method: token (default) or userpass"),
    ] = "token",
    no_store: Annotated[
        bool,
        typer.Option(help="Do not persist the token to disk", is_flag=True),
    ] = False,
    params: Annotated[
        list[str] | None,
        typer.Argument(
            help="Auth parameters as key=value, like username=alice password=foo",
        ),
    ] = None,
) -> None:
    kv = {}
    if params:
        for p in params:
            if "=" not in p:
                msg = f"Invalid argument '{p}', expected key=value"
                raise typer.BadParameter(msg)
            k, v = p.split("=", 1)
            kv[k] = v

    client = hvac.Client(
        url=address,
        verify=(
            str(ca_cert) if ca_cert else str(ca_path) if ca_path else (not skip_verify)
        ),
    )

    username = kv.get("username")
    password = kv.get("password")
    token = kv.get("token")

    try:
        if method == "token":
            if not token:
                token = typer.prompt(
                    "Token (will be hidden)",
                    hide_input=True,
                    type=str,
                )
            client.token = token
            lookup = client.auth.token.lookup_self()
            token_info = lookup["data"]

        elif method == "userpass":
            if not username:
                username = typer.prompt("Username", type=str)
            if not password:
                password = typer.prompt(
                    "Password (will be hidden)",
                    hide_input=True,
                    type=str,
                )
            auth_resp = client.auth.userpass.login(username=username, password=password)
            token_info = auth_resp["auth"]
            client.token = token_info.get("client_token")

    except (VaultError, InvalidRequest) as e:
        typer.secho(f"Vault Error: {e}", fg="red", err=True)
        raise typer.Exit(code=1) from None

    token = token_info.get("client_token") or token_info.get("id")
    accessor = token_info.get("accessor", "n/a")
    ttl = token_info.get("lease_duration") or token_info.get("ttl", 0)
    renewable = token_info.get("renewable", False)
    metadata = token_info.get("metadata") or token_info.get("meta") or {}

    if not no_store and client.token:
        TOKEN_FILE.write_text(client.token)

    console = Console()
    table = Table("Key", "Value")
    table.add_row("token", token)
    table.add_row("token_accessor", accessor)
    table.add_row("token_duration", format_lease_duration(ttl))
    table.add_row("token_renewable", str(renewable))
    table.add_row("token_policies", str(token_info.get("token_policies", [])))
    table.add_row("identity_policies", str(token_info.get("identity_policies", [])))
    table.add_row("policies", str(token_info.get("policies", [])))
    table.add_row("token_meta_username", metadata.get("username", "n/a"))
    console.print(table)
