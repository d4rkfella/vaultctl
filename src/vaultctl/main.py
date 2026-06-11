import typer

from vaultctl.commands.backup_raft_snapshot import app as backup_raft_snapshot
from vaultctl.commands.bootstrap import app as bootstrap
from vaultctl.commands.login import app as login
from vaultctl.commands.pki.rotate_issuing import app as pki
from vaultctl.commands.restore_raft_snapshot import app as restore_raft_snapshot
from vaultctl.version import app as version

app = typer.Typer(no_args_is_help=True)

app.add_typer(version)
app.add_typer(bootstrap)
app.add_typer(restore_raft_snapshot)
app.add_typer(backup_raft_snapshot)
app.add_typer(login)
app.add_typer(pki)


if __name__ == "__main__":
    app()
