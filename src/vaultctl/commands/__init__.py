import typer

from vaultctl.commands.backup_raft_snapshot import app as backup_raft_snapshot
from vaultctl.commands.bootstrap import app as bootstrap
from vaultctl.commands.login import app as login
from vaultctl.commands.restore_raft_snapshot import app as restore_raft_snapshot

app = typer.Typer()

app.add_typer(bootstrap)
app.add_typer(restore_raft_snapshot)
app.add_typer(backup_raft_snapshot)
app.add_typer(login)
