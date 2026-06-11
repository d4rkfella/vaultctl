import time
from typing import Any

import hvac
import typer

from vaultctl.commands.restore_raft_snapshot import restore_raft_snapshot
from vaultctl.options import (
    AddressOption,
    AwsAccessKeyIdOption,
    AwsEndpointUrlOption,
    AwsProfileOption,
    AwsRegionOption,
    AwsSecretAccessKeyOption,
    CACertOption,
    CAPathOption,
    S3BucketNameOption,
    S3KeyPrefixOption,
    SkipVerifyOption,
    SnapshotFileOption,
    SnapshotNameOption,
    SnapshotNameRegexOption,
    TimeoutOption,
)

app = typer.Typer()

AUTO_UNSEAL_MAX_ATTEMPT = 10


@app.command(
    help="Init, unseal and force restore a hashicorp vault cluster from S3 storage using raft snapshots",
)
def bootstrap(  # noqa: PLR0913
    ctx: typer.Context,
    address: AddressOption,
    s3_bucket_name: S3BucketNameOption = None,
    snapshot_file: SnapshotFileOption = None,
    *,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    skip_verify: SkipVerifyOption = False,
    s3_key_prefix: S3KeyPrefixOption = "",
    filename: SnapshotNameOption = None,
    filename_regex: SnapshotNameRegexOption = None,
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    timeout: TimeoutOption = 30,
) -> None:
    if not s3_bucket_name and not snapshot_file:
        msg = "Either --s3-bucket-name or --snapshot-file is required"
        raise typer.BadParameter(msg)
    client = hvac.Client(
        url=address,
        timeout=timeout,
        verify=(
            str(ca_cert) if ca_cert else str(ca_path) if ca_path else (not skip_verify)
        ),
    )

    if not client.sys.is_initialized():
        typer.echo("Vault is not initialized. Starting bootstrap procedure...")
        seal_status: dict[str, Any] = client.sys.read_seal_status()
        seal_type = seal_status["type"]

        is_kms = seal_type != "shamir"

        if is_kms:
            typer.echo(
                f"Detected Auto-Unseal ({seal_type}). Initializing with recovery keys...",
            )
            result = client.sys.initialize(recovery_shares=5, recovery_threshold=3)
            typer.echo("Successfully initialized with Auto-Unseal.")
        else:
            typer.echo("Detected Shamir seal. Initializing with secret shares...")
            result = client.sys.initialize(secret_shares=5, secret_threshold=3)
            typer.echo("Successfully initialized with Shamir seal.")

        root_token = result["root_token"]
        client.token = root_token

        if not is_kms:
            typer.echo("Unsealing with Shamir keys...")
            keys = result["keys"]
            client.sys.submit_unseal_keys(keys)
        else:
            typer.echo("Waiting for Auto-Unseal to complete...")
            attempts = 0
            while client.sys.is_sealed() and attempts < AUTO_UNSEAL_MAX_ATTEMPT:
                time.sleep(1)
                attempts += 1

            if client.sys.is_sealed():
                typer.echo(
                    "Error: Vault is still sealed after Auto-Unseal init. Check Vault logs.",
                )
                raise typer.Exit(code=1)

        typer.echo("Vault is unsealed and ready. Starting restore...")

        restore_raft_snapshot(
            ctx=ctx,
            address=address,
            ca_cert=ca_cert,
            ca_path=ca_path,
            skip_verify=skip_verify,
            s3_bucket_name=s3_bucket_name,
            snapshot_file=snapshot_file,
            s3_key_prefix=s3_key_prefix,
            filename=filename,
            filename_regex=filename_regex,
            aws_profile=aws_profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_endpoint_url=aws_endpoint_url,
            aws_region=aws_region,
            force_restore=True,
            timeout=timeout,
            token=root_token,
        )
    else:
        typer.echo("Vault already initialized. Skipping bootstrap procedure.")
