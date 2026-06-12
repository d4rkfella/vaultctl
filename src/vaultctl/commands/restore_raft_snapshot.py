from pathlib import Path

import botocore.exceptions
import hvac
import typer
from hvac.api.system_backend import Raft
from hvac.exceptions import InvalidRequest, VaultError

from vaultctl.options import (
    AddressOption,
    AwsAccessKeyIdOption,
    AwsEndpointUrlOption,
    AwsProfileOption,
    AwsRegionOption,
    AwsSecretAccessKeyOption,
    CACertOption,
    CAPathOption,
    K8sMountPointOption,
    K8sRoleOption,
    RestoreSourceOption,
    SkipVerifyOption,
    SnapshotForceRestoreOption,
    TimeoutOption,
    TokenOption,
)
from vaultctl.utils import (
    handle_s3_authentication,
    handle_vault_authentication,
    is_s3_uri,
    logger,
    parse_s3_uri,
)

app = typer.Typer()


@app.command(
    help="Restore a HashiCorp Vault cluster from a Raft snapshot (S3 or local).",
)
def restore_raft_snapshot(  # noqa: PLR0913
    address: AddressOption,
    source: RestoreSourceOption = None,
    k8s_role: K8sRoleOption = None,
    k8s_mount_point: K8sMountPointOption = "kubernetes",
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    token: TokenOption = None,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    timeout: TimeoutOption = 30,
    *,
    force_restore: SnapshotForceRestoreOption = False,
    skip_verify: SkipVerifyOption = False,
) -> None:
    if not source:
        msg = "--from is required"
        raise typer.BadParameter(msg)

    vault_client = handle_vault_authentication(
        hvac.Client(
            url=address,
            timeout=timeout,
            verify=(
                str(ca_cert)
                if ca_cert
                else str(ca_path)
                if ca_path
                else (not skip_verify)
            ),
        ),
        token=token,
        k8s_role=k8s_role,
        k8s_mount_point=k8s_mount_point,
    )

    if vault_client.sys.is_sealed():
        logger.error("Vault is sealed. Cannot proceed.")
        raise typer.Exit(code=1)

    if not is_s3_uri(source):
        snapshot_path = Path(source)
        if snapshot_path.is_dir():
            msg = "--from must be a file path, not a directory"
            raise typer.BadParameter(msg)
        logger.info("Reading snapshot from %s...", snapshot_path)
        snapshot_data = snapshot_path.read_bytes()
    else:
        s3_bucket, s3_key = parse_s3_uri(source)
        if not s3_key or s3_key.endswith("/"):
            msg = "S3 URI must point to a specific object, not a prefix"
            raise typer.BadParameter(msg)

        logger.info("Getting snapshot from S3: %s...", s3_key)
        s3_client = handle_s3_authentication(
            bucket_name=s3_bucket,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_region=aws_region,
            aws_profile=aws_profile,
            endpoint_url=aws_endpoint_url,
        )

        try:
            download_response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
            snapshot_data = download_response["Body"].read()
        except botocore.exceptions.ClientError:
            logger.exception("Getting snapshot from S3")
            raise typer.Exit(1) from None

        logger.info("Snapshot downloaded successfully.")

    raft = Raft(adapter=vault_client.adapter)

    logger.info("Restoring snapshot...")

    if force_restore:
        logger.warning("Force restore is ENABLED !")
        try:
            raft.force_restore_raft_snapshot(snapshot_data)
        except VaultError, InvalidRequest:
            logger.exception("Restoring snapshot")
            raise typer.Exit(1) from None
    else:
        try:
            raft.restore_raft_snapshot(snapshot_data)
        except VaultError, InvalidRequest:
            logger.exception("Restoring snapshot")
            raise typer.Exit(1) from None

    logger.info("Snapshot restored successfully!")
