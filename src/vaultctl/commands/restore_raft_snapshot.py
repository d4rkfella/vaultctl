from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import botocore.exceptions
import hvac
import typer
from dateutil.parser import parse as parse_datetime
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
    S3BucketNameOption,
    S3KeyPrefixOption,
    SkipVerifyOption,
    SnapshotFileOption,
    SnapshotForceRestoreOption,
    SnapshotNameOption,
    SnapshotNameRegexOption,
    TimeoutOption,
    TokenOption,
)
from vaultctl.utils import handle_s3_authentication, handle_vault_authentication, logger

if TYPE_CHECKING:
    import re
    from collections.abc import Mapping, Sequence

app = typer.Typer()


def select_snapshot(
    contents: Sequence[Mapping[str, object]],
    filename_regex: re.Pattern | None,
) -> str:
    if filename_regex:
        valid_objects = []

        for o in contents:
            key = o.get("Key")
            if not isinstance(key, str):
                continue

            match = filename_regex.match(key)
            if not match:
                continue

            ts_str = match.group(1)
            try:
                ts = parse_datetime(ts_str)
                valid_objects.append({"Key": key, "Timestamp": ts})
            except ValueError:
                continue

        if not valid_objects:
            msg = "No valid snapshots found matching the filename regex with parseable timestamp"
            raise ValueError(
                msg,
            )

        latest_obj = max(valid_objects, key=lambda o: cast("datetime", o["Timestamp"]))
        return cast("str", latest_obj["Key"])

    valid_objects = [
        o
        for o in contents
        if isinstance(o.get("Key"), str) and isinstance(o.get("LastModified"), datetime)
    ]
    if not valid_objects:
        msg = "No valid snapshots with LastModified found"
        raise RuntimeError(msg)

    latest_obj = max(valid_objects, key=lambda o: cast("datetime", o["LastModified"]))
    return cast("str", latest_obj["Key"])


@app.command(help="Restore a HashiCorp Vault cluster from an S3 Raft snapshot.")
def restore_raft_snapshot(  # noqa: C901, PLR0912, PLR0913, PLR0915
    address: AddressOption,
    s3_bucket_name: S3BucketNameOption = None,
    snapshot_file: SnapshotFileOption = None,
    k8s_role: K8sRoleOption = None,
    k8s_mount_point: K8sMountPointOption = "kubernetes",
    filename: SnapshotNameOption = None,
    filename_regex: SnapshotNameRegexOption = None,
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    s3_key_prefix: S3KeyPrefixOption = "",
    token: TokenOption = None,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    timeout: TimeoutOption = 30,
    *,
    force_restore: SnapshotForceRestoreOption = False,
    skip_verify: SkipVerifyOption = False,
) -> None:
    if not s3_bucket_name and not snapshot_file:
        msg = "Either --s3-bucket-name or --snapshot-file is required"
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

    if snapshot_file:
        logger.info("Reading snapshot from %s...", snapshot_file)
        snapshot_data = Path(snapshot_file).read_bytes()
    else:
        s3_bucket_name = cast("str", s3_bucket_name)
        s3_client = handle_s3_authentication(
            bucket_name=s3_bucket_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_region=aws_region,
            aws_profile=aws_profile,
            endpoint_url=aws_endpoint_url,
        )

        if filename:
            s3_key = f"{s3_key_prefix}{filename}"
            logger.info("Using snapshot: %s", s3_key)
        else:
            logger.info("Selecting latest snapshot from S3...")

            try:
                list_response = s3_client.list_objects_v2(
                    Bucket=s3_bucket_name,
                    Prefix=s3_key_prefix,
                )
            except botocore.exceptions.ClientError:
                logger.exception("Listing S3 bucket contents")
                raise typer.Exit(1) from None

            if list_response.get("KeyCount", 0) == 0:
                logger.error(
                    "No snapshots found in bucket '%s' with prefix '%s'.",
                    s3_bucket_name,
                    s3_key_prefix,
                )
                raise typer.Exit(1)

            contents = list_response.get("Contents", [])
            try:
                s3_key = select_snapshot(contents, filename_regex)
            except (ValueError, RuntimeError):
                logger.exception("Selecting snapshot")
                raise typer.Exit(1) from None

            logger.info("Selected snapshot: %s", s3_key)

        logger.info("Downloading snapshot from S3: %s...", s3_key)

        try:
            download_response = s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
            snapshot_data = download_response["Body"].read()
        except botocore.exceptions.ClientError:
            logger.exception("Downloading snapshot")
            raise typer.Exit(1) from None

        logger.info("Snapshot downloaded.")

    raft = Raft(adapter=vault_client.adapter)

    if force_restore:
        logger.warning("Restoring snapshot with force...")
        try:
            raft.force_restore_raft_snapshot(snapshot_data)
        except (VaultError, InvalidRequest):
            logger.exception("Restoring snapshot")
            raise typer.Exit(1) from None
    else:
        logger.info("Restoring snapshot...")
        try:
            raft.restore_raft_snapshot(snapshot_data)
        except (VaultError, InvalidRequest):
            logger.exception("Restoring snapshot")
            raise typer.Exit(1) from None

    logger.info("Snapshot restored.")
    logger.info("Restore completed")
