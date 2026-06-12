from __future__ import annotations

import datetime
import hashlib
import io
import tarfile
from enum import Enum
from pathlib import Path
from typing import Annotated

import hvac
import typer
from botocore.exceptions import ClientError
from requests import Response

from vaultctl.options import (
    AddressOption,
    AwsAccessKeyIdOption,
    AwsEndpointUrlOption,
    AwsProfileOption,
    AwsRegionOption,
    AwsSecretAccessKeyOption,
    BackupDestinationOption,
    CACertOption,
    CAPathOption,
    K8sMountPointOption,
    K8sRoleOption,
    SkipVerifyOption,
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


class RaftUploadError(Exception):
    """Raised when uploading a Raft snapshot to S3 fails."""


class S3ChecksumAlgorithm(Enum):
    CRC32 = "CRC32"
    CRC32C = "CRC32C"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    CRC64NVME = "CRC64NVME"


def parse_sha256sums(content: bytes) -> dict[str, str]:
    sums = {}
    lines = content.strip().split(b"\n")
    for line in lines:
        trimmed_line = line.strip()
        if not trimmed_line:
            continue
        parts = trimmed_line.split()
        if len(parts) == 2:  # noqa: PLR2004
            checksum = parts[0].decode("utf-8")
            filename = parts[1].decode("utf-8")
            sums[filename] = checksum
    return sums


def verify_internal_checksums(snapshot_data: bytes) -> None:
    logger.info("Verifying snapshot integrity...")
    snapshot_stream = io.BytesIO(snapshot_data)

    try:
        with tarfile.open(fileobj=snapshot_stream, mode="r:gz") as tar:
            sha_sums_content = None
            files_in_tar: dict[str, bytes] = {}

            for member in tar.getmembers():
                if not member.isfile():
                    continue

                if not (f := tar.extractfile(member)):
                    continue

                content = f.read()

                if member.name == "SHA256SUMS":
                    sha_sums_content = content

                files_in_tar[member.name] = content

            if sha_sums_content is None:
                msg = "SHA256SUMS file not found in the snapshot archive."
                raise ValueError(
                    msg,
                )

            expected_sums = parse_sha256sums(sha_sums_content)

            for name, expected_sum in expected_sums.items():
                content = files_in_tar.get(name)

                if content is None:
                    msg = f"file '{name}' listed in SHA256SUMS not found in archive."
                    raise ValueError(
                        msg,
                    )

                computed_sum = hashlib.sha256(content).hexdigest()

                if computed_sum != expected_sum:
                    msg = f"checksum mismatch for file '{name}'. Expected: {expected_sum}, Got: {computed_sum}"
                    raise ValueError(
                        msg,
                    )

            logger.info("Snapshot integrity verified.")

    except tarfile.TarError as e:
        msg = f"reading archive: {e}"
        raise tarfile.TarError(msg) from e


@app.command(
    help="Executes a complete workflow for obtaining a HashiCorp Vault Raft snapshot, verifying its integrity, and saving it to a local path or S3 URI. Provides flexible authentication options for both HashiCorp Vault and S3 APIs.",
)
def backup_raft_snapshot(  # noqa: PLR0913
    address: AddressOption,
    destination: BackupDestinationOption = None,
    k8s_role: K8sRoleOption = None,
    k8s_mount_point: K8sMountPointOption = "kubernetes",
    k8s_sa_token_path: Path = Path(
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    ),
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    s3_checksum_algorithm: Annotated[
        S3ChecksumAlgorithm,
        typer.Option(help="The algorithm to use for s3 transport checksum."),
    ] = S3ChecksumAlgorithm.CRC64NVME,
    token: TokenOption = None,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    timeout: TimeoutOption = 30,
    *,
    skip_verify: SkipVerifyOption = False,
) -> None:
    if not destination:
        msg = "--to is required"
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
        k8s_token_path=k8s_sa_token_path,
    )

    if vault_client.sys.is_sealed():
        logger.error("Vault is sealed. Cannot proceed with backup.")
        raise typer.Exit(code=1)

    logger.info("Starting backup...")

    logger.info("Requesting snapshot...")
    response: Response = vault_client.sys.take_raft_snapshot()

    if response.status_code != 200:  # noqa: PLR2004
        logger.error(
            "Snapshot request failed with status code %s.",
            response.status_code,
        )
        logger.debug("Response body: %s", response.text)
        raise typer.Exit(1)

    snapshot_data: bytes = response.content

    logger.info("Snapshot retrieved.")

    try:
        verify_internal_checksums(snapshot_data)
    except tarfile.TarError, ValueError:
        logger.exception("Verifying snapshot integrity")
        raise typer.Exit(1) from None

    if not is_s3_uri(destination):
        output_path = Path(destination)
        if output_path.is_dir():
            timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d_%H%M%S")
            output_path = output_path / f"vault-snapshot-{timestamp}.snap"
        output_path.write_bytes(snapshot_data)
        logger.info("Snapshot written to %s", output_path)
    else:
        s3_bucket, s3_key = parse_s3_uri(destination)

        if not s3_key or s3_key.endswith("/"):
            timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d_%H%M%S")
            snapshot_name = f"vault-snapshot-{timestamp}.snap"
            s3_key = f"{s3_key}{snapshot_name}"

        s3_client = handle_s3_authentication(
            bucket_name=s3_bucket,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_region=aws_region,
            aws_profile=aws_profile,
            endpoint_url=aws_endpoint_url,
        )

        try:
            logger.info("Uploading snapshot to %s/%s...", s3_bucket, s3_key)
            s3_client.upload_fileobj(
                io.BytesIO(snapshot_data),
                s3_bucket,
                s3_key,
                ExtraArgs={
                    "ContentType": "application/gzip",
                    "ChecksumAlgorithm": s3_checksum_algorithm.value,
                },
            )
            logger.info("Snapshot uploaded.")
        except ClientError:
            logger.exception("Uploading snapshot")
            raise typer.Exit(1) from None

    logger.info("Backup completed successfully.")
