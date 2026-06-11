from __future__ import annotations

import datetime
import hashlib
import io
import tarfile
from enum import Enum
from pathlib import Path
from typing import Annotated, cast

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
    CACertOption,
    CAPathOption,
    K8sMountPointOption,
    K8sRoleOption,
    OutputFileOption,
    S3BucketNameOption,
    S3KeyPrefixOption,
    SkipVerifyOption,
    TimeoutOption,
    TokenOption,
)
from vaultctl.utils import handle_s3_authentication, handle_vault_authentication, logger

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
                msg = "SHA256SUMS file not found in the Raft snapshot archive."
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
    help="Executes a complete workflow for obtaining a HashiCorp Vault Raft snapshot from a cluster, verifying its integrity, and uploading it securely to S3 storage. Provides flexible authentication options for both HashiCorp Vault and S3 APIs.",
)
def backup_raft_snapshot(  # noqa: PLR0913
    address: AddressOption,
    s3_bucket_name: S3BucketNameOption = None,
    output_file: OutputFileOption = None,
    k8s_role: K8sRoleOption = None,
    k8s_mount_point: K8sMountPointOption = "kubernetes",
    token: TokenOption = None,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    aws_profile: AwsProfileOption = None,
    aws_access_key_id: AwsAccessKeyIdOption = None,
    aws_secret_access_key: AwsSecretAccessKeyOption = None,
    aws_endpoint_url: AwsEndpointUrlOption = None,
    aws_region: AwsRegionOption = "us-east-1",
    s3_key_prefix: S3KeyPrefixOption = "",
    s3_checksum_algorithm: Annotated[
        S3ChecksumAlgorithm,
        typer.Option(help="The algorithm to use for s3 transport checksum."),
    ] = S3ChecksumAlgorithm.CRC64NVME,
    timeout: TimeoutOption = 30,
    *,
    skip_verify: SkipVerifyOption = False,
) -> None:
    if not s3_bucket_name and not output_file:
        msg = "Either --s3-bucket-name or --output-file is required"
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
        logger.error("Vault is sealed. Cannot proceed with backup.")
        raise typer.Exit(code=1)

    logger.info("Starting backup...")

    logger.info("Requesting raft snapshot...")
    response: Response = vault_client.sys.take_raft_snapshot()

    if response.status_code != 200:  # noqa: PLR2004
        logger.error(
            "Raft snapshot request failed with status code %s.",
            response.status_code,
        )
        logger.debug("Response body: %s", response.text)
        raise typer.Exit(1)

    snapshot_data: bytes = response.content

    logger.info("Raft snapshot retrieved.")

    try:
        verify_internal_checksums(snapshot_data)
    except (tarfile.TarError, ValueError):
        logger.exception("Verifying raft snapshot integrity")
        raise typer.Exit(1) from None

    if output_file:
        output_path = Path(output_file)
        if output_path.is_dir():
            timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d_%H%M%S")
            output_path = output_path / f"vault-snapshot-{timestamp}.snap"
        output_path.write_bytes(snapshot_data)
        logger.info("Snapshot written to %s", output_path)
        logger.info("Backup completed")
        return

    s3_bucket_name = cast("str", s3_bucket_name)

    s3_client = handle_s3_authentication(
        bucket_name=s3_bucket_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_region=aws_region,
        aws_profile=aws_profile,
        endpoint_url=aws_endpoint_url,
    )

    timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d_%H%M%S")
    snapshot_name = f"vault-snapshot-{timestamp}.snap"
    s3_key = f"{s3_key_prefix}{snapshot_name}"

    try:
        logger.info("Uploading raft snapshot to %s/%s...", s3_bucket_name, s3_key)
        s3_client.upload_fileobj(
            io.BytesIO(snapshot_data),
            s3_bucket_name,
            s3_key,
            ExtraArgs={
                "ContentType": "application/gzip",
                "ChecksumAlgorithm": s3_checksum_algorithm.value,
            },
        )
    except ClientError:
        logger.exception("Uploading raft snapshot")
        raise typer.Exit(1) from None

    logger.info("Raft snapshot uploaded.")
    logger.info("Backup completed")
