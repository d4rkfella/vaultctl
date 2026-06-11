import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, cast

import boto3
import botocore.exceptions
import typer
import validators
from hvac.exceptions import InvalidRequest, VaultError

if TYPE_CHECKING:
    import hvac
    from mypy_boto3_s3 import S3Client


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("vaultctl")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s"),
        )
        logger.addHandler(handler)
    return logger


logger = _setup_logger()


def parse_regex(value: str) -> re.Pattern:
    """Parse and validate a regex pattern."""
    try:
        return re.compile(value)
    except re.error as e:
        msg = f"Invalid regex: {e}"
        raise typer.BadParameter(msg) from e


def validate_s3_key_prefix(
    value: str,
) -> str:
    """Validate S3 key prefix format."""
    if not value:
        return ""
    if value.startswith("/"):
        msg = "S3 key prefix must not start with '/'. Example: backups/2026/"
        raise typer.BadParameter(
            msg,
        )

    pattern = re.compile(r"^[A-Za-z0-9/_\-.]+$")
    if not pattern.match(value):
        msg = (
            "S3 key prefix contains invalid characters. "
            "Allowed: letters, numbers, '/', '-', '_', '.'"
        )
        raise typer.BadParameter(
            msg,
        )

    if not value.endswith("/"):
        value = value + "/"

    return value


def validate_address(
    ctx: typer.Context,  # noqa: ARG001
    param: object,  # noqa: ARG001
    value: str,
) -> str:
    if value == "https://127.0.0.1:8200":
        logger.warning(
            "VAULT_ADDR and --address unset. Defaulting to https://127.0.0.1:8200.",
        )
    elif not validators.url(value):
        msg = f"Invalid Vault address URL: {value!r}"
        raise typer.BadParameter(msg) from None
    return value


def handle_vault_authentication(
    client: hvac.Client,
    token: str | None,
    k8s_role: str | None = None,
    k8s_mount_point: str = "kubernetes",
    k8s_token_path: Path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token"),
) -> hvac.Client:
    token_filepath = Path.home() / ".vault-token"

    if token:
        client.token = token
        return client

    if token_filepath.exists() and (saved_token := token_filepath.read_text().strip()):
        client.token = saved_token
        return client

    if k8s_role:
        logger.info("Attempting Kubernetes Auth for role: %s...", k8s_role)

        if not k8s_token_path.exists():
            logger.error(
                "K8s token file not found at %s.",
                k8s_token_path,
            )
            raise typer.Exit(code=1)

        jwt = k8s_token_path.read_text().strip()

        try:
            client.auth.kubernetes.login(
                role=k8s_role,
                jwt=jwt,
                mount_point=k8s_mount_point,
            )
        except InvalidRequest, VaultError:
            logger.exception("Kubernetes Auth Failed")
            raise typer.Exit(code=1) from None
        else:
            return client

    logger.error("Vault client authentication failed.")
    raise typer.Exit(code=1)


def handle_s3_authentication(  # noqa: PLR0913
    bucket_name: str,
    *,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_session_token: str | None = None,
    aws_region: str | None = None,
    aws_profile: str | None = None,
    endpoint_url: str | None = None,
) -> S3Client:
    logger.info("Initializing S3 client...")

    s3_client: S3Client | None = None

    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=aws_region,
        profile_name=aws_profile,
    )
    s3_client = cast(
        "S3Client",
        session.client("s3", endpoint_url=endpoint_url),
    )

    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as e:
        msg = e.response.get("Error", {}).get("Message", "Unknown S3 Error")
        logger.exception("S3 Head Bucket failed: %s", msg)
        raise typer.Exit(code=1) from None
    except (
        botocore.exceptions.NoCredentialsError,
        botocore.exceptions.PartialCredentialsError,
    ):
        logger.exception("S3 authentication failed")
        raise typer.Exit(code=1) from None

    logger.info("S3 client initialized.")
    return s3_client
