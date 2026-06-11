from typing import TYPE_CHECKING, Annotated

import hvac
import typer
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from hvac.exceptions import InvalidPath, InvalidRequest, VaultError
from requests import Response

from vaultctl.options import (
    AddressOption,
    CACertOption,
    CAPathOption,
    SkipVerifyOption,
    TokenOption,
)
from vaultctl.utils import handle_vault_authentication

if TYPE_CHECKING:
    from typing import Any

app = typer.Typer()


def to_dict(resp: dict[str, Any] | Response | None) -> dict[str, Any]:
    if isinstance(resp, Response):
        return resp.json()
    if resp is None:
        return {}
    return resp


@app.command()
def rotate_issuing(  # noqa: PLR0913
    ctx: typer.Context,  # noqa: ARG001
    address: AddressOption,
    token: TokenOption = None,
    ca_cert: CACertOption = None,
    ca_path: CAPathOption = None,
    *,
    skip_verify: SkipVerifyOption = False,
    iss_mount: Annotated[
        str,
        typer.Option(help="Vault PKI mount path for the target issuer."),
    ],
    int_mount: Annotated[
        str,
        typer.Option(
            help="Vault PKI mount path for the intermediate CA that signs the CSR.",
        ),
    ],
    common_name: Annotated[
        str,
        typer.Option(help="Common name for the new certificate."),
    ],
    ttl: Annotated[
        str,
        typer.Option(help="Time-to-live for the new certificate."),
    ] = "8760h",
    country: Annotated[
        str,
        typer.Option(help="Country name for the certificate subject."),
    ] = "Bulgaria",
    locality: Annotated[
        str,
        typer.Option(help="Locality name for the certificate subject."),
    ] = "Sofia",
    organization: Annotated[
        str,
        typer.Option(help="Organization name for the certificate subject."),
    ] = "DarkfellaNET",
) -> None:
    vault_client = handle_vault_authentication(
        hvac.Client(
            url=address,
            verify=(
                str(ca_cert)
                if ca_cert
                else str(ca_path)
                if ca_path
                else (not skip_verify)
            ),
        ),
        token=token,
    )

    if vault_client.sys.is_sealed():
        typer.secho("Vault is sealed. Cannot proceed..", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

    try:
        typer.echo("Generating CSR using existing key material...")
        generate_resp = to_dict(
            vault_client.write(
                f"{iss_mount}/issuers/generate/intermediate/existing",
                common_name=common_name,
                country=country,
                locality=locality,
                organization=organization,
                format="pem_bundle",
                wrap_ttl=None,
            ),
        )
        csr = generate_resp["data"]["csr"]
    except (VaultError, InvalidRequest) as e:
        typer.echo(f"Failed to generate CSR: {e}")
        raise

    try:
        typer.echo("Signing CSR with intermediate CA...")
        sign_resp = to_dict(
            vault_client.write(
                f"{int_mount}/root/sign-intermediate",
                csr=csr,
                ttl=ttl,
                wrap_ttl=None,
            ),
        )
        signed_cert = sign_resp["data"]["certificate"]
    except (VaultError, InvalidRequest) as e:
        typer.echo(f"Failed to sign CSR: {e}")
        raise

    try:
        typer.echo(f"Importing signed certificate back into {iss_mount}...")
        import_resp = to_dict(
            vault_client.write(
                f"{iss_mount}/intermediate/set-signed",
                certificate=signed_cert,
                wrap_ttl=None,
            ),
        )
        imported_issuers = import_resp.get("data", {}).get("imported_issuers", [])
        if not imported_issuers:
            msg = "Vault did not return an imported issuer ID!"
            raise RuntimeError(msg)
        new_issuer_id = imported_issuers[0]

        vault_client.write(
            f"{iss_mount}/config/issuers",
            default=new_issuer_id,
            wrap_ttl=None,
        )
        typer.echo(f"New issuer {new_issuer_id} set as default")
    except (VaultError, InvalidRequest, InvalidPath) as e:
        typer.echo(f"Failed to import signed certificate: {e}")
        raise

    cert = x509.load_pem_x509_certificate(signed_cert.encode(), default_backend())
    typer.echo("\nNew Issuing CA info:")
    typer.echo(f"  Subject: {cert.subject.rfc4514_string()}")
    typer.echo(f"  Serial: {cert.serial_number}")
    typer.echo(f"  Expires: {cert.not_valid_after.isoformat()} UTC")

    typer.echo("Done! Issuing CA successfully reissued and set as default.")
