# Distributed Trust Architecture for AI (DTAI)

DTAI protects model data-encryption keys (DEKs) by splitting the input to the
DEK derivation across two independently administered cloud key authorities.
One authority must use an HSM-backed key in **Azure Key Vault Premium**; the
other must use a different cloud provider and endpoint. Neither 256-bit
contribution is the model DEK.

The workload:

1. starts in an Intel TDX, AMD SEV-SNP, or Azure Confidential VM TEE;
2. creates an ephemeral 3072-bit RSA proof-of-possession key;
3. asks each cloud's attestation client for fresh evidence binding a random
   nonce, model context, key ID, and the ephemeral public key;
4. sends the evidence to each independently configured secure-release
   authority;
5. validates and decrypts both returned contributions only inside the TEE; and
6. derives a 256-bit DEK with HKDF-SHA-256.

The DEK is never stored by either authority and is not written by the module.

## Components

- `DTAI/Dtai.psm1` — configuration validation, secure release orchestration,
  envelope validation, RSA-OAEP-256 unwrapping, and HKDF-SHA-256 derivation.
- `DTAI/dtai.ps1` — CLI wrapper for tools that need a raw 32-byte DEK file.
- `DTAI/config.example.json` — two-authority configuration example.
- `test/Dtai.Tests.ps1` — dependency-free focused tests.

The previous Azure Functions key-rotation template remains available for
operators that still use it; it is not part of the DTAI release path.

## Authority requirements

Deploy one release service in each cloud under separate administrators,
identities, audit sinks, and authorization policies. Each service must:

- validate evidence using its cloud's attestation and secure key release
  facilities, never claims supplied outside signed evidence;
- enforce an allowlist for workload measurement/signing identity, TEE type,
  debug-disabled state, secure boot/platform baseline, model key ID, and
  authorization;
- verify that the evidence binds the request's nonce, `context`, `keyId`, and
  exact recipient JWK, rejecting replayed or expired evidence;
- obtain only its own 32-byte contribution from its cloud KMS;
- wrap that contribution directly to the attested recipient with
  RSA-OAEP-256; and
- return the response below over authenticated HTTPS without logging evidence,
  contributions, ciphertext plaintext, or derived keys.

For the Azure authority, create an exportable HSM-backed key in a Premium Key
Vault with its release policy on the first key version. Grant only
`keys/release`, and restrict the policy to approved Microsoft Azure Attestation
claims. Secure Key Release applies to keys, not Key Vault secrets or
certificates. The second authority must use a different provider's
attestation-gated KMS mechanism.

This client implements a normalized DTAI authority protocol, not the native
Azure `/release` response format. Azure returns a signed object containing a
`key_hsm` blob wrapped with its selected PKCS#11 key-wrap mechanism; that value
is not raw RSA ciphertext. A provider adapter is therefore a deployment
prerequisite. It must preserve recipient-key binding and either run inside the
same TEE or have the authority produce the normalized response directly. It
must never unwrap a contribution outside an attested TEE. If the second
provider only authorizes KMS access through a bearer token and returns
plaintext over TLS, use an attestation-aware release broker to meet DTAI's
stronger recipient-binding requirement.

The release response is:

```json
{
  "protocol": "DTAI-SKR-v1",
  "authority": "authority-azure",
  "provider": "azure-key-vault",
  "keyId": "https://example.vault.azure.net/keys/dtai-k1/version",
  "nonce": "base64url-request-nonce",
  "recipientThumbprint": "base64url-RFC7638-thumbprint",
  "issuedAt": "2026-09-14T16:27:20Z",
  "ciphertext": "base64url-RSA-OAEP-256-ciphertext"
}
```

The authority values, key ID, nonce, recipient thumbprint, and freshness are
checked before a contribution is accepted.

## Configuration

Copy `DTAI/config.example.json`, then:

1. replace `DerivationSalt` with at least 16 random bytes encoded as Base64;
2. configure exactly two HTTPS endpoints on different hosts;
3. set the Azure provider to `azure-key-vault`, SKU to `Premium`, and use a
   versioned Key Vault key ID;
4. set the second authority to a different provider; and
5. keep `MaxReleaseAgeSeconds` as short as operationally practical (30–900).

The salt is not secret, but it must remain stable for a given encrypted model.
Use a stable, unambiguous context such as `model://publisher/name/version`.
Changing the salt, context, key IDs, authority order, or either contribution
produces a different DEK.

## Use

For in-process use (preferred), import the module and provide an attestation
callback that receives the exact challenge to place in signed runtime data:

```powershell
Import-Module ./DTAI/Dtai.psm1
$config = Get-Content ./dtai.json -Raw | ConvertFrom-Json
$dek = Invoke-DtaiKeyRelease -Configuration $config `
    -Context 'model://publisher/name/v1' `
    -AttestationProvider $attestationProvider
try {
    # Decrypt and load model weights inside the TEE.
}
finally {
    [Array]::Clear($dek)
}
```

For command-line integrations, the attestation executable receives the
authority name as its first argument and the challenge JSON on standard input.
It must write only the signed evidence token/document to standard output:

```powershell
./DTAI/dtai.ps1 -ConfigurationPath ./dtai.json `
  -AttestationCommand /opt/dtai/get-attestation `
  -Context 'model://publisher/name/v1' `
  -OutputPath /dev/shm/model.dek
```

Run the CLI only inside the attested TEE. Put the output on a TEE-protected
memory filesystem, consume it immediately, and delete it after loading the
model. The CLI refuses to overwrite a file and creates it with mode `0600` on
Unix.

## Test

PowerShell 7.4 or newer is required.

```powershell
pwsh -NoLogo -NoProfile -File ./test/Dtai.Tests.ps1
```
