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

- `tools/Dtai.DemoGenerator` — the only code project in this repository and the
  sole project in `Dtai.sln`. It generates the deliberately public,
  **demo-only** fixtures under `samples/demo`.

The architecture below documents the DTAI protocol this repository targets. No
protocol implementation is currently kept in this repository.

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

## AWS secondary trust authority

Set the second authority's `Provider` to `aws-kms` to use AWS for secondary
trust. AWS authorities are validated and called with AWS-specific operations:

- `Region` is required and must be a valid AWS region such as `us-east-1`;
- `KeyId` must be an AWS KMS key or alias ARN in that same region; and
- `SigningService` is optional and defaults to `execute-api`; set it to the
  service name that fronts the release endpoint.

Requests to an AWS authority must be signed with AWS Signature Version 4 over
the exact release request body, so the authority can authorize the caller with
IAM and reject tampered or replayed request bodies. Credentials come from the
standard `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional
`AWS_SESSION_TOKEN` environment variables, which is what an instance, task, or
enclave parent role provides. SigV4 only authorizes transport; the contribution
is still accepted only after the DTAI envelope's nonce, key ID, recipient
thumbprint, and freshness checks pass.

The AWS authority is expected to validate an AWS Nitro Enclaves attestation
document, call KMS with the attested recipient (`Recipient` /
`CiphertextForRecipient` attestation-gated release), and return the normalized
`DTAI-SKR-v1` response below with the contribution wrapped directly to the
request's recipient JWK using RSA-OAEP-256.

The release response is:

```json
{
  "protocol": "DTAI-SKR-v1",
  "authority": "authority-aws",
  "provider": "aws-kms",
  "keyId": "arn:aws:kms:us-east-1:123456789012:key/dtai-k2",
  "nonce": "base64url-request-nonce",
  "recipientThumbprint": "base64url-RFC7638-thumbprint",
  "issuedAt": "2026-09-14T16:27:20Z",
  "ciphertext": "base64url-RSA-OAEP-256-ciphertext"
}
```

The authority values, key ID, nonce, recipient thumbprint, and freshness are
checked before a contribution is accepted.

## Configuration

Create a DTAI configuration JSON file, then:

1. replace `DerivationSalt` with at least 16 random bytes encoded as Base64;
2. configure exactly two HTTPS endpoints on different hosts;
3. set the Azure provider to `azure-key-vault`, SKU to `Premium`, and use a
   versioned Key Vault key ID;
4. set the second authority to a different provider, such as `aws-kms` with a
   `Region`, a matching KMS key ARN, and an optional `SigningService`, or
   `google-cloud-kms` with a versioned Cloud KMS crypto key ID and a
   `GoogleAudience` accepted by its release service; and
5. keep `MaxReleaseAgeSeconds` as short as operationally practical (30–900).

The salt is not secret, but it must remain stable for a given encrypted model.
Use a stable, unambiguous context such as `model://publisher/name/version`.
Changing the salt, context, key IDs, authority order, or either contribution
produces a different DEK.

For a Google Cloud secondary authority, deploy the normalized release service
on a Google workload that can access only its Cloud KMS contribution. The
default client obtains an identity token from the Google metadata service for
`GoogleAudience` and presents it as a bearer token to that service. The service
must validate the token and attestation evidence before using Cloud KMS, then
return the normalized response with the contribution encrypted directly to the
recipient JWK. Do not return a plaintext Cloud KMS decrypt result to the
workload.

## Build

The demo generator requires the .NET 8.0 SDK or newer.

```shell
dotnet build Dtai.sln
```

`Dtai.sln` contains `tools/Dtai.DemoGenerator/Dtai.DemoGenerator.csproj` as its
only project.

## Demo tool

`tools/Dtai.DemoGenerator` builds as an executable assembly named `DTAI` while
retaining the project directory name. On Windows, normal build/publish apphost
output uses `DTAI.exe`.

### Fixture generation

The tool writes six local fixtures: `model001.safetensors`, `dek-plain.txt`,
`K1-public.pem`, `K1.pfx`, `K2-public.pem`, and `K2.pfx`. It preserves the
original invocation shape: no argument writes to the current directory, and one
non-command argument writes to that output directory. The explicit command is
also supported:

```shell
dotnet run --project tools/Dtai.DemoGenerator -- generate samples/demo
```

The generator creates the output directory if needed and refuses to overwrite
any existing fixture, so delete the previous files first when regenerating.

`model001.safetensors` is a format-valid toy F32 `[1]` tensor. `dek-plain.txt`
is Base64 text encoding exactly 32 random bytes. K1 is 3072-bit RSA and K2 is
4096-bit RSA; both PFX files use the password `dtai-demo-only`.

### Local encryption/decryption demo

Run the demo from `samples/demo`, where the default `K1`/`K2` public PEM and PFX
files are resolved from the current working directory:

```shell
DTAI.exe encrypt -Model model001.safetensors -DEK dek-plain.txt
DTAI.exe decrypt -EncryptedDEK encrypted-dek.txt -EncryptedModel e-model001.safetensors
```

`encrypt` validates that the DEK file is Base64 text for exactly 32 bytes, then
AES-256-GCM encrypts the model with a fresh 12-byte nonce and 16-byte tag. The
output model path is the input model file name prefixed with `e-` in the same
directory; for example, `model001.safetensors` becomes
`e-model001.safetensors`. This file is a DTAI demo encrypted container, not a
loadable safetensors file. Its binary format is: 8-byte magic `DTAIEMOD`,
1-byte version `1`, 1-byte algorithm `1` for AES-256-GCM, 1-byte nonce length,
1-byte tag length, 8-byte little-endian ciphertext length, then nonce, tag, and
ciphertext. The fixed header is authenticated as AES-GCM additional data.
Malformed, unsupported, truncated, or unauthenticated containers are rejected.

`encrypt` also encrypts the original DEK file bytes with `K1-public.pem` using
RSA-OAEP-SHA256, encrypts those raw RSA ciphertext bytes again with
`K2-public.pem` using RSA-OAEP-SHA256, and writes the final Base64 ciphertext to
`encrypted-dek.txt` in the current directory. The inner RSA ciphertext is not
Base64 encoded before the outer RSA encryption. The bundled K1 can encrypt up to
318 bytes with OAEP-SHA256, and the bundled K2 can encrypt the 384-byte raw K1
ciphertext because its limit is 446 bytes; larger or incompatible keys fail
clearly instead of changing padding or splitting ciphertext.

`decrypt` reads only `encrypted-dek.txt`, `e-model001.safetensors`, `K2.pfx`,
and `K1.pfx` from the provided/current paths. It writes `result-dek.txt` in the
current directory and writes the authenticated decrypted model as the encrypted
model file name with leading `e-` removed and `result-` prefixed, for example
`result-model001.safetensors`. Authentication is completed before plaintext
outputs are written.

The generated files, including the ones tracked under `samples/demo`, are
deliberately public **demo-only** fixtures. Never use their DEK, PFX private
keys, or shared password for real models. Sharing both PFX files is not
independent-authority enforcement, and this local demo material is **not** the
production DTAI attestation/TEE multi-authority HKDF protocol described above.
