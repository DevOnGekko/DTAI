# DTAI Agent

Local model encrypt/decrypt demo with an optional **test-only** attestation leg
that runs a real SEV-SNP / TDX → Microsoft Azure Attestation (MAA) → Azure Key
Vault Secure Key Release. The attestation leg is illustrative — local PFX keys do
the actual decryption — and is off unless a vault and key are configured.

## Evidence files are required (and git-ignored)

The `Attestation/Evidence/` files are **not committed** — they're excluded in
`.gitignore` on purpose (not shared). You must supply them locally to run the
real attestation path:

| Type | Files |
|------|-------|
| SEV-SNP | `snp-report.b64url`, `vcek-cert-chain.b64url`, `runtime-data.json` |
| TDX | `tdx-quote.b64url`, `tdx-runtime-data.b64url` |

They are Azure's public `AttestSevSnpVm` / `AttestTdxVm` samples (attestation
evidence, no secrets). Without them the build still succeeds, but the real
attestation path throws a missing-file error at runtime. The demo encrypt/decrypt
(no attestation) works without them.

## Run — SEV-SNP (works end-to-end against the shared MAA endpoint)

1. Put the SEV-SNP Evidence files above in `Attestation/Evidence/`.
2. Configure a local, git-ignored override with an HSM-backed **exportable** Key
   Vault key whose release policy allows `x-ms-attestation-type == sevsnpvm`:

   **Attestation/attestation.settings.local.json**
   ```json
   { "AttestationType": "SevSnpVm", "KeyVaultName": "<your-premium-vault>", "KeyName": "<your-exportable-key>" }
   ```
   (or set `DTAI_ATTESTATION_TYPE=SevSnpVm` + `DTAI_ATTESTATION_KEYVAULTNAME` /
   `DTAI_ATTESTATION_KEYNAME`). Auth uses `DefaultAzureCredential` — sign in with
   `az login`, VS, or interactively.

3. Run the demo; the `decrypt` step runs the attestation leg:
   ```powershell
   cd tools/Dtai.Agent
   dotnet run -- generate .
   dotnet run -- encrypt -Model model001.safetensors -DEK dek-plain.txt
   dotnet run -- decrypt -EncryptedDEK encrypted-dek.txt -EncryptedModel e-model001.safetensors
   ```

Expected attestation output:
```
  [maa] attesting SevSnpVm at https://sharedwus.wus.attest.azure.net/attest/SevSnpVm?api-version=2022-08-01
  [maa] token verified: signature OK, issuer https://sharedwus.wus.attest.azure.net, expires ...
  [maa] x-ms-attestation-type: sevsnpvm
  [kv] release authorized by MAA token; received wrapped key (<n>-char JWE)
```

The MAA token is verified locally (signature via MAA's `/certs` JWKS, issuer,
lifetime); Key Vault re-verifies it and releases only when the token's claims
satisfy the key's release policy.

## TDX note

`AttestationType` defaults to `TdxVm`. A TDX quote relies on Intel PCS collateral
MAA fetches out-of-band and that must be current, so the public TDX sample is
rejected live with `InvalidQuote` (the decrypt logs a warning and continues). The
request shaping and verification are identical to SEV-SNP — a fresh quote from a
real TDX CVM (or a provider with staged collateral) is required. Use `SevSnpVm`
for the self-contained end-to-end path.

## Tests

```powershell
dotnet test tools/Dtai.Agent.Tests
```
