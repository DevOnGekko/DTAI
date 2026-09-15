# Local file demo fixtures

**Never use these files for real models.** The two PFX files and the DEK are
intentionally public test material. Sharing both PFX files does not provide
independent-authority enforcement.

`model001.safetensors` is a format-valid toy F32 `[1]` tensor. `dek-plain.txt`
is Base64 text for a random 32-byte AES-256 key (no newline). The PFX password
is `dtai-demo-only`; override it with `DTAI_K1_PFX_PASSWORD` and
`DTAI_K2_PFX_PASSWORD` for freshly generated fixtures.

Regenerate six fresh fixtures without overwriting any existing fixture:

```shell
dotnet run --project tools/Dtai.DemoGenerator -- samples/demo
```

Run `./verify-demo.sh` after building, or copy a published `DTAI.exe` here and
set `DTAI_BIN=./DTAI.exe`. Remove `e-model001.safetensors`,
`encrypted-dek.txt`, `result-dek.txt`, and `result-model001.safetensors`
before rerunning. The local demo is deliberately separate from the production
attestation/TEE multi-authority HKDF protocol.
