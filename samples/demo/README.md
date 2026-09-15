# Local file demo fixtures

**Never use these files for real models.** The two PFX files, their shared
password (`dtai-demo-only`), and the DEK are intentionally public demo-only
material. Sharing both PFX files does not provide independent-authority
enforcement.

`model001.safetensors` is a format-valid toy F32 `[1]` tensor. `dek-plain.txt`
is Base64 text for a random 32-byte AES-256 key (no newline). These fixtures are
deliberately separate from the production attestation/TEE multi-authority HKDF
protocol.

Run from this directory so the default `K1`/`K2` files resolve from the current
working directory:

```shell
DTAI.exe encrypt -Model model001.safetensors -DEK dek-plain.txt
DTAI.exe decrypt -EncryptedDEK encrypted-dek.txt -EncryptedModel e-model001.safetensors
```

`encrypt` writes `e-model001.safetensors`, an encrypted DTAI demo container, not
a directly loadable safetensors file. The container starts with magic
`DTAIEMOD`, version `1`, AES-256-GCM algorithm `1`, nonce/tag lengths, a
little-endian ciphertext length, then the nonce, tag, and ciphertext; the header
is authenticated as AES-GCM additional data. It also writes `encrypted-dek.txt`
by encrypting the original DEK file bytes with K1 RSA-OAEP-SHA256 and then
encrypting the raw K1 ciphertext with K2 RSA-OAEP-SHA256. With the bundled keys,
K1 accepts at most 318 DEK file bytes and K2 accepts the 384-byte K1 ciphertext.

`decrypt` does not need the original model or `dek-plain.txt`. It writes
`result-dek.txt` and `result-model001.safetensors` only after the encrypted model
authenticates.

Regenerate six fresh fixtures without overwriting any existing fixture:

```shell
dotnet run --project ../../tools/Dtai.DemoGenerator -- generate .
```

Delete the existing fixtures first; the generator refuses to overwrite them.
