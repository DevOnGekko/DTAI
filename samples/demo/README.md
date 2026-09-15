# Local file demo fixtures

**Never use these files for real models.** The two PFX files and the DEK are
intentionally public test material. Sharing both PFX files does not provide
independent-authority enforcement.

`model001.safetensors` is a format-valid toy F32 `[1]` tensor. `dek-plain.txt`
is Base64 text for a random 32-byte AES-256 key (no newline). The PFX password
is `dtai-demo-only`. These fixtures are deliberately separate from the
production attestation/TEE multi-authority HKDF protocol.

Regenerate six fresh fixtures without overwriting any existing fixture:

```shell
dotnet run --project tools/Dtai.DemoGenerator -- samples/demo
```

Delete the existing fixtures first; the generator refuses to overwrite them.
