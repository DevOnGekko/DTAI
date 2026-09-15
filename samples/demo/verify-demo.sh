#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
run() {
  if [ -n "${DTAI_BIN:-}" ]; then "$DTAI_BIN" "$@"; else dotnet run --project ../../src/Dtai.Cli -- "$@"; fi
}
run encrypt -Model model001.safetensors -DEK dek-plain.txt
run decrypt -EncryptedDEK encrypted-dek.txt -EncryptedModel e-model001.safetensors
cmp dek-plain.txt result-dek.txt
cmp model001.safetensors result-model001.safetensors
printf '\033[32mDemo comparisons succeeded.\033[0m\n'
