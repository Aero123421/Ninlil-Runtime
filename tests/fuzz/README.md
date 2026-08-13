# Decoder fuzzing

The six harnesses in this directory are private, opt-in libFuzzer targets for
the untrusted decoder boundaries named in the project charter review. They are
not installed and are not part of the default build.

Configure with Clang, sanitizers, and the private R7/route-relay candidates:

```sh
cmake -S . -B build/fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DNINLIL_ENABLE_SANITIZERS=ON \
  -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON \
  -DNINLIL_BUILD_DECODER_FUZZERS=ON
cmake --build build/fuzz --target ninlil_decoder_fuzzers
python3 tools/decoder_fuzz_seed_corpus.py generate \
  --output build/fuzz/corpus
```

Each corpus is generated from the existing checked-in JSON or independent C
KAT vectors. `manifest.json` records the exact source, byte count, and SHA-256
of every seed. CI runs all six fuzzers concurrently for five minutes each.

When a crash is fixed, place the minimized input under
`tests/fuzz/regressions/<target>/` and keep it there. The generator includes
those files in the corresponding corpus, so the crash becomes a permanent
regression input without adding another test framework. No crash corpus is
currently claimed.
