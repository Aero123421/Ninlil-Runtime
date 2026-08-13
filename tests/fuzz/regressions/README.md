# Minimized crash regressions

This directory is intentionally empty until a real decoder fuzz crash is
fixed. Store a minimized reproducer under a directory named for its corpus:

- `nfl1_codec/`
- `rrmp_codec/`
- `r7_wire_codec/`
- `r7_frag_wire/`
- `n6_record_codec/`
- `domain_store_body_codec/`

`tools/decoder_fuzz_seed_corpus.py` copies every non-hidden file in those
directories into the generated seed corpus and pins its SHA-256 in the corpus
manifest. Do not add synthetic placeholder crashes.
