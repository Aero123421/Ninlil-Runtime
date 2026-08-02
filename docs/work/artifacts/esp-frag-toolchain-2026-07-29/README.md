# ESP FRAG toolchain failure evidence (environment, not FRAG size gate)

Captured host-side Docker/Colima compile failures before Ninlil FRAG
source/link evaluation. Do **not** use these as FRAG DRAM/size acceptance.

- `frag_on_build*.log`: mbedtls / esp_partition ICE / OOM under parallel ninja
- Official re-run deferred until semantic P0/P1 close; use pinned digest + `-j1` + clean ccache.

Keep `sdkconfig.defaults.r7_frag_on` in smoke_app as formal config when present.
