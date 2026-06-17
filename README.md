<!--
==================================================
Giulio Golinelli - golinelli.giulio13@gmail.com
TUMCREATE QUASAR RESEARCH ENGINEER
Modified: 2026-06-17
This file contains modifications vs. the upstream
CVA6 / ML-DSA-OSH source fork.
==================================================
-->

# ML-DSA-OSH (Quasar-NRF fork)

Fork of [`KULeuven-COSIC/ML-DSA-OSH`](https://github.com/KULeuven-COSIC/ML-DSA-OSH),
the open-source hardware implementation of **ML-DSA** ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)),
the NIST post-quantum digital signature standard. The original design is
based on Beckwith et al., [IACR ePrint 2021/1451](https://eprint.iacr.org/2021/1451).

This fork is consumed as a git submodule by the parent system
integration repository
[`quasar-NRF/cva6-mldsa`](https://github.com/quasar-NRF/cva6-mldsa),
which wires the accelerator into a CVA6 RISC-V SoC on the Genesys2 FPGA
via a memory-mapped AXI bridge.

## Why this fork exists

The upstream accelerator works standalone, but the AXI bridge +
accelerator combination exposed two issues that needed source-level
fixes. Both fixes are commented in-line (`// TUMCREATE ...`) at the
change sites.

### 1. `ref_combined/src/decoder.v` — T0 decoder stall (commit `44d1d2b`)

When the bridge's `out_ready` is deasserted mid-burst, the decoder's
shift-register would advance without a corresponding load, corrupting
the streaming output. Fix: gate the shift enable on bridge
backpressure so a not-ready bridge freezes the decoder state machine
without breaking standalone draining.

### 2. `ref_combined/src/combined_top.v` — `VY_COMPARE` output (commit `5345974`)

For Verify mode the spec defines a single fail bit (FIPS 204
`UseHint`-based verification). The original combined top was emitting a
multi-bit diagnostic vector that broke the bridge's pass/fail detector.
Fix: revert `VY_COMPARE` to the baseline single-fail-bit output so the
bridge reads exactly one bit for VALID/INVALID.

All other changes in this fork are limited to the two files above
(plus a few related pipeline/FIFO-depth tweaks in `combined_top.v`
needed for the Sign phase to drain cleanly under backpressure — see the
commit message of `44d1d2b` for the full list).

## Test status

All three phases (KeyGen, Sign, Verify) pass the NIST KAT vectors at
security level 3, both standalone and through the AXI bridge. See the
parent repo's `CVA6_MLDSA_INTEGRATION.md` § 2 for the per-phase pass
table.

## Layout

```
ML-DSA-OSH/
├── ref_combined/
│   ├── src/         # Verilog + VHDL accelerator sources (modified here)
│   └── src_tb/      # original testbenches (modified for sim driver)
├── common/          # shared params (mldsa_params.v, zetas.txt)
└── KAT/             # NIST Known Answer Test vectors
```

## Upstream attribution

Original design © KU Leuven COSIC (MIT license). See upstream
`LICENSE` for full terms. This fork's changes are released under the
same MIT license.

## Author

Giulio Golinelli — `golinelli.giulio13@gmail.com`
TUMCREATE — QUASAR Research Engineer

## References

- FIPS 204, *Module-Lattice Digital Signature Algorithm*,
  [NIST (2024)](https://doi.org/10.6028/NIST.FIPS.204).
- Beckwith et al., *NTT Multiplication for NTT-Unfriendly Rings…*,
  [IACR ePrint 2021/1451](https://eprint.iacr.org/2021/1451).
- Parent system repo: <https://github.com/quasar-NRF/cva6-mldsa>.
