# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-02

Initial public release, accompanying the ESORICS 2026 paper *COD-SSI: Enforcing Mutual Privacy for Credential Oblivious Disclosure in Self Sovereign Identity* and its extended version on [arXiv:2604.10685](https://doi.org/10.48550/arXiv.2604.10685).

### Added

- Self-contained proof-of-concept demo (`src/demo.js`) running the full Holder ↔ Verifier oblivious disclosure protocol, from commitment and encryption to unblinding and re-verification.
- Reference implementation of the protocol (`src/OPRF/main.js`), annotated against Algorithms 1 and 2 of the paper, together with the hash-based claim commitments (`src/OPRF/hashAttributes.js`).
- Benchmarking harness (`src/main.js`) targeting the `did:ethr` credential stack, with protocol and experiment parameters in `src/config.json`.
- Benchmark data backing the paper's experimental evaluation (`performancesData/`): COD-SSI timings for credentials of 2 to 1024 claims (a reduced subset of 100 runs per configuration) and the classical hash-based selective-disclosure baseline.
- Figure-generation notebook (`analysis/PerformanceAnalysis.ipynb`) with a pinned Python environment (`analysis/requirements.txt`).
- Project documentation: `README.md`, the protocol figures, and the CC BY-NC-SA 4.0 `LICENSE`.

[1.0.0]: https://github.com/eOnofri04/COD-ssi/releases/tag/v1.0.0
