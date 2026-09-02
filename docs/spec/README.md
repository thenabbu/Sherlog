# SAT-SA replication specification set

These files are the implementation contract for SAT-SA v0.1.0 as it exists in this repository. Together they are intended to let another team reproduce the same command-line program, storage layout, analytics, evidence records, resource behaviour, and validation process without needing to infer behaviour from a demo.

Read in this order:

1. [01 — Product and architecture](01-product-and-architecture.md): scope, boundaries, components, and repository layout.
2. [02 — Data and storage contract](02-data-and-storage-contract.md): every table, field, validation rule, and produced file.
3. [03 — CLI and operating workflows](03-cli-and-workflows.md): exact commands, argument defaults, and observable command behaviour.
4. [04 — Analytics and evidence](04-analytics-and-evidence.md): detector equations, scoring, benchmarking, and JSON output contracts.
5. [05 — Streaming and adaptive runtime](05-streaming-and-adaptive-runtime.md): batch processing, multiprocessing, resource tuning, and health checks.
6. [06 — Build, test, validation, and deployment](06-build-test-and-deployment.md): packages, offline installation, tests, and release checks.
7. [07 — Module implementation blueprint](07-module-implementation-blueprint.md): file-by-file responsibilities and callable interfaces.
8. [08 — Streamlit supervisory workbench](08-streamlit-workbench.md): presentation design, artifact binding, pipeline controls, and UI acceptance checks.

## Normative language

**MUST** means required to reproduce current behaviour. **SHOULD** means advisable for operational quality but not required for byte-for-byte equivalence. **MAY** indicates an optional extension.

## Version boundary

This is a local/offline MVP with a CLI core and optional Streamlit presentation layer. It does not implement live log collection, streaming telemetry, an SIEM, user authentication, cloud services, hosted models, free-text NLP, or machine-learning anomaly detection.
