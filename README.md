# Audit Evidence Engine

Evaluate whether a control register has owned, current, available, and unaltered artifacts ready for auditor review. Suitable for internal IT audit preparation and evidence tracking alongside an ISO management-system audit program.

## Run

Python 3.12+, no runtime dependencies:

```sh
python audit_evidence.py register.example.json --evidence-root . --as-of 2026-10-20
python -m unittest discover -v
```

The sample register intentionally has evidence gaps and exits 1. It uses organization-defined control IDs, not copied standards text. Map IDs to your licensed standard and approved Statement of Applicability in your own register.

## Evidence contract

Each applicable control has an `owner`, an organization-defined `max_age_days`, and an `evidence` list. Each evidence entry contains `path`, `collected_on` (ISO calendar date), and a lowercase SHA-256 digest. Every declared artifact must pass. Example entry:

```json
{"path": "access-review.csv", "collected_on": "2026-10-01", "sha256": "replace_with_the_64_character_sha256_of_your_artifact"}
```

Excluded controls need an owner and `exclusion_reason`. An exclusion rationale must still be reviewed by an authorized auditor. Duplicate IDs and evidence paths fail rather than being silently merged.

## Results

`gap` includes a precise issue list: missing owner/evidence/artifact, stale or future evidence, hash mismatch, or unjustified exclusion. `excluded` means a rationale is recorded. `ready_for_review` means the declared evidence passed mechanical checks. Neither status establishes control design, operating effectiveness, certification readiness, or standards compliance.

The CLI requires a fixed `--as-of` date for reproducibility. Evidence exactly at the configured maximum age is accepted; older evidence is flagged. The engine streams artifact hashes and rejects paths outside the evidence root, symlinks, and junctions. Keep the register trusted and the evidence tree immutable during review; the path checks are not a defense against concurrent hostile filesystem changes.

## Workflow

Agree control applicability and age thresholds, export the register, collect copied artifacts into an isolated evidence root, record their trusted digests, then evaluate. Investigate gaps and have the auditor assess relevance, sufficiency, authenticity, and effectiveness. This tool does not infer those judgments from a file's existence.
