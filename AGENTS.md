# Repository instructions

Maintain Japanese documentation and executable detection content organized by ATT&CK and log source.
Read docs/daily.md and docs/deployment.md before adding rules. All new rules start experimental.
Never execute attack commands or fetch malware. Use inert synthetic events for tests.
Preserve provenance and upstream licensing when adapting content.
Run python tools/build.py and python -m unittest discover -s tests -v before committing.
Do not claim production validation based on synthetic tests or claim a whole technique is covered.

Target SIEM is Splunk Enterprise / Splunk Cloud Platform. Embed detection and investigation SPL
inside docs/rules/*.md; do not create standalone queries/*.spl files.
Use symbolic condition operators (= and ~=) in JSON, evaluator and readable rule formulas.
Every rule needs official tactic IDs/names, parent technique, sub-technique, mapping rationale,
and a distinction between primary detection hypothesis and other official tactic positions.
Verify current MITRE STIX IDs; record the pinned source in data/attack.json when extending it.
References must include title, URL, summary explaining relevance, and accessed date.
Write rule-specific investigation steps with fields, time/entity correlation, benign criteria and
escalation evidence. Explain specific blind spots and compensating telemetry, not generic warnings.
