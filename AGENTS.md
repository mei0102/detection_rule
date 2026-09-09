# Repository instructions

Maintain Japanese documentation and executable detection content organized by ATT&CK and log source.
Read docs/daily.md and docs/deployment.md before adding rules. All new rules start experimental.
Never execute attack commands or fetch malware. Use inert synthetic events for tests.
Preserve provenance and upstream licensing when adapting content.
Run python tools/build.py and python -m unittest discover -s tests -v before committing.
Do not claim production validation based on synthetic tests or claim a whole technique is covered.
