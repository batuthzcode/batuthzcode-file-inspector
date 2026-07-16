# Contributing

1. Open an issue describing the proposed behavior.
2. Create a focused branch.
3. Add or update tests for detection changes.
4. Run `pytest` before opening a pull request.
5. Never commit live malware, credentials, API keys or proprietary samples.

YARA rules must include a description and severity in `meta`, use narrow conditions to reduce false positives, and have a harmless synthetic test fixture.
