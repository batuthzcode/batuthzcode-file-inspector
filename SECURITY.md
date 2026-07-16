# Security policy

## Scope

THZCodeSpair File Inspector is a static triage tool. It does not claim to prove that a file is safe and it is not a replacement for an isolated malware-analysis laboratory.

## Handling untrusted files

- Never double-click or execute a sample to test a finding.
- Keep the project and its dependencies patched.
- Use a disposable virtual machine for genuinely hostile samples.
- Do not mount shared host directories while investigating live malware.
- Verify report paths before sharing; reports may contain sensitive strings found in the sample.

The application reads files, calculates hashes and uses parsers. It never imports target files as Python modules, extracts archive contents, opens document viewers or invokes a shell with sample-controlled text.

## Reporting a vulnerability

Please use GitHub Security Advisories for vulnerabilities in this project. Include:

1. affected version or commit;
2. minimal reproduction steps;
3. security impact;
4. suggested mitigation, if available.

Do not attach real malware to a public issue. Use harmless synthetic fixtures or hashes.
