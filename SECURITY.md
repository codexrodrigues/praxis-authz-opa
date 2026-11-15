# Security Policy

`praxis-authz-opa` compiles authorization policies to OPA Rego v1, computes canonical bundle digests, guards `SEARCH` evaluations against revision drift, and gates release activation against positive and negative verification corpora. Security-relevant defects must be handled responsibly.

## Reporting a Vulnerability

Do **not** open public GitHub issues containing exploit payloads, sensitive policy definitions, credentials, tokens, keys, or customer details.

Report vulnerabilities privately to the repository maintainer via GitHub Security Advisories (`codexrodrigues/praxis-authz-opa`) and include:

- Affected version, tag, or commit hash;
- Component involved (compiler, bundle assembler, `SameInstanceSearchRevisionGuard`, `HttpClientOpaTransport`, `DeterministicLocalOpaTransport`, or `GovernedOpaReleaseCoordinator`);
- Minimal reproduction steps without real credentials or tenant data;
- Security impact (e.g., Rego injection, permissive undefined handling, revision split-brain bypass, or corpus-gate circumvention).

## Security Design Invariants

- **Strict Rego v1 & Non-Competing Units:** `RegoV1PolicyCompiler` validates inputs against bounded AST rules and emits `import rego.v1` units; `OpaBundleAssembler` rejects colliding `policyUnitKey` or `policyId` definitions (`P38`);
- **Fail-Closed OPA Transport:** Missing `result` payloads (`AUTHZ_OPA_UNDEFINED_RESULT`), timeouts (`AUTHZ_OPA_TIMEOUT`), and unknown instance routing (`AUTHZ_OPA_UNKNOWN_INSTANCE`) fail closed (`P18`, `P20`);
- **Same-Instance SEARCH Revision Consistency:** `SameInstanceSearchRevisionGuard` retries bounded same-instance bundle rotations (`0..3`) and fails closed immediately without retry if `X-OPA-Instance-Id` / `instanceId` changes between preflight and postflight (`P17`);
- **Corpus-Verified Release Activation:** `GovernedOpaReleaseCoordinator` requires `POLICY_ADMIN_PUBLISH`, pinned `definitionFingerprint`, and passing positive + negative verification cases (`P53`, `P55`, `P63`).

## Credential & Release Hygiene

- Never commit Maven Central tokens, GitHub PATs, GPG private keys, passphrases, or TLS/OPA credentials;
- All Maven Central releases wait for upstream `praxis-authz-contracts` and `praxis-authz-enforcement-core` artifacts and execute exclusively in CI (see [RELEASING.md](RELEASING.md)).
