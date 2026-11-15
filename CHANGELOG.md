# Changelog

All notable changes to `praxis-authz-opa` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Added
- Initial Maven Central beta publication of `io.github.codexrodrigues:praxis-authz-opa:0.1.0-beta.1`.
- Deterministic `RegoV1PolicyCompiler` and `CompiledRegoUnit` generating strict `import rego.v1` policy modules with 6-state fact presence checks and Stages `1–5` of `PolicyDigestChain`.
- `OpaBundleAssembler`, `OpaBundleArtifact`, and `OpaBundleDataDocument` generating `praxis/authz/system/combining.rego`, rejecting competing policy unit assignments (`P38`), and computing `COMPOSITION_DIGEST`, `POLICY_SET_DIGEST`, and `BUNDLE_ARTIFACT_DIGEST` (Stages `6–8`).
- `OpaAuthorizationProviderAdapter` implementing `AuthorizationProviderPort` (`evaluateTarget`, `evaluateSearch`) over `OpaClientTransport` with fail-closed handling for undefined OPA responses and timeouts (`P18`, `P20`).
- `HttpClientOpaTransport` (pinned instance routing + `X-OPA-Instance-Id` verification + bounded `Duration` timeouts) and `DeterministicLocalOpaTransport` (in-memory OPA conformance engine with deterministic fault-injection hooks).
- `SameInstanceSearchRevisionGuard` implementing the 3-step `SEARCH` revision handshake (`search_preflight -> compile_data_scope -> runtime_head`, bounded same-instance retry, zero cross-instance tolerance).
- `GovernedOpaReleaseCoordinator`, `PolicyCandidateVerificationCorpusCase`, and `PolicyCandidateActivationReceipt` enforcing `POLICY_ADMIN_PUBLISH` authority, `definitionFingerprint` parity, and positive/negative anti-`denyAll` corpus verification.
- Reproducible Maven release pipeline with `flatten-maven-plugin`, source/Javadoc packaging, GPG signing, and Maven Enforcer rules banning `org.springframework.boot:*` and `org.hibernate.orm:*`.
