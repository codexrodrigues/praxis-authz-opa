# Praxis Authz OPA Provider & Materializer

Deterministic Rego v1 policy compiler, signed OPA bundle assembler, same-instance `SEARCH` revision guard, and OPA decision provider adapter for the Praxis Authorization Decision Platform.

## Highlights

- **Deterministic Compilation:** `RegoV1PolicyCompiler` and `OpaBundleAssembler` compile `AuthorizationPolicyDefinition` models into reproducible Rego v1 units and OPA bundle manifests.
- **Provider Integration:** `OpaAuthorizationProviderAdapter` bridges `AuthorizationProviderPort` over HTTP (`HttpClientOpaTransport`) or embedded verification (`DeterministicLocalOpaTransport`).
- **Revision & Search Consistency:** `SameInstanceSearchRevisionGuard` ensures multi-phase `SEARCH` queries bind Phase 1 filtering and Phase 2 item reads to a verified revision.
- **Governed Release Coordination:** `GovernedOpaReleaseCoordinator` runs verification corpora before candidate activation.

## Maven Coordinates

```xml
<dependency>
    <groupId>io.github.codexrodrigues</groupId>
    <artifactId>praxis-authz-opa</artifactId>
    <version>0.1.0-beta.1</version>
</dependency>
```

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
