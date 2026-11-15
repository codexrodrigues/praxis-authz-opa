# Contributing to Praxis Authz OPA

Thank you for contributing to `praxis-authz-opa`.

## Development Baseline

- **Java:** 21+ (`[21,)` enforced by `maven-enforcer-plugin`, compiled with `--release 21`)
- **Maven:** 3.8.0 or newer (`mvn -B clean verify` verified with Maven 3.9+)

Run full local verification before submitting changes:

```powershell
mvn -B clean verify
```

Verify that runtime dependencies stay free of Spring Boot and Hibernate ORM:

```powershell
mvn -B dependency:tree -Dscope=runtime
```

## Module Boundary & Enforcer Rules

`praxis-authz-opa` provides deterministic Rego v1 compilation, bundle assembly, revision guarding, and OPA transport adapters on top of `praxis-authz-contracts` and `praxis-authz-enforcement-core`:

- **Never** add dependencies on `org.springframework.boot:*` or `org.hibernate.orm:*` (`maven-enforcer-plugin` rule `enforce-opa-module-boundary` and CI checks reject them);
- Keep Spring Boot auto-configuration, Spring Web exception mapping, JPA integration, and Actuator readiness in `praxis-authz-starter`;
- Keep persistence-neutral contracts (`CC01–CC12`) and digest calculators in `praxis-authz-contracts`, and keep the 15-step PEP pipeline and JPA/masking adapters in `praxis-authz-enforcement-core`.

## Contract & Release Discipline

- Changes to `RegoV1PolicyCompiler`, `OpaBundleAssembler`, `SameInstanceSearchRevisionGuard`, `OpaAuthorizationProviderAdapter`, or `GovernedOpaReleaseCoordinator` must preserve compatibility with `praxis-authz-contracts` digest preimages and be verified against `praxis-authz-starter`;
- Update Javadoc, `README.md`, and `CHANGELOG.md` whenever compiler output, bundle schemas, or transport error codes change;
- Never commit secrets, GPG material, personal tokens, or environment-specific URLs;
- Do not create release tags manually or run local `mvn deploy`; follow [RELEASING.md](RELEASING.md).
