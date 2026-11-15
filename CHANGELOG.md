# Histórico de Alterações (Changelog)

Todas as mudanças relevantes de `praxis-authz-opa` são documentadas neste arquivo.

O formato segue o padrão [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Adicionado
- Publicação beta inicial no Maven Central de `io.github.codexrodrigues:praxis-authz-opa:0.1.0-beta.1`.
- Compilador determinístico `RegoV1PolicyCompiler` e `CompiledRegoUnit` gerando módulos `import rego.v1` com checagens de presença de fatos em 6 estados (`input.facts["..."].status == "PRESENT"`) e Estágios `1–5` de `PolicyDigestChain`.
- `OpaBundleAssembler`, `OpaBundleArtifact` e `OpaBundleDataDocument` gerando `praxis/authz/system/combining.rego`, rejeitando atribuições concorrentes (`P38`) e calculando `COMPOSITION_DIGEST`, `POLICY_SET_DIGEST` e `BUNDLE_ARTIFACT_DIGEST` (Estágios `6–8`).
- `OpaAuthorizationProviderAdapter` implementando `AuthorizationProviderPort` (`evaluateTarget`, `evaluateSearch`) sobre `OpaClientTransport` com comportamento *fail-closed* para respostas `undefined` e timeouts do OPA (`P18`, `P20`).
- `HttpClientOpaTransport` (roteamento com instância fixada, verificação de `X-OPA-Instance-Id` e timeouts limitados) e `DeterministicLocalOpaTransport` (motor local em memória com injeção determinística de falhas).
- `SameInstanceSearchRevisionGuard` executando o handshake de revisão em 3 etapas em `SEARCH` (`search_preflight -> compile_data_scope -> runtime_head`, retentativa limitada na mesma instância e tolerância zero entre instâncias diferentes).
- `GovernedOpaReleaseCoordinator`, `PolicyCandidateVerificationCorpusCase` e `PolicyCandidateActivationReceipt` impondo `POLICY_ADMIN_PUBLISH`, paridade de `definitionFingerprint` e verificação positiva/negativa anti-`denyAll`.
- Pipeline Maven reprodutível com `flatten-maven-plugin`, fontes/Javadoc, assinatura GPG e regras `maven-enforcer-plugin` proibindo `org.springframework.boot:*` e `org.hibernate.orm:*`.
