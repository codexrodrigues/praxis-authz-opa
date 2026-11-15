# AGENTS.md — Praxis Authz OPA

## Escopo e Herança

- Aplica-se a todo o repositório `praxis-authz-opa`.
- Herda as diretrizes do `AGENTS.md` da raiz do monorepo Praxis (`praxis-plataform`), adicionando as regras locais deste módulo.

## Fronteira Canônica

- Este artefato pertence à camada `decisionKind = AUTHORIZATION` da **Praxis Decision Platform** e é dono exclusivamente da compilação determinística para OPA Rego v1 (`RegoV1PolicyCompiler`), montagem de bundles com digests em 8 estágios (`OpaBundleAssembler`), adapter `OpaAuthorizationProviderAdapter`, transportes `HttpClientOpaTransport` / `DeterministicLocalOpaTransport`, guarda de revisão em `SEARCH` (`SameInstanceSearchRevisionGuard`) e coordenação de publicação por corpus (`GovernedOpaReleaseCoordinator`).
- **Proibido** introduzir dependências de Spring Boot (`org.springframework.boot:*`) ou Hibernate ORM (`org.hibernate.orm:*`) neste módulo (`maven-enforcer-plugin` falha o build e o CI rejeita qualquer violação em `target/runtime-dependencies.txt`).
- Auto-configuração Spring Boot, endpoints HTTP, bridges de metadata (`AbstractAuthzGovernedResourceService`) e outbox JDBC pertencem exclusivamente a `praxis-authz-starter`.
- O repositório deve funcionar de forma autônoma no GitHub Actions, consumindo `praxis-authz-contracts` e `praxis-authz-enforcement-core` publicados no Maven Central (ou instalados no fluxo local autorizado).

## Invariantes de Segurança e Contrato

- Mantenha geração estrita com `import rego.v1` e validação de presença de fatos 6-state (`status == "PRESENT"`).
- Nunca degrade resultado `undefined`, timeout HTTP, instância desconhecida ou divergência de `instanceId` no `SameInstanceSearchRevisionGuard` para decisão permissiva: todo erro de transporte ou revisão deve falhar fechado (*fail-closed*).
- Alterações em schemas de entrada/saída (`praxis.opa-target-input/v1`, `praxis.opa-search-input/v1`, `praxis.opa-target-result/v1`, `praxis.opa-ucast-result/v1`) exigem sincronização com `praxis-authz-contracts` e atualização de `README.md` / `CHANGELOG.md`.

## Validação e Economia de GitHub Actions

- Use Java 21 e Maven 3.9+ com `mvn -B clean verify`.
- Não execute `mvn deploy` localmente nem crie tags `v*` sem seguir a ordem multi-repositório (`contracts -> enforcement-core -> opa -> starter`).
- Consulte [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md) e [RELEASING.md](RELEASING.md) antes de qualquer dispatch de workflow.
