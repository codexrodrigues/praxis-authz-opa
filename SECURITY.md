# Política de Segurança (`praxis-authz-opa`)

`praxis-authz-opa` compila políticas de autorização para OPA Rego v1, calcula digests canônicos de bundles em 8 estágios, protege consultas `SEARCH` contra deriva de revisão entre instâncias e condiciona ativações à aprovação em corpus positivo e negativo. Defeitos relevantes de segurança devem ser tratados com discrição e responsabilidade.

## Reportando uma Vulnerabilidade

**Não** abra issues públicas no GitHub contendo payloads de exploração, definições reais de políticas corporativas, credenciais, tokens, chaves privadas ou detalhes de clientes.

Envie o relato em canal privado ao mantenedor via **GitHub Security Advisories** (`codexrodrigues/praxis-authz-opa`), incluindo:

- Versão, tag ou hash de commit afetado;
- Componente envolvido (`RegoV1PolicyCompiler`, `OpaBundleAssembler`, `SameInstanceSearchRevisionGuard`, `HttpClientOpaTransport`, `DeterministicLocalOpaTransport` ou `GovernedOpaReleaseCoordinator`);
- Passos mínimos de reprodução sem credenciais ou dados reais;
- Impacto de segurança observado (ex.: injeção em Rego, aceitação permissiva de `undefined`, contorno do guarda *split-brain* de revisão ou bypass do gate de corpus).

## Invariantes de Segurança por Design

- **Rego v1 Estrito e Unidades Não Concorrentes:** `RegoV1PolicyCompiler` valida o AST contra limites fechados e emite `import rego.v1`; `OpaBundleAssembler` rejeita colisões de `policyUnitKey` ou `policyId` (`P38`);
- **Transporte OPA Fail-Closed:** Ausência de `result` (`AUTHZ_OPA_UNDEFINED_RESULT`), timeouts (`AUTHZ_OPA_TIMEOUT`) e roteamento para instância desconhecida (`AUTHZ_OPA_UNKNOWN_INSTANCE`) falham fechado (`P18`, `P20`);
- **Consistência de Revisão na Mesma Instância em `SEARCH`:** `SameInstanceSearchRevisionGuard` tolera apenas rotação benigna limitada na mesma instância (`0..3`) e aborta imediatamente sem retry se `X-OPA-Instance-Id` mudar entre preflight e postflight (`P17`);
- **Ativação Verificada por Corpus:** `GovernedOpaReleaseCoordinator` exige `POLICY_ADMIN_PUBLISH`, `definitionFingerprint` fixado e casos positivos + negativos aprovados (`P53`, `P55`, `P63`).

## Higiene de Credenciais e Releases

- Nunca comite tokens Maven Central, GitHub PATs, chaves GPG ou credenciais TLS/OPA;
- Todas as releases oficiais aguardam `praxis-authz-contracts` e `praxis-authz-enforcement-core` e executam apenas em CI (veja [RELEASING.md](RELEASING.md)).
