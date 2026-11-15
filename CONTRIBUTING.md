# Como Contribuir com `praxis-authz-opa`

Contribuições para `praxis-authz-opa` devem manter a emissão determinística de Rego v1, o alinhamento criptográfico dos 8 estágios de digest e o isolamento de frameworks Web/ORM.

## Baseline de Desenvolvimento

- **Java:** 21 (`--release 21`, `-Xlint:all,-serial`, `[21,)` no Enforcer)
- **Apache Maven:** `3.8.0+` no `pom.xml` (recomendado `3.9.0+` em toda a família Authz)

Execute a verificação completa e inspecione a árvore de dependências de runtime:

```powershell
mvn -B clean verify
mvn -B dependency:tree -Dscope=runtime
```

## Princípios de Contribuição (`BND-OWN-004`)

1. **Zero Spring Boot / Zero Hibernate ORM:** Mantenha apenas [`praxis-authz-contracts`](https://github.com/codexrodrigues/praxis-authz-contracts), [`praxis-authz-enforcement-core`](https://github.com/codexrodrigues/praxis-authz-enforcement-core) e Jackson `2.18.2`. Toda integração Spring Boot (`ApplicationContext`, properties e HealthIndicator) pertence a [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Emissão Determinística `import rego.v1`:** Nunca gere código Rego com ordenação dependente de `HashSet`/`HashMap` ou sem checagem explícita do modelo de 6 estados dos fatos (`input.facts["..."].status == "PRESENT"`).
3. **Respostas `undefined` Sempre Falham Fechado:** Em `OpaAuthorizationProviderAdapter` e nos transportes, qualquer ausência de `result`, timeout ou troca de instância em `SEARCH` deve lançar exceção explícita *fail-closed*.
4. **Cobertura no Motor Local e HTTP Guarded:** Qualquer nova diretiva ou endpoint Rego exige verificação em `DeterministicLocalOpaTransport` e provas de guarda de revisão (`SameInstanceSearchRevisionGuard`).
5. **Idioma:** Documente guias e melhorias de README em **PT-BR** claro e didático, mantendo nomes exatos de classes, pacotes e propriedades.

## Governança e Releases

Consulte também [RELEASING.md](RELEASING.md), [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
