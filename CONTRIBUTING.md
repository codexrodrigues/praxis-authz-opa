# Como Contribuir com `praxis-authz-opa`

Contribuições para `praxis-authz-opa` devem manter a emissão determinística de Rego v1, o alinhamento criptográfico dos 8 estágios de digest e o isolamento de frameworks Web/ORM.

## Princípios de Contribuição

1. **Zero Spring Boot / Zero Hibernate ORM (`BND-OWN-004`):** Mantenha apenas `praxis-authz-contracts`, `praxis-authz-enforcement-core` e Jackson `2.18.2`. Toda integração Spring Boot (`ApplicationContext`, properties e HealthIndicator) pertence a [`praxis-authz-starter`](https://github.com/codexrodrigues/praxis-authz-starter).
2. **Emissão Determinística `import rego.v1`:** Nunca gere código Rego com ordenação dependente de `HashSet`/`HashMap` ou sem checagem explícita do modelo de 6 estados dos fatos.
3. **Respostas `undefined` Sempre Falham Fechado:** Em `OpaAuthorizationProviderAdapter` e nos transportes, qualquer ausência de `result`, timeout ou troca de instância em `SEARCH` deve lançar exceção explícita *fail-closed*.
4. **Cobertura no Motor Local e HTTP Guarded:** Qualquer nova diretiva ou endpoint Rego exige verificação em `DeterministicLocalOpaTransport` e provas de guarda de revisão (`SameInstanceSearchRevisionGuard`).
5. **Idioma:** Documente guias e melhorias de README em PT-BR claro, mantendo nomes exatos de classes, pacotes e propriedades.

## Verificação Local

```powershell
mvn -B clean verify
```

Consulte também [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
