# Guia de Release (`praxis-authz-opa`)

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md) para manter releases reprodutíveis, assinadas e compatíveis com `praxis-authz-contracts`, `praxis-authz-enforcement-core` e `praxis-authz-starter`.

## Pré-requisitos do Ambiente

- **Java:** `21` (compilação com `--release 21` e `-Xlint:all,-serial`, enforcer `requireJavaVersion [21,)`)
- **Apache Maven:** `3.8.0` ou superior (recomendado `3.9+` em toda a stack Authz)
- **GPG & Central Portal:** segredos `CENTRAL_TOKEN_USER`, `CENTRAL_TOKEN_PASS`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `GPG_KEY_ID` e `RELEASE_PAT` configurados no repositório para execução em CI

## Ordem de Publicação Multi-Repositório

`praxis-authz-opa` ocupa o **Nível 1** (após `contracts` e em paralelo a `enforcement-core`, consumindo ambos na cadeia de dependência):

1. `praxis-authz-contracts` e `praxis-authz-enforcement-core` *(devem estar disponíveis no Maven Central nas versões exatas)*
2. **`praxis-authz-opa`**
3. `praxis-authz-starter` *(aguarda a publicação deste repositório)*

## Verificação Local Pré-Release

Antes de disparar a release via CI:

```powershell
mvn -B clean verify
```

Verifique que:
- Toda a suíte do compilador Rego v1, montador de bundles e guarda `SameInstanceSearchRevisionGuard` passou;
- O `maven-enforcer-plugin` não reportou dependências proibidas (`org.springframework.boot:*` ou `org.hibernate.orm:*`) nem dependências `-SNAPSHOT`;
- O `CHANGELOG.md` está alinhado com a versão alvo.

## Fluxo Oficial no GitHub Actions

- `ci.yml` executa **apenas** via `workflow_dispatch`;
- `release.yml` executa via `workflow_dispatch` ou criação de tag `v*` aprovada, publicando via `central-publishing-maven-plugin`.
