# Guia de Release — Praxis Authz OPA

## Linha Pública

A linha pública ativa é `0.1.0-beta.*` sob a coordenada `io.github.codexrodrigues:praxis-authz-opa` (release atual publicada: `0.1.0-beta.1`).

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md).

## Ordem Sequencial de Publicação Multi-Repositório (4 Etapas)

`praxis-authz-opa` depende diretamente de `praxis-authz-contracts` e `praxis-authz-enforcement-core`. O `release.yml` verifica os arquivos `.pom` de **ambos** no `repo1.maven.org` antes de criar a tag:

1. `codexrodrigues/praxis-authz-contracts`
2. `codexrodrigues/praxis-authz-enforcement-core`
3. **`codexrodrigues/praxis-authz-opa`** *(este repositório — aguarda os passos 1 e 2 visíveis com `HTTP 200` no Maven Central)*
4. `codexrodrigues/praxis-authz-starter` *(aguarda a publicação deste repositório)*

Todos os quatro módulos de uma onda coordenada devem publicar exatamente a mesma string SemVer.

## Segredos Obrigatórios no Repositório

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (bloco ASCII-armored com a linha em branco obrigatória pela RFC 4880 imediatamente após `-----BEGIN PGP PRIVATE KEY BLOCK-----`, ou exportação binária codificada em base64)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (opcional)
- `RELEASE_PAT`, com permissão `contents: write` para enviar commits e tags para `main`

`RELEASE_PAT` é obrigatório porque tags enviadas via `GITHUB_TOKEN` não disparam o workflow separado com gatilho `push: tags: v*`.

## Fluxo Oficial de Release

1. Confirme que `praxis-authz-contracts` e `praxis-authz-enforcement-core` na versão alvo já respondem `HTTP 200` em `repo1.maven.org`, que o working tree está limpo e a validação local passa com JDK 21 (`--release 21`, `-Xlint:all,-serial`) e Maven `3.8.0+` (recomendado `3.9+`):

   ```powershell
   mvn -B clean verify
   ```

2. No GitHub Actions, execute **Release Praxis Authz OPA** (`workflow_dispatch`) em `main` com `create_tag=true` informando `version` ou `bump`/`preid`.
3. O job `create_tag` valida a presença dos `.pom`s upstream em `repo1.maven.org`, grava a versão no `pom.xml`, cria a tag anotada `v<semver>` e envia `HEAD:main` + tag atomicamente.
4. O job `publish` valida a tag, importa a chave GPG, impõe fronteiras (`maven-enforcer-plugin`), executa toda a suíte do compilador Rego v1 / montador de bundles / guarda `SEARCH`, aplica `flatten-maven-plugin` (modo `oss`), assina os artefatos, publica via `central-publishing-maven-plugin` e aguarda `HTTP 200` em `repo1.maven.org`.
5. Somente inicie `praxis-authz-starter` após o probe deste workflow concluir com sucesso.
6. Antes de executar `mvn install` local para desenvolvimento inédito, avance `<version>` para `-SNAPSHOT` para evitar sobrescrever a release publicada em `~/.m2`.
7. Valide as coordenadas publicadas usando um repositório local temporário isolado contra `repo1.maven.org`:

   ```powershell
   mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree
   ```

Nunca crie tags manualmente nem execute `mvn deploy` localmente.
