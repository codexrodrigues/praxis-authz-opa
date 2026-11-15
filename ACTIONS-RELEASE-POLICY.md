# Actions no Fechamento de Versões

O padrão durante desenvolvimento é **zero execuções remotas**. Valide alterações localmente; commits, PRs, documentação interna e tarefas rotineiras não são motivos para iniciar workflows no GitHub Actions. Use os workflows manuais somente no fechamento autorizado de uma versão/publicação ou em validação de corte de release. Não utilize `[skip ci]` como contorno nem desabilite gates estruturais.

Antes de push, tag ou dispatch, confira os gatilhos reais em `.github/workflows/`:
- `ci.yml` (`CI`): dispara apenas por `workflow_dispatch` para validação isolada em `ubuntu-latest` (incluindo checagem que proíbe `org.springframework.boot` e `org.hibernate.orm` em `target/runtime-dependencies.txt`).
- `release.yml` (`Release Praxis Authz OPA`): dispara por `workflow_dispatch` (job `create_tag`) ou por push de tag `v*` (job `publish`). O job `create_tag` verifica `HTTP 200` no Maven Central (`repo1.maven.org`) para `praxis-authz-contracts` e `praxis-authz-enforcement-core` na mesma versão `v*` antes de criar a tag anotada. **Nunca crie tags `v*` manualmente para testar automação**.

## Fluxo deste repositório

1. Durante o desenvolvimento local, valide com Java 21: `mvn -B clean verify`.
2. Garanta que `praxis-authz-contracts` e `praxis-authz-enforcement-core` da mesma versão já estejam disponíveis em `repo1.maven.org`.
3. No fechamento de versão, execute `release.yml` em `main` com `create_tag=true` e aguarde o probe no Maven Central antes de disparar o release de `praxis-authz-starter`. Consulte [RELEASING.md](RELEASING.md).
