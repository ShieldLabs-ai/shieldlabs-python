# Publishing

Release packages by pushing a semver tag (`v0.1.0`, `v1.0.0`, …). Workflows live in `.github/workflows/publish.yml`.

## Prerequisites (founder / org admin)

| Registry | Package | Setup |
|---|---|---|
| npm | `@shieldlabs/node`, `@shieldlabs/js`, … | Create npm org `@shieldlabs`. Add GitHub Actions secret `NPM_TOKEN` **or** configure [trusted publishing / OIDC](https://docs.npmjs.com/trusted-publishers) for each package. Provenance is enabled (`id-token: write`). |
| PyPI | `shieldlabs` | Claim project name. Add a [trusted publisher](https://docs.pypi.org/trusted-publishers/) for `ShieldLabs-ai/shieldlabs-python` → workflow `publish.yml`. |
| Packagist | `shieldlabs/shieldlabs` | Submit https://github.com/ShieldLabs-ai/shieldlabs-php. Optional secrets `PACKAGIST_USERNAME` + `PACKAGIST_TOKEN` for update hooks. |
| Go | `github.com/ShieldLabs-ai/shieldlabs-go` | Consumers `go get` by git tag; publish workflow creates a GitHub Release. |

## Publish

```bash
git tag v0.1.0
git push origin v0.1.0
```

Do not publish until namespaces are reserved and secrets/OIDC are configured — the workflows will fail otherwise.
