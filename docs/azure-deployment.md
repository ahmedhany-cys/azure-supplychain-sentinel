# Optional Azure deployment

> **Status:** designed and validated with `terraform validate` (azurerm provider 5.11.0).
> **Nothing has been deployed by this project, and no Azure resources were created during its
> development.** The core application never needs Azure.

## Stages

| Stage | What runs where | Azure cost |
|---|---|---|
| **A - local-first (default)** | CLI, API, dashboard and SQLite on a laptop or in GitHub Actions | none |
| **B - optional Azure** | Identity for CI (OIDC), optional registry, Key Vault signing key, evidence storage, hosted dashboard | only for resources you enable |

Services were chosen because they map to a supply-chain control, not to make the project look
cloud-based:

| Service | Control it provides | Local alternative |
|---|---|---|
| User-assigned managed identity + GitHub OIDC federation | CI authenticates to Azure without any stored secret | not needed locally |
| Azure Key Vault (EC P-256, non-exportable) | Release signing key generated inside Key Vault and marked non-exportable (software-protected in the Standard tier; Premium adds HSM protection); used by Cosign via `azurekms://` | encrypted local key (`sentinel keygen`) or Cosign key pair |
| Azure Container Registry (Basic) | Stores the Sentinel image and its Cosign signature next to each other | local Docker image |
| Storage account (versioned, Entra-only auth) | Retains release evidence (SBOMs, decisions, reports) outside the build system | SQLite + `--out` evidence directories / CI artifacts |
| Container Apps (consumption, scale to zero) | Hosted dashboard for a team | `streamlit run` on localhost |

## Resources and naming

`<prefix>-<environment>-<purpose>`; globally unique names drop hyphens and add a random 4-character
suffix (`sscsdev7k2qacr`). All resources carry `project`, `environment`, `managed_by`,
`cost_center` tags.

| Terraform resource | Created when | Name |
|---|---|---|
| `azurerm_resource_group.main` | always | `sscs-dev-rg` |
| `azurerm_user_assigned_identity.release` | always | `sscs-dev-release-id` |
| `azurerm_federated_identity_credential.github` | `enable_github_oidc` | `github-<owner>-<repo>-main` |
| `azurerm_container_registry.main` + `AcrPush` role | `enable_container_registry` | `<compact>acr` |
| `azurerm_key_vault.signing` + `Key Vault Crypto User` role (+ `Crypto Officer` for the operator) + `azurerm_key_vault_key.release_signing` | `enable_signing_key_vault` (key needs `key_vault_admin_object_id`) | `<compact>kv` / `release-signing` |
| `azurerm_storage_account.evidence` + container + `Storage Blob Data Contributor` role | `enable_evidence_storage` | `<compact>ev` / `release-evidence` |
| `azurerm_container_app_environment.main` + `azurerm_container_app.dashboard` | `enable_container_apps` **and** `enable_container_registry` | `sscs-dev-cae` / `sscs-dev-dashboard` |

## Least-privilege identity design

- One **release identity** (user-assigned managed identity). GitHub Actions obtains tokens for it
  through OIDC federation restricted to `repo:<owner>/<repo>:ref:refs/heads/main` - pull requests
  and other branches cannot assume it.
- Role assignments are scoped to the single resource (or blob container), never to the resource
  group or subscription:
  - `AcrPush` on the registry (push image + signature; includes pull for the Container App);
  - `Key Vault Crypto User` on the vault (sign/verify with the key; cannot export, delete, rotate);
  - `Storage Blob Data Contributor` on the `release-evidence` container only.
- The human operator gets `Key Vault Crypto Officer` (manage keys) only if their object ID is
  supplied.
- Registry admin user disabled; storage shared-key auth disabled (Entra ID only); Key Vault in RBAC
  mode with purge protection.

## Secrets

Terraform creates **no secrets** and needs none in the repository. The values you will copy into
GitHub repository *variables* (not secrets) are identifiers: `AZURE_CLIENT_ID`
(`release_identity_client_id` output), `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`. State files may
contain resource metadata: keep them out of Git (`.gitignore` covers `*.tfstate`) and use a remote
backend with restricted access for team use.

## Cost risk

Prices are Microsoft retail list prices for **East US, USD**, retrieved on **2026-10-29** from the
Azure Retail Prices API (`https://prices.azure.com/api/retail/prices`) and the service pricing
pages. They exclude tax and discounts, vary by region, and change - **check the
[Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) before enabling
anything.**

| Resource (flag) | Billing meters | List price | Free allowance | Risk |
|---|---|---|---|---|
| Resource group, managed identity, federated credential (always / `enable_github_oidc`) | none | $0 | n/a | none |
| Container Registry Basic (`enable_container_registry`) | registry unit per day; storage over 10 GB | **$0.1666/day (≈ $5/month)**; $0.10/GB-month over 10 GB | none for Basic (the free account's 12-month offer covers one *Standard* registry for new customers) | **Fixed daily charge for as long as the registry exists, even if unused.** Delete it when the demo is over. |
| Key Vault Standard (`enable_signing_key_vault`) | operations | **$0.15 per 10,000** advanced key operations (EC keys); $0.03 per 10,000 standard operations | none | Very low at demo volumes (a few hundred signatures cost cents). No monthly charge for software-protected keys. Purge protection keeps the vault name reserved for 7 days after deletion. |
| Storage GPv2 Hot LRS (`enable_evidence_storage`) | data stored; write/read operations | **$0.0208/GB-month**; $0.05 per 10,000 writes; $0.004 per 10,000 reads | none | Low: evidence files are kilobytes. Versioning keeps old versions (billed as data). |
| Container Apps consumption (`enable_container_apps`) | vCPU-s, GiB-s, requests (active/idle) | $0.000024/vCPU-s active, $0.000003/GiB-s, $0.40 per million requests | **180,000 vCPU-s, 360,000 GiB-s, 2 M requests per subscription per month** | `min_replicas = 0`: no resource charges while scaled to zero. A replica kept running 24/7 at 0.5 vCPU would exceed the vCPU grant. **Caveat:** the Retail Prices API lists new Container Apps *environment* meters ($0.10/hour each: management, private endpoint, planned maintenance) effective 2026-09-01; the billing documentation still describes this charge only for dedicated workload profiles, private endpoints and planned maintenance, none of which this configuration uses. This could not be confirmed - check Cost Management the day after deploying. Also requires the registry above. |
| Log Analytics (not created) | GB ingested | $2.30/GB beyond the free amount | first 5 GB per billing account per month; 31 days retention | Avoided: the Container Apps environment is created without a log destination (logs are streamed only). |

**Service cost vs. underlying cost.** Some services are free or cheap themselves but bill for what
they use underneath: Container Apps bills the vCPU/memory of running replicas and needs a registry
(with its own daily charge) to pull from; Cosign signatures stored in ACR consume registry storage;
attaching Log Analytics to Container Apps adds ingestion charges; a storage account's cost is
driven by data volume and operations, not by the account itself. The free account's credit lasts
30 days and its 12-month offers apply only to new customers - do not assume either is available.

Egress/bandwidth costs were not evaluated.

## Deploy (only after reviewing the cost table)

Prerequisites: Terraform ≥ 1.9, Azure CLI, an account with rights to create role assignments
(Owner or User Access Administrator on the subscription or target resource group).

```bash
az login
cd infrastructure/terraform
cp terraform.tfvars.example terraform.tfvars   # set subscription_id; leave billable flags false first
terraform init
terraform plan -out tfplan                     # read it: only free resources with default flags
terraform apply tfplan
terraform output billable_resources_enabled    # confirm what costs money
```

Enable one billable feature at a time by setting its flag in `terraform.tfvars`, re-running
`plan`, and reading the plan before `apply`.

Using the outputs:

```bash
# GitHub Actions (with id-token: write on the job that needs Azure):
#   azure/login with client-id = release_identity_client_id, tenant-id, subscription-id
# Sign with the Key Vault key:
cosign sign-blob --key "$(terraform output -raw cosign_kms_key_uri)" --bundle app.sigstore.json app.tar.gz
cosign public-key --key "$(terraform output -raw cosign_kms_key_uri)" > config/keys/release.pub
```

Images must be pushed to the registry (`az acr login`, `docker push`) before enabling Container Apps.

## Teardown

```bash
cd infrastructure/terraform
terraform destroy          # removes everything this configuration created
az group show -n sscs-dev-rg   # should report ResourceGroupNotFound
```

Notes:

- `prevent_deletion_if_contains_resources` is enabled: if someone created resources by hand in
  the resource group, destroy stops instead of deleting them. Remove or import them first.
- Key Vault uses soft delete with purge protection (7 days): the vault is recoverable and its name
  stays reserved for 7 days; it incurs no charge in the soft-deleted state.
- To stop only the fixed ACR charge, set `enable_container_registry = false` (this also disables
  Container Apps) and apply.
- Verify in **Cost Management → Cost analysis** (filter by tag `project = azure-supplychain-sentinel`)
  over the following days that charges stopped.
