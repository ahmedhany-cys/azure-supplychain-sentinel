# Azure SupplyChain Sentinel - optional Azure footprint.
#
# Naming:  <prefix>-<environment>-<purpose>, e.g. sscs-dev-rg. Globally unique names
#          (registry, storage, key vault) drop hyphens and append a 4-char random suffix.
# Identity: one user-assigned managed identity ("release identity") receives only the
#           data-plane roles it needs, scoped to the individual resource - never the
#           subscription or resource group.
# Secrets:  none are created or stored by Terraform. GitHub authenticates with OIDC
#           federation; the signing key is generated inside Key Vault and never exported.

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 4
  upper   = false
  special = false
}

locals {
  name       = "${var.prefix}-${var.environment}"
  compact    = "${var.prefix}${var.environment}${random_string.suffix.result}"
  enable_aca = var.enable_container_apps && var.enable_container_registry
  tags = merge({
    project     = "azure-supplychain-sentinel"
    environment = var.environment
    managed_by  = "terraform"
    cost_center = "portfolio-demo"
  }, var.tags)
}

resource "azurerm_resource_group" "main" {
  name     = "${local.name}-rg"
  location = var.location
  tags     = local.tags
}

# Release identity: used by CI (via OIDC) and by the Container App.
resource "azurerm_user_assigned_identity" "release" {
  name                = "${local.name}-release-id"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "github" {
  count                     = var.enable_github_oidc ? 1 : 0
  name                      = "github-${replace(var.github_repository, "/", "-")}-main"
  user_assigned_identity_id = azurerm_user_assigned_identity.release.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  subject                   = "repo:${var.github_repository}:${var.github_oidc_subject}"
}

# ------------------------------------------------------------------ container registry

resource "azurerm_container_registry" "main" {
  count                         = var.enable_container_registry ? 1 : 0
  name                          = "${local.compact}acr"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                           = "Basic"
  admin_enabled                 = false # identities only; no shared admin password
  public_network_access_enabled = true  # Basic SKU does not support private endpoints
  anonymous_pull_enabled        = false
  tags                          = local.tags
}

resource "azurerm_role_assignment" "acr_push" {
  count                = var.enable_container_registry ? 1 : 0
  scope                = azurerm_container_registry.main[0].id
  role_definition_name = "AcrPush" # push image + cosign signature; includes pull
  principal_id         = azurerm_user_assigned_identity.release.principal_id
}

# ------------------------------------------------------------------ signing key vault

resource "azurerm_key_vault" "signing" {
  count                         = var.enable_signing_key_vault ? 1 : 0
  name                          = "${local.compact}kv"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7
  public_network_access_enabled = true # restrict with network_acls for production use
  tags                          = local.tags
}

resource "azurerm_role_assignment" "kv_admin" {
  count                = var.enable_signing_key_vault && var.key_vault_admin_object_id != "" ? 1 : 0
  scope                = azurerm_key_vault.signing[0].id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = var.key_vault_admin_object_id
}

# The release identity may sign and read the public key - it cannot export, delete or
# rotate the key.
resource "azurerm_role_assignment" "kv_sign" {
  count                = var.enable_signing_key_vault ? 1 : 0
  scope                = azurerm_key_vault.signing[0].id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.release.principal_id
}

resource "azurerm_key_vault_key" "release_signing" {
  count        = var.enable_signing_key_vault && var.key_vault_admin_object_id != "" ? 1 : 0
  name         = "release-signing"
  key_vault_id = azurerm_key_vault.signing[0].id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]
  tags         = local.tags

  depends_on = [azurerm_role_assignment.kv_admin]
}

# ------------------------------------------------------------------ evidence storage

resource "azurerm_storage_account" "evidence" {
  count                           = var.enable_evidence_storage ? 1 : 0
  name                            = substr("${local.compact}ev", 0, 24)
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Entra ID auth only
  default_to_oauth_authentication = true
  tags                            = local.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "evidence" {
  count                 = var.enable_evidence_storage ? 1 : 0
  name                  = "release-evidence"
  storage_account_id    = azurerm_storage_account.evidence[0].id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "evidence_writer" {
  count                = var.enable_evidence_storage ? 1 : 0
  scope                = azurerm_storage_container.evidence[0].id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.release.principal_id
}

# ------------------------------------------------------------------ container apps

resource "azurerm_container_app_environment" "main" {
  count               = local.enable_aca ? 1 : 0
  name                = "${local.name}-cae"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  # No Log Analytics workspace is attached, to avoid ingestion charges. Attach one
  # deliberately if you need centralised logs (see docs/azure-deployment.md).
  tags = local.tags
}

resource "azurerm_container_app" "dashboard" {
  count                        = local.enable_aca ? 1 : 0
  name                         = "${local.name}-dashboard"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main[0].id
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.release.id]
  }

  registry {
    server   = azurerm_container_registry.main[0].login_server
    identity = azurerm_user_assigned_identity.release.id
  }

  template {
    min_replicas = 0 # scale to zero when idle
    max_replicas = 1

    container {
      name    = "dashboard"
      image   = "${azurerm_container_registry.main[0].login_server}/azure-supplychain-sentinel:${var.container_image_tag}"
      cpu     = 0.5
      memory  = "1Gi"
      command = ["streamlit", "run", "sentinel/dashboard/app.py", "--server.address=0.0.0.0", "--server.port=8501"]

      env {
        name  = "SENTINEL_ALLOWED_ROOTS"
        value = "/app/examples"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8501
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  depends_on = [azurerm_role_assignment.acr_push]
}
