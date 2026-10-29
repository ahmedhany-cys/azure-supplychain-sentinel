output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "release_identity_client_id" {
  description = "Use as AZURE_CLIENT_ID in GitHub Actions (azure/login with OIDC). Not a secret."
  value       = azurerm_user_assigned_identity.release.client_id
}

output "tenant_id" {
  description = "Use as AZURE_TENANT_ID in GitHub Actions. Not a secret."
  value       = data.azurerm_client_config.current.tenant_id
}

output "container_registry_login_server" {
  value = var.enable_container_registry ? azurerm_container_registry.main[0].login_server : null
}

output "cosign_kms_key_uri" {
  description = "Pass to `cosign sign --key` / `cosign verify --key` once the key exists."
  value = (var.enable_signing_key_vault && var.key_vault_admin_object_id != ""
    ? "azurekms://${azurerm_key_vault.signing[0].name}.vault.azure.net/${azurerm_key_vault_key.release_signing[0].name}"
  : null)
}

output "evidence_container_url" {
  value = (var.enable_evidence_storage
    ? "${azurerm_storage_account.evidence[0].primary_blob_endpoint}${azurerm_storage_container.evidence[0].name}"
  : null)
}

output "dashboard_url" {
  value = local.enable_aca ? "https://${azurerm_container_app.dashboard[0].ingress[0].fqdn}" : null
}

output "billable_resources_enabled" {
  description = "Quick check of which cost-bearing features this configuration creates."
  value = {
    container_registry = var.enable_container_registry
    signing_key_vault  = var.enable_signing_key_vault
    evidence_storage   = var.enable_evidence_storage
    container_apps     = local.enable_aca
  }
}
