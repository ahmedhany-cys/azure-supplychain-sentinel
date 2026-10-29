variable "subscription_id" {
  description = "Azure subscription to deploy into. Supplied explicitly so a deployment never lands in an unintended default subscription."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "prefix" {
  description = "Short lowercase project prefix used in resource names (3-10 letters/digits)."
  type        = string
  default     = "sscs"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,9}$", var.prefix))
    error_message = "prefix must be 3-10 lowercase letters/digits, starting with a letter."
  }
}

variable "environment" {
  description = "Environment name used in resource names and tags."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be dev, test or prod."
  }
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}

# --------------------------------------------------------------------------------------
# Feature flags. EVERYTHING THAT CAN COST MONEY IS OFF BY DEFAULT.
# With all flags false, the plan creates only a resource group and a user-assigned
# managed identity, neither of which is billed.
# --------------------------------------------------------------------------------------

variable "enable_github_oidc" {
  description = "Create a federated identity credential so GitHub Actions can obtain Azure tokens without stored secrets (free)."
  type        = bool
  default     = false
}

variable "github_repository" {
  description = "owner/name of the GitHub repository trusted for OIDC."
  type        = string
  default     = "ahmedhany-cys/azure-supplychain-sentinel"
}

variable "github_oidc_subject" {
  description = "OIDC subject claim to trust. Default: only workflows running on the main branch."
  type        = string
  default     = "ref:refs/heads/main"
}

variable "enable_container_registry" {
  description = "BILLABLE: Azure Container Registry (Basic SKU) for the Sentinel image and signatures."
  type        = bool
  default     = false
}

variable "enable_signing_key_vault" {
  description = "BILLABLE (per operation): Key Vault holding a non-exportable EC P-256 release signing key usable by cosign via azurekms://."
  type        = bool
  default     = false
}

variable "enable_evidence_storage" {
  description = "BILLABLE (per GB and per operation): storage account for release evidence (SBOMs, decisions, reports)."
  type        = bool
  default     = false
}

variable "enable_container_apps" {
  description = "BILLABLE beyond the free grant: Container Apps environment running the API and dashboard (scale to zero). Requires enable_container_registry."
  type        = bool
  default     = false
}

variable "container_image_tag" {
  description = "Image tag deployed to Container Apps (must already exist in the registry)."
  type        = string
  default     = "0.1.0"
}

variable "key_vault_admin_object_id" {
  description = "Entra ID object ID of the operator allowed to manage the signing key (Key Vault Crypto Officer). Leave empty to skip."
  type        = string
  default     = ""
}
