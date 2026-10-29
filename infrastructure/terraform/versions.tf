terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # State is local by default. For team use, configure a remote backend
  # (for example azurerm with a storage account you create separately) via
  # `terraform init -backend-config=...`; never commit state files.
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false # keep soft-deleted keys recoverable
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
  }
  subscription_id = var.subscription_id
}
