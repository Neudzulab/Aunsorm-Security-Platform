// Terraform configuration enabling AWS Shield Advanced for the ingress Network Load Balancer.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region where the EKS cluster is deployed"
  type        = string
}

variable "ingress_nlb_arn" {
  description = "ARN of the Network Load Balancer fronting ingress-nginx"
  type        = string
}

variable "waf_web_acl_arn" {
  description = "Optional AWS WAF v2 WebACL to associate with the ingress"
  type        = string
  default     = ""
}

resource "aws_shield_protection" "aunsorm_ingress" {
  name         = "aunsorm-edge-nlb"
  resource_arn = var.ingress_nlb_arn
  tags = {
    Service     = "aunsorm-gateway"
    Environment = "production"
  }
}

resource "aws_shield_protection_group" "aunsorm_services" {
  aggregation         = "SUM"
  protection_group_id = "aunsorm-services"
  members             = [var.ingress_nlb_arn]
  resource_type       = "APPLICATION"
  tags = {
    Service     = "aunsorm-gateway"
    Environment = "production"
  }
}

resource "aws_shield_application_layer_automatic_response" "aunsorm_waf_response" {
  count = length(var.waf_web_acl_arn) > 0 ? 1 : 0

  resource_arn = var.waf_web_acl_arn
  action       = "COUNT"
}

output "shield_protection_id" {
  description = "Identifier for the Shield Advanced protection"
  value       = aws_shield_protection.aunsorm_ingress.id
}
