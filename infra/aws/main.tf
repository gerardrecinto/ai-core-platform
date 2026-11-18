terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "name" {
  type    = string
  default = "ai-core"
}
variable "subnet_ids" { type = list(string) }
variable "vpc_id" { type = string }
variable "eks_node_sg_id" { type = string }
variable "oidc_provider_arn" { type = string }
variable "oidc_provider_url" { type = string }
variable "bedrock_model_arns" { type = list(string) }
variable "monthly_budget_usd" { type = number }
variable "budget_emails" { type = list(string) }

resource "aws_kms_key" "platform" {
  description         = "${var.name} data encryption"
  enable_key_rotation = true
}

resource "aws_security_group" "db" {
  name   = "${var.name}-db"
  vpc_id = var.vpc_id
  ingress {
    description     = "Postgres from EKS nodes only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.eks_node_sg_id]
  }
}

resource "aws_db_subnet_group" "db" {
  name       = "${var.name}-db"
  subnet_ids = var.subnet_ids
}

resource "aws_rds_cluster" "db" {
  cluster_identifier            = "${var.name}-db"
  engine                        = "aurora-postgresql"
  engine_mode                   = "provisioned"
  database_name                 = "aicore"
  master_username               = "aicore"
  manage_master_user_password   = true # Secrets Manager owns and rotates the password
  master_user_secret_kms_key_id = aws_kms_key.platform.arn
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.platform.arn
  db_subnet_group_name          = aws_db_subnet_group.db.name
  vpc_security_group_ids        = [aws_security_group.db.id]
  backup_retention_period       = 7
  deletion_protection           = true
  skip_final_snapshot           = false
  final_snapshot_identifier     = "${var.name}-final"
  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 4
  }
}

resource "aws_rds_cluster_instance" "db" {
  identifier         = "${var.name}-db-1"
  cluster_identifier = aws_rds_cluster.db.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.db.engine
}

data "aws_iam_policy_document" "irsa_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:ai-core:ai-core-gateway"]
    }
  }
}

data "aws_iam_policy_document" "gateway" {
  statement {
    sid       = "InvokeApprovedModelsOnly"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = var.bedrock_model_arns
  }
  statement {
    sid       = "ReadOwnDatabaseSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_rds_cluster.db.master_user_secret[0].secret_arn]
  }
  statement {
    sid       = "UseOwnKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.platform.arn]
  }
}

resource "aws_iam_role" "gateway" {
  name               = "${var.name}-gateway"
  assume_role_policy = data.aws_iam_policy_document.irsa_trust.json
}

resource "aws_iam_role_policy" "gateway" {
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway.json
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/${var.name}/gateway"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.platform.arn
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  dynamic "notification" {
    for_each = [80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.budget_emails
    }
  }
}

output "gateway_role_arn" { value = aws_iam_role.gateway.arn }
output "db_secret_arn" { value = aws_rds_cluster.db.master_user_secret[0].secret_arn }
