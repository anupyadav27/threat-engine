# Add a resource using the weak password variable
resource "aws_db_instance" "bad_password_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = var.instance_type
  name                 = "mydb2"
  username             = "foo"
  password             = var.db_password # Should trigger weak password rule
  parameter_group_name = "default.mysql5.7"
}
# Insecure S3 bucket (public ACL, no logging)
resource "aws_s3_bucket" "public_bucket" {
  bucket = var.bucket_name
  acl    = "public-read" # Should trigger public ACL rule
  # No logging block (should trigger logging rule)
  versioning {
    enabled    = true
    mfa_delete = false # Should trigger MFA delete rule
  }
}

# Unencrypted RDS instance
resource "aws_db_instance" "unencrypted_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = var.instance_type
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "default.mysql5.7"
  # No storage_encrypted = true (should trigger RDS encryption rule)
}

# Open security group
resource "aws_security_group" "open_sg" {
  name        = "open-sg-git1"
  description = "Open to the world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Should trigger open security group rule
  }
}
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.7.0"

  cidr = var.vpc_cidr_block

  azs             = data.aws_availability_zones.available.names
  private_subnets = slice(var.private_subnet_cidr_blocks, 0, 2)
  public_subnets  = slice(var.public_subnet_cidr_blocks, 0, 2)

  enable_nat_gateway = true
  enable_vpn_gateway = false
}

module "app_security_group" {
  source  = "terraform-aws-modules/security-group/aws//modules/web"
  version = "5.1.2"

  name        = "web-server-sg"
  description = "Security group for web-servers with HTTP ports open within VPC"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = module.vpc.public_subnets_cidr_blocks
}

module "lb_security_group" {
  source  = "terraform-aws-modules/security-group/aws//modules/web"
  version = "5.1.2"

  name        = "lb-sg-project-alpha-dev"
  description = "Security group for load balancer with HTTP ports open within VPC"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
}

resource "random_string" "lb_id" {
  length  = 3
  special = false
}

module "elb_http" {
  source  = "terraform-aws-modules/elb/aws"
  version = "4.0.2"

  # Ensure load balancer name is unique
  name = "lb-${random_string.lb_id.result}-project-alpha-dev"

  internal = false

  security_groups = [module.lb_security_group.security_group_id]
  subnets         = module.vpc.public_subnets

  number_of_instances = length(module.ec2_instances.instance_ids)
  instances           = module.ec2_instances.instance_ids

  listener = [{
    instance_port     = "80"
    instance_protocol = "HTTP"
    lb_port           = "80"
    lb_protocol       = "HTTP"
  }]

  health_check = {
    target              = "HTTP:80/index.html"
    interval            = 10
    healthy_threshold   = 3
    unhealthy_threshold = 10
    timeout             = 5
  }
}

module "ec2_instances" {
  source = "./modules/aws-instance"

  instance_count     = var.instances_per_subnet * length(module.vpc.private_subnets)
  instance_type      = var.instance_type
  subnet_ids         = module.vpc.private_subnets[*]
  security_group_ids = [module.app_security_group.security_group_id]
}

resource "aws_db_subnet_group" "private" {
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "database" {
  allocated_storage = 5
  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.t3.micro"
  username          = var.db_username
  password          = var.db_password

  db_subnet_group_name = aws_db_subnet_group.private.name

  skip_final_snapshot = true
}
