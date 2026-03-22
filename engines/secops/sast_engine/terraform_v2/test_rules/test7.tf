# Test file to trigger: Administration services access should be restricted to specific IP addresses

resource "aws_security_group" "admin_sg" {
  name        = "admin-sg"
  description = "Allow admin access from anywhere"

  # ❌ This is the problem: SSH (22) open to 0.0.0.0/0
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0","192.168.1.0/24"] # Should trigger the rule
  }

  # ❌ RDP (3389) also open to the world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Should trigger the rule
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
