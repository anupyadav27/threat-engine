# Threat Engine Consolidated Services Makefile
# Provides convenient commands for building, testing, and deploying

.PHONY: help build test deploy clean

# Default values
REGISTRY_PREFIX ?= threat-engine
VERSION ?= latest
NAMESPACE ?= threat-engine
ENVIRONMENT ?= development

help: ## Show this help message
	@echo "Threat Engine Consolidated Services"
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# Development Commands
# ============================================================================

install: ## Install development dependencies
	@echo "Installing development dependencies..."
	@for service_dir in consolidated_services/*/; do \
		if [ -f "$$service_dir/requirements.txt" ]; then \
			echo "Installing $$service_dir dependencies..."; \
			pip install -r "$$service_dir/requirements.txt"; \
		fi; \
	done
	@if [ -f "api_gateway/requirements.txt" ]; then \
		pip install -r api_gateway/requirements.txt; \
	fi

test: ## Run all tests
	@echo "Running tests..."
	@python -m pytest tests/ -v --cov=consolidated_services --cov=api_gateway

lint: ## Run linting
	@echo "Running linting..."
	@flake8 consolidated_services/ api_gateway/ --max-line-length=120
	@black --check consolidated_services/ api_gateway/

format: ## Format code
	@echo "Formatting code..."
	@black consolidated_services/ api_gateway/
	@isort consolidated_services/ api_gateway/

# ============================================================================
# Docker Commands  
# ============================================================================

build: ## Build all Docker images
	@echo "Building all services..."
	@chmod +x deployment/scripts/build-all-services.sh
	@REGISTRY_PREFIX=$(REGISTRY_PREFIX) VERSION=$(VERSION) deployment/scripts/build-all-services.sh

build-service: ## Build specific service (usage: make build-service SERVICE=api-gateway)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter required. Example: make build-service SERVICE=api-gateway"; \
		exit 1; \
	fi
	@echo "Building $(SERVICE)..."
	@docker build -t $(REGISTRY_PREFIX)/$(SERVICE):$(VERSION) ./$(SERVICE)/

push: ## Push images to registry
	@echo "Pushing images to registry..."
	@docker push $(REGISTRY_PREFIX)/api-gateway:$(VERSION)
	@docker push $(REGISTRY_PREFIX)/core-engine-service:$(VERSION)
	@docker push $(REGISTRY_PREFIX)/configscan-service:$(VERSION)
	@docker push $(REGISTRY_PREFIX)/platform-service:$(VERSION)
	@docker push $(REGISTRY_PREFIX)/data-secops-service:$(VERSION)

# ============================================================================
# Local Development Commands
# ============================================================================

up: ## Start all services with Docker Compose
	@echo "Starting services with Docker Compose..."
	@cd deployment && docker-compose up -d
	@echo "Services available at:"
	@echo "  API Gateway: http://localhost:8000"
	@echo "  Core Engine: http://localhost:8001" 
	@echo "  ConfigScan: http://localhost:8002"
	@echo "  Platform: http://localhost:8003"
	@echo "  Data SecOps: http://localhost:8004"

down: ## Stop all services
	@echo "Stopping services..."
	@cd deployment && docker-compose down

logs: ## Show logs for all services
	@cd deployment && docker-compose logs -f

logs-service: ## Show logs for specific service (usage: make logs-service SERVICE=api-gateway)
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE parameter required. Example: make logs-service SERVICE=api-gateway"; \
		exit 1; \
	fi
	@cd deployment && docker-compose logs -f $(SERVICE)

restart: ## Restart all services
	@make down
	@make up

# ============================================================================
# Kubernetes Commands
# ============================================================================

deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	@chmod +x deployment/scripts/deploy-consolidated.sh
	@NAMESPACE=$(NAMESPACE) ENVIRONMENT=$(ENVIRONMENT) VERSION=$(VERSION) deployment/scripts/deploy-consolidated.sh

deploy-staging: ## Deploy to staging environment
	@make deploy NAMESPACE=threat-engine-staging ENVIRONMENT=staging

deploy-production: ## Deploy to production environment
	@make deploy NAMESPACE=threat-engine ENVIRONMENT=production

migrate: ## Migrate from legacy to consolidated architecture
	@echo "Running migration..."
	@chmod +x deployment/scripts/migrate-to-consolidated.sh
	@NAMESPACE=$(NAMESPACE) deployment/scripts/migrate-to-consolidated.sh

rollback: ## Rollback deployment
	@echo "Rolling back deployment..."
	@chmod +x deployment/scripts/deploy-consolidated.sh
	@NAMESPACE=$(NAMESPACE) deployment/scripts/deploy-consolidated.sh rollback

status: ## Check deployment status
	@echo "Checking deployment status..."
	@kubectl get pods,services,deployments -n $(NAMESPACE)

# ============================================================================
# Utility Commands
# ============================================================================

clean: ## Clean up Docker resources
	@echo "Cleaning up Docker resources..."
	@docker system prune -f
	@docker volume prune -f

clean-images: ## Remove all threat-engine Docker images
	@echo "Removing threat-engine images..."
	@chmod +x deployment/scripts/build-all-services.sh
	@deployment/scripts/build-all-services.sh clean

health-check: ## Check health of all services
	@echo "Checking service health..."
	@curl -f http://localhost:8000/health || echo "API Gateway: FAILED"
	@curl -f http://localhost:8001/health || echo "Core Engine: FAILED"
	@curl -f http://localhost:8002/health || echo "ConfigScan: FAILED" 
	@curl -f http://localhost:8003/health || echo "Platform: FAILED"
	@curl -f http://localhost:8004/health || echo "Data SecOps: FAILED"

port-forward: ## Forward API Gateway port for local access
	@echo "Port forwarding API Gateway..."
	@kubectl port-forward -n $(NAMESPACE) service/api-gateway 8000:8000

# ============================================================================
# Database Commands
# ============================================================================

db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	@kubectl exec -n $(NAMESPACE) deployment/platform-service -- python -m alembic upgrade head

db-seed: ## Seed database with test data
	@echo "Seeding database..."
	@kubectl exec -n $(NAMESPACE) deployment/platform-service -- python scripts/seed_data.py

# ============================================================================
# Monitoring Commands  
# ============================================================================

grafana: ## Open Grafana dashboard
	@kubectl port-forward -n monitoring service/grafana 3000:3000 &
	@echo "Grafana available at: http://localhost:3000"

prometheus: ## Open Prometheus dashboard  
	@kubectl port-forward -n monitoring service/prometheus 9090:9090 &
	@echo "Prometheus available at: http://localhost:9090"