.PHONY: help up down build migrate shell test lint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start all services (Postgres, Redis, MinIO, Backend, Frontend)
	docker compose up -d

down: ## Stop all services
	docker compose down

build: ## Build all Docker images
	docker compose build

migrate: ## Run Django migrations
	docker compose exec backend python manage.py migrate

shell: ## Open Django shell
	docker compose exec backend python manage.py shell

createsuperuser: ## Create Django admin superuser
	docker compose exec backend python manage.py createsuperuser

test: ## Run backend tests
	docker compose exec backend python manage.py test

logs: ## Tail all service logs
	docker compose logs -f

logs-backend: ## Tail backend logs
	docker compose logs -f backend

logs-celery: ## Tail Celery worker logs
	docker compose logs -f celery-worker

psql: ## Open Postgres shell
	docker compose exec postgres psql -U ato_user -d ato_db

redis-cli: ## Open Redis CLI
	docker compose exec redis redis-cli

minio-console: ## Print MinIO console URL
	@echo "MinIO Console: http://localhost:9001 (minioadmin/minioadmin)"

api-docs: ## Print API docs URL
	@echo "API Docs: http://localhost:8000/api/docs/"
