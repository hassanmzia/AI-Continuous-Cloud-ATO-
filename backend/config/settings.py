"""
Django settings for AI Continuous ATO platform.
Multi-cloud compliance operator with Agentic RAG, MCP, and A2A.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "change-me-in-production")

DEBUG = os.getenv("DEBUG", "True").lower() == "true"

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "corsheaders",
    "django_filters",
    "drf_spectacular",
    # Project
    "core",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ---------------------------------------------------------------------------
# Database — Postgres with pgvector
# ---------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "ato_db"),
        "USER": os.getenv("DB_USER", "ato_user"),
        "PASSWORD": os.getenv("DB_PASSWORD", "ato_pass"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
    }
}

# ---------------------------------------------------------------------------
# REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "AI Continuous ATO API",
    "DESCRIPTION": "Multi-cloud continuous compliance operator with Agentic RAG, MCP, and A2A",
    "VERSION": "1.0.0",
}

# ---------------------------------------------------------------------------
# CORS (dev — restrict in production)
# ---------------------------------------------------------------------------
CORS_ALLOW_ALL_ORIGINS = DEBUG

# ---------------------------------------------------------------------------
# Celery (async task queue)
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# Evidence Vault (S3-compatible / MinIO)
# ---------------------------------------------------------------------------
EVIDENCE_VAULT = {
    "ENDPOINT": os.getenv("EVIDENCE_VAULT_ENDPOINT", "http://localhost:9000"),
    "ACCESS_KEY": os.getenv("EVIDENCE_VAULT_ACCESS_KEY", "minioadmin"),
    "SECRET_KEY": os.getenv("EVIDENCE_VAULT_SECRET_KEY", "minioadmin"),
    "BUCKET": os.getenv("EVIDENCE_VAULT_BUCKET", "ato-evidence"),
    "SECURE": os.getenv("EVIDENCE_VAULT_SECURE", "false").lower() == "true",
}

# ---------------------------------------------------------------------------
# Vector DB (pgvector or external)
# ---------------------------------------------------------------------------
VECTOR_DB = {
    "BACKEND": os.getenv("VECTOR_DB_BACKEND", "pgvector"),  # pgvector | chroma | opensearch
    "COLLECTION": os.getenv("VECTOR_DB_COLLECTION", "ato_compliance"),
    "EMBEDDING_MODEL": os.getenv("EMBEDDING_MODEL", "text-embedding-3-small"),
    "EMBEDDING_DIMENSIONS": int(os.getenv("EMBEDDING_DIMENSIONS", "1536")),
}

# ---------------------------------------------------------------------------
# LLM Configuration
# ---------------------------------------------------------------------------
LLM_CONFIG = {
    "PROVIDER": os.getenv("LLM_PROVIDER", "openai"),  # openai | anthropic
    "MODEL": os.getenv("LLM_MODEL", "gpt-4o"),
    "TEMPERATURE": float(os.getenv("LLM_TEMPERATURE", "0.0")),
    "MAX_TOKENS": int(os.getenv("LLM_MAX_TOKENS", "4096")),
}

# ---------------------------------------------------------------------------
# MCP Router
# ---------------------------------------------------------------------------
MCP_ROUTER = {
    "MAX_CONCURRENT_CALLS": int(os.getenv("MCP_MAX_CONCURRENT", "10")),
    "DEFAULT_TIMEOUT_SECONDS": int(os.getenv("MCP_TIMEOUT", "60")),
    "REQUIRE_MTLS": os.getenv("MCP_REQUIRE_MTLS", "false").lower() == "true",
    "AUDIT_ALL_CALLS": True,  # Always audit MCP tool calls
}

# ---------------------------------------------------------------------------
# Static / Auth / Internationalization
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
