# 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          USERS                              │
│         (Security Admin / Faculty / IT Team)                │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                Nginx (Reverse Proxy + TLS)                  │
└─────┬───────────────────────────────────────────────┬───────┘
      │ /                                           /api
      ▼                                               ▼
┌───────────────────┐                    ┌─────────────────────────┐
│  React Frontend   │                    │   FastAPI Backend       │
│  Tailwind +       │                    │   SQLAlchemy + JWT      │
│  Chart.js         │                    │   APScheduler (in-proc)  │
└───────────────────┘                    └─────┬─────────┬─────────┘
                                                │         │
                                  ┌─────────────┘         └──────────────┐
                                  ▼                                      ▼
                        ┌─────────────────────┐                ┌─────────────────────┐
                        │   PostgreSQL        │                │   ChromaDB (RAG)    │
                        │   Users, CVEs,      │                │   CVE embeddings    │
                        │   Search Logs       │                │                     │
                        └─────────────────────┘                └─────────────────────┘
                                  ▲                                      ▲
                                  │                                      │
                        ┌─────────┴──────────────────┐    ┌──────────────┴───────────────┐
                        │   APScheduler / Standalone │    │  Embeddings (HF / OpenAI)   │
                        │   • fetch_all_cves (NVD)   │    │  Sentence-Transformers      │
                        │   • fetch_cisa_kev         │    │                              │
                        └─────────┬──────────────────┘    └──────────────────────────────┘
                                  │
                          ┌───────┴───────┐
                          ▼               ▼
                   ┌─────────────┐ ┌─────────────┐
                   │   NVD API   │ │ CISA KEV    │
                   └─────────────┘ └─────────────┘
```

## Tech layers

| Layer        | Stack                                                            |
|--------------|------------------------------------------------------------------|
| Frontend     | React 18, Vite, Tailwind CSS, Chart.js, Axios, React Router       |
| Backend      | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2                  |
| Auth         | JWT (python-jose), bcrypt (passlib)                              |
| Database     | PostgreSQL 16                                                    |
| AI / RAG     | LangChain, OpenAI / Ollama, HuggingFace sentence-transformers, ChromaDB |
| Scheduler    | APScheduler (in-process) / standalone CLI                        |
| Security data| NVD 2.0 API, CISA KEV catalog                                    |
| Container    | Docker, docker-compose                                           |
| Orchestration| Kubernetes manifests                                              |
| CI/CD        | GitHub Actions                                                    |
| Cloud        | AWS EC2 + RDS + S3 + CloudWatch                                   |