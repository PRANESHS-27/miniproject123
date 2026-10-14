# ☁️ Enterprise Cloud Deployment & Operations Guide (AWS Target)

This document provides the complete production architecture, networking topology, security controls, and step-by-step deployment instructions for the **Cloud-Native Centralized Vulnerability Registry and Intelligent Security Query Interface for Institutions** (**VulnWatch**).

---

## 1. Production Architecture Overview

The production architecture is designed for institutional deployment following the principle of defense-in-depth, strict network segregation, and zero-trust data access:

```
                  Internet Users / Security Analysts
                                  │
                                  │ HTTPS (443)
                                  ▼
                    ┌───────────────────────────┐
                    │  Amazon Route 53 / DNS    │
                    └─────────────┬─────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          │                                               │
          ▼                                               ▼
┌───────────────────────────┐               ┌───────────────────────────┐
│     Amazon CloudFront     │               │ Application Load Balancer │
│   (Global Edge Cache &    │               │  (ALB - Public Subnets,   │
│      WAF Protected)       │               │   AWS ACM SSL/TLS Term.)  │
└─────────────┬─────────────┘               └─────────────┬─────────────┘
              │                                           │
              ▼                                           │
┌───────────────────────────┐                             │
│      Amazon S3 Bucket     │                             │
│ (Encrypted, Private OAC,  │                             │
│   React Static Assets)    │                             │
└───────────────────────────┘                             │
                                                          │ Forward /api/*
                                                          ▼
    ═════════════════════════════════════════════════════════════════════════════
    VPC: 10.0.0.0/16 (2 Availability Zones)
    ═════════════════════════════════════════════════════════════════════════════
      Private App Subnets (10.0.10.0/24, 10.0.11.0/24)
      ┌───────────────────────────────────────────────────────────────────────┐
      │  AWS ECS Fargate Cluster                                              │
      │                                                                       │
      │  ┌─────────────────────────────┐     ┌──────────────────────────────┐ │
      │  │ FastAPI API Task (Service)  │     │ Async Scan Worker Task       │ │
      │  │ Port 8000                   │     │ Nmap / Sockets / Sync Job    │ │
      │  │ Auto-scaled 2-10 tasks      │     │ Controlled Concurrency       │ │
      │  └──────────────┬──────────────┘     └──────────────┬───────────────┘ │
      └─────────────────┼───────────────────────────────────┼─────────────────┘
                        │                                   │
                        │ Outbound via NAT Gateway          │
                        │ for NVD / CISA KEV Sync           │
                        ▼                                   ▼
      Private Database Subnets (10.0.20.0/24, 10.0.21.0/24)
      ┌───────────────────────────────────────────────────────────────────────┐
      │  Amazon RDS PostgreSQL 16 (Multi-AZ)                                  │
      │  - Primary DB Instance (Encrypted gp3 with AWS KMS)                   │
      │  - Standby Replica in AZ-B with synchronous replication               │
      │  - Isolated security group: allows ingress ONLY from ECS Tasks on 5432│
      └───────────────────────────────────────────────────────────────────────┘

      Auxiliary Services:
      - AWS Secrets Manager: JWT secret, DB credentials, API keys (Groq/NVD)
      - Amazon CloudWatch: Container stdout/stderr log aggregation & metric alarms
      - Amazon S3 (Evidence & Reports): Encrypted at rest, versioning enabled
```

---

## 2. Network Topology & Security Groups

### Subnet Allocation
| Subnet Name | CIDR Block | AZ | Route Table | Purpose |
|-------------|------------|----|-------------|---------|
| `public-subnet-1a` | `10.0.1.0/24` | `us-east-1a` | Internet Gateway | ALB, NAT Gateway |
| `public-subnet-1b` | `10.0.2.0/24` | `us-east-1b` | Internet Gateway | ALB (High Availability) |
| `private-app-1a` | `10.0.10.0/24` | `us-east-1a` | NAT Gateway 1a | ECS Fargate API & Workers |
| `private-app-1b` | `10.0.11.0/24` | `us-east-1b` | NAT Gateway 1b | ECS Fargate API & Workers |
| `private-db-1a` | `10.0.20.0/24` | `us-east-1a` | Isolated (No egress) | RDS Primary PostgreSQL |
| `private-db-1b` | `10.0.21.0/24` | `us-east-1b` | Isolated (No egress) | RDS Standby PostgreSQL |

### Security Group Rules
1. **`alb-sg` (Application Load Balancer)**:
   - Ingress: `TCP 443` from `0.0.0.0/0` (HTTPS)
   - Ingress: `TCP 80` from `0.0.0.0/0` (HTTP to HTTPS redirect)
   - Egress: `TCP 8000` to `ecs-tasks-sg`
2. **`ecs-tasks-sg` (FastAPI Application Tasks)**:
   - Ingress: `TCP 8000` from `alb-sg`
   - Egress: `TCP 5432` to `rds-postgres-sg`
   - Egress: `TCP 443` to `0.0.0.0/0` (for NVD, CISA feeds, and Groq API calls via NAT Gateway)
   - Egress: `TCP 80, 443` to approved scanned target ranges
3. **`rds-postgres-sg` (Database Tier)**:
   - Ingress: `TCP 5432` strictly from `ecs-tasks-sg`
   - Egress: None (Isolated)

---

## 3. Database Tier Provisioning (AWS RDS PostgreSQL)

### Engine & Storage
- **Engine**: PostgreSQL 16.2+
- **Instance Class**: `db.t4g.medium` (Development/Testing) or `db.r6g.large` (Production)
- **Deployment**: Multi-AZ (Automatic failover across Availability Zones)
- **Storage**: `100 GB` gp3, Autoscale up to `1000 GB`
- **Encryption**: KMS-managed customer key (`aws/rds`)
- **Automated Backups**: 30-day retention window with point-in-time recovery (PITR)
- **Parameter Group**:
  - `rds.force_ssl = 1` (Enforce TLS encryption on all client connections)
  - `shared_preload_libraries = 'pg_stat_statements'`

### Database Connection String Format
```
postgresql+psycopg2://<DB_USER>:<DB_PASSWORD>@<RDS_ENDPOINT>:5432/<DB_NAME>?sslmode=require
```

---

## 4. Compute Tier (AWS ECS Fargate)

### Container Configuration
- **CPU & Memory**:
  - API Container: 1 vCPU (1024 CPU units), 2048 MB RAM
  - Background Worker / Scanner: 1 vCPU, 2048 MB RAM
- **Logging**: `awslogs` driver sending to CloudWatch Log Group `/ecs/vulnwatch-prod`
- **Health Check**:
  - Command: `CMD-SHELL, curl -f http://localhost:8000/health || exit 1`
  - Interval: 30 seconds
  - Timeout: 5 seconds
  - Retries: 3
  - Start Period: 45 seconds

### IAM Roles (Least-Privilege)

#### 1. Task Execution Role (`ecsTaskExecutionRole`)
Allows ECS agent to pull Docker images and fetch Secrets Manager secrets:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:*:secret:vulnwatch/*"
      ]
    }
  ]
}
```

#### 2. Task Role (`vulnwatchTaskRole`)
Assigned to the running application container:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::vulnwatch-reports-production",
        "arn:aws:s3:::vulnwatch-reports-production/*"
      ]
    }
  ]
}
```

---

## 5. Frontend Hosting (S3 + CloudFront)

1. **S3 Bucket Creation**:
   - Bucket: `vulnwatch-ui-production`
   - Block all public access: **Enabled**
   - Bucket policy: Grant read access solely to CloudFront Origin Access Control (OAC).

2. **CloudFront Distribution**:
   - Origin 1: S3 Bucket (Default root object: `index.html`)
   - Origin 2: Application Load Balancer (Path pattern: `/api/*`)
   - Custom Error Response: HTTP 403 and 404 $\rightarrow$ return `/index.html` with HTTP 200 (SPA client-side routing support).
   - Viewer Protocol Policy: Redirect HTTP to HTTPS.
   - SSL Certificate: AWS Certificate Manager (ACM) certificate issued in `us-east-1`.

---

## 6. Local Full-Stack Deployment (Docker Compose)

For testing the complete containerized stack locally before cloud push:

### Prerequisites
- Docker Engine 24+ and Docker Compose v2.20+
- Port 3000, 8000, and 5432 available

### Step-by-Step Launch
```bash
# 1. Clone and enter repository
cd D:\vuln-mgmt-system

# 2. Configure local environment
cp .env.example backend/.env

# 3. Build and launch all services in detached mode
docker compose -f docker/docker-compose.yml up --build -d

# 4. Verify running health status
docker compose -f docker/docker-compose.yml ps

# 5. Check backend logs for database migration and bootstrap
docker compose -f docker/docker-compose.yml logs -f backend
```

Access points:
- **Frontend Web UI**: `http://localhost:3000`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`
- **Default Bootstrap Credentials**: `admin` / `Admin@123`

---

## 7. Automated Production CI/CD Pipeline

The `.github/workflows/ci.yml` and `.github/workflows/deploy.yml` workflows ensure zero-downtime automated deployment:

1. **Pull Request / Commit to `develop` or `main`**:
   - Spins up ephemeral PostgreSQL 16 container.
   - Executes 247+ pytest unit and integration test suites (`test_scanner_and_modules.py`, `test_tenant_isolation.py`, `test_api.py`, `test_rbac.py`).
   - Builds React frontend (`npm run build`).
2. **Push to `main` (Production Release)**:
   - Builds multi-stage Docker container images.
   - Pushes images to Amazon ECR or Docker Hub with commit SHA tags.
   - Triggers ECS rolling update service deployment with zero downtime (`aws ecs update-service --force-new-deployment`).
   - Syncs compiled frontend assets to S3 and invalidates CloudFront cache (`aws cloudfront create-invalidation --paths "/*"`).