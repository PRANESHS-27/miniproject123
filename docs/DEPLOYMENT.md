# ☁️ Cloud Deployment Guide (AWS)

This guide walks you through deploying VulnWatch to AWS using:

- **EC2** — application host (backend + frontend via docker-compose)
- **RDS** — managed PostgreSQL (recommended for production)
- **S3** — long-term storage for reports & logs
- **GitHub Actions** — CI/CD pipeline

## 1. Provision RDS

1. In the AWS console → RDS → Create database → PostgreSQL 16.
2. Engine options: Production / Dev/Test.
3. DB identifier: `vulnwatch-db`.
4. Master username: `vulnwatch`, set a strong password (save it!).
5. Make it publicly accessible for now (you can lock it down later via VPC).
6. Note the endpoint — you'll need it as `DATABASE_URL`.

## 2. Launch EC2

1. EC2 → Launch instance → Ubuntu 22.04 LTS, t3.small is enough to start.
2. Storage: 30 GB gp3.
3. Security group: allow 22 (SSH), 80 (HTTP), 443 (HTTPS).
4. SSH in and install Docker:

   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose-plugin git
   sudo usermod -aG docker $USER
   ```

5. Clone the repo and configure:

   ```bash
   git clone https://github.com/<you>/vuln-mgmt-system.git
   cd vuln-mgmt-system
   cp backend/.env.example backend/.env
   $EDITOR backend/.env   # set DATABASE_URL to RDS, set OPENAI_API_KEY, etc.
   ```

6. Start the stack:

   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```

7. Visit `http://<ec2-public-ip>` — login with `admin / Admin@123` and change it immediately.

## 3. Front HTTPS with Nginx + Let's Encrypt

On the EC2 instance:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
# Copy our nginx config
sudo cp docker/nginx.conf /etc/nginx/sites-available/vulnwatch
sudo ln -s /etc/nginx/sites-available/vulnwatch /etc/nginx/sites-enabled/
sudo certbot --nginx -d vulnwatch.yourdomain.com
```

## 4. Wire CI/CD (optional but recommended)

1. Add these GitHub repo secrets:
   - `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
   - `EC2_HOST`, `EC2_SSH_KEY`
2. Push to `main` → `.github/workflows/ci.yml` runs tests.
3. After tests pass, `.github/workflows/deploy.yml` builds & pushes images and SSHes into your EC2 to redeploy.

## 5. Operational tips

- **Backups:** RDS has automated backups; snapshot weekly.
- **S3 for reports:** set `S3_BUCKET` in `.env` to push generated PDFs to S3 (see `backend/app/services/report_service.py` for an extension point).
- **Logs:** CloudWatch agent on EC2; forward `/var/log/vuln-watch/*.log`.
- **Scaling:** if traffic grows, move backend → ECS Fargate or EKS using the manifests in `kubernetes/`.

## Costs (rough, monthly)

- EC2 t3.small: ~$15
- RDS db.t4g.micro: ~$15
- S3 + CloudWatch: ~$2
- Data transfer: ~$2

≈ **$35/month** for a low-traffic production deployment.