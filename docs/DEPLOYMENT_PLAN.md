# Coco TestAI - AWS Deployment Plan

**Created:** February 2026
**Environments:** Test, Demo, Production
**Estimated Monthly Cost:** ~$265/mo (with test/demo on-demand)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         CloudFront                               │
│                    (Frontend CDN + API Proxy)                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     │
   ┌─────────┐         ┌─────────────┐              │
   │   S3    │         │     ALB     │              │
   │ (React) │         │             │              │
   └─────────┘         └──────┬──────┘              │
                              │                     │
                       ┌──────┴──────┐              │
                       │             │              │
                       ▼             ▼              │
                 ┌──────────┐ ┌──────────┐          │
                 │   ECS    │ │   ECS    │          │
                 │ (Fargate)│ │ (Fargate)│          │
                 └────┬─────┘ └────┬─────┘          │
                      │            │                │
         ┌────────────┴────────────┴────────────┐   │
         │              Private Subnet          │   │
         │  ┌─────────────┐  ┌────────────────┐ │   │
         │  │     RDS     │  │  ElastiCache   │ │   │
         │  │ (PostgreSQL)│  │    (Redis)     │ │   │
         │  └─────────────┘  └────────────────┘ │   │
         └──────────────────────────────────────┘   │
                                                    │
└───────────────────────────────────────────────────┘
                         VPC
```

---

## Cost Breakdown

### Production (Always On)

| Service | Spec | Monthly Cost |
|---------|------|--------------|
| ECS Fargate | 0.5 vCPU, 1GB × 2 tasks | ~$50 |
| RDS PostgreSQL | db.t3.micro | ~$15 |
| ElastiCache Redis | cache.t3.micro | ~$12 |
| NAT Gateway | Single AZ | ~$32 |
| ALB | Application Load Balancer | ~$16 |
| CloudFront + S3 | Frontend CDN | ~$6 |
| **Total** | | **~$131/mo** |

### Test & Demo (On-Demand)

| State | Daily Cost | Monthly (4 days use) |
|-------|------------|---------------------|
| Running | ~$3.50/day | |
| Stopped | ~$2.05/day | |
| **Average** | | **~$67/mo each** |

### Total Monthly Estimate

| Environment | Cost |
|-------------|------|
| Production | $131 |
| Test (on-demand) | $67 |
| Demo (on-demand) | $67 |
| **Total** | **~$265/mo** |

---

## Infrastructure Files Created

```
coco-testai-webapp/
├── infrastructure/
│   ├── README.md                           # Deployment guide
│   ├── terraform/
│   │   ├── main.tf                         # Main Terraform config
│   │   ├── variables.tf                    # Variable definitions
│   │   ├── .gitignore                      # Terraform ignores
│   │   ├── environments/
│   │   │   ├── test/terraform.tfvars       # Test config (starts stopped)
│   │   │   ├── demo/terraform.tfvars       # Demo config (starts stopped)
│   │   │   └── prod/terraform.tfvars       # Prod config (always on)
│   │   └── modules/
│   │       ├── vpc/main.tf                 # VPC, subnets, NAT Gateway
│   │       ├── ecs/main.tf                 # ECS Fargate, ALB, tasks
│   │       ├── rds/main.tf                 # PostgreSQL database
│   │       ├── elasticache/main.tf         # Redis cache
│   │       └── frontend/main.tf            # S3 + CloudFront CDN
│   ├── scripts/
│   │   ├── start-env.sh                    # Start test/demo
│   │   ├── stop-env.sh                     # Stop test/demo
│   │   └── env-status.sh                   # Check all environments
│   └── docker/
│       ├── api/Dockerfile                  # Django API container
│       └── docker-compose.yml              # Local development
├── .github/workflows/
│   ├── deploy.yml                          # CI/CD pipeline
│   └── manage-env.yml                      # Start/stop environments
└── DEPLOYMENT_PLAN.md                      # This file
```

---

## Implementation Plan

### Phase 1: AWS Setup (Day 1)

| Step | Task | Command/Action |
|------|------|----------------|
| 1.1 | Install prerequisites | `brew install terraform awscli` |
| 1.2 | Configure AWS CLI | `aws configure` |
| 1.3 | Create ECR repository | `aws ecr create-repository --repository-name coco-api` |
| 1.4 | Get AWS account ID | `aws sts get-caller-identity --query Account --output text` |
| 1.5 | Update tfvars with account ID | Replace `YOUR_AWS_ACCOUNT_ID` in all tfvars files |

### Phase 2: Deploy Production (Day 1-2)

| Step | Task | Command |
|------|------|---------|
| 2.1 | Initialize Terraform | `cd infrastructure/terraform && terraform init` |
| 2.2 | Create prod workspace | `terraform workspace new prod` |
| 2.3 | Plan deployment | `terraform plan -var-file=environments/prod/terraform.tfvars` |
| 2.4 | Apply infrastructure | `terraform apply -var-file=environments/prod/terraform.tfvars` |
| 2.5 | Note outputs | Save API URL, S3 bucket, CloudFront ID |

### Phase 3: Deploy Test & Demo (Day 2)

| Step | Task | Command |
|------|------|---------|
| 3.1 | Create test workspace | `terraform workspace new test` |
| 3.2 | Deploy test | `terraform apply -var-file=environments/test/terraform.tfvars` |
| 3.3 | Create demo workspace | `terraform workspace new demo` |
| 3.4 | Deploy demo | `terraform apply -var-file=environments/demo/terraform.tfvars` |

### Phase 4: Build & Deploy API (Day 2-3)

| Step | Task | Command |
|------|------|---------|
| 4.1 | Clone Django backend | (from separate repo) |
| 4.2 | Build Docker image | `docker build -t coco-api -f infrastructure/docker/api/Dockerfile .` |
| 4.3 | Tag for ECR | `docker tag coco-api:latest <account>.dkr.ecr.us-east-1.amazonaws.com/coco-api:latest` |
| 4.4 | Login to ECR | `aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com` |
| 4.5 | Push to ECR | `docker push <account>.dkr.ecr.us-east-1.amazonaws.com/coco-api:latest` |
| 4.6 | Force ECS deployment | `aws ecs update-service --cluster coco-prod-cluster --service coco-prod-api --force-new-deployment` |

### Phase 5: Deploy Frontend (Day 3)

| Step | Task | Command |
|------|------|---------|
| 5.1 | Build frontend | `npm run build` |
| 5.2 | Upload to S3 | `aws s3 sync dist/ s3://<bucket-name> --delete` |
| 5.3 | Invalidate CloudFront | `aws cloudfront create-invalidation --distribution-id <id> --paths "/*"` |

### Phase 6: Configure CI/CD (Day 3)

| Step | Task | Action |
|------|------|--------|
| 6.1 | Add GitHub secrets | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| 6.2 | Add GitHub variables (per env) | `API_URL`, `FRONTEND_BUCKET`, `CLOUDFRONT_DISTRIBUTION_ID` |
| 6.3 | Test deployment | Push to `develop` branch → deploys to test |
| 6.4 | Test prod deployment | Push to `main` branch → deploys to prod |

### Phase 7: Custom Domain (Optional)

| Step | Task | Action |
|------|------|--------|
| 7.1 | Request ACM certificate | AWS Console → ACM → Request (must be us-east-1) |
| 7.2 | Validate domain | Add CNAME records for validation |
| 7.3 | Update tfvars | Add `certificate_arn`, `api_domain_name`, `frontend_domain_name` |
| 7.4 | Re-apply Terraform | `terraform apply` |
| 7.5 | Add DNS records | CNAME to ALB (API) and CloudFront (frontend) |

---

## Operating Procedures

### Start Test/Demo Environment

```bash
# Using script
./infrastructure/scripts/start-env.sh test

# Or via GitHub Actions
# Go to Actions → Manage Environment → Run workflow → Select "test" + "start"
```

### Stop Test/Demo Environment

```bash
# Using script
./infrastructure/scripts/stop-env.sh demo

# Or via GitHub Actions
# Go to Actions → Manage Environment → Run workflow → Select "demo" + "stop"
```

### Check Environment Status

```bash
./infrastructure/scripts/env-status.sh
```

### Deploy Code Changes

```bash
# Automatic via GitHub Actions:
git push origin main      # → deploys to prod
git push origin develop   # → deploys to test
git push origin demo      # → deploys to demo

# Manual frontend deploy:
npm run build
aws s3 sync dist/ s3://<bucket> --delete
aws cloudfront create-invalidation --distribution-id <id> --paths "/*"
```

### View Logs

```bash
# ECS task logs
aws logs tail /ecs/coco-prod-api --follow

# Recent errors
aws logs filter-log-events \
  --log-group-name /ecs/coco-prod-api \
  --filter-pattern "ERROR" \
  --start-time $(date -v-1H +%s000)
```

### Scale Production

```bash
# Update desired count
aws ecs update-service \
  --cluster coco-prod-cluster \
  --service coco-prod-api \
  --desired-count 3
```

---

## Rollback Procedures

### Rollback Frontend

```bash
# List previous versions
aws s3api list-object-versions --bucket <bucket> --prefix index.html

# Restore previous version
aws s3api copy-object \
  --bucket <bucket> \
  --copy-source <bucket>/index.html?versionId=<version-id> \
  --key index.html
```

### Rollback API

```bash
# List previous task definitions
aws ecs list-task-definitions --family coco-prod-api

# Deploy previous version
aws ecs update-service \
  --cluster coco-prod-cluster \
  --service coco-prod-api \
  --task-definition coco-prod-api:<previous-revision>
```

---

## Security Checklist Before Launch

Before enabling the Chrome extension for public users, complete these requirements (see [EXTENSION_LAUNCH_SECURITY.md](docs/EXTENSION_LAUNCH_SECURITY.md)):

### SHIELD Wrapper (deploy once, protects all apps)
- [ ] SHIELD-1: WAF & Threat Protection (rate limiting, bot protection)
- [ ] SHIELD-2: Security Headers (HSTS, CSP, X-Frame-Options)
- [ ] SHIELD-3: Response Sanitization (error message cleanup)

### CSEC Code Fixes (Coco-specific)
- [ ] CSEC-18: Remove hardcoded SECRET_KEY fallback
- [ ] CSEC-19: Change DEBUG to default False
- [ ] CSEC-20: Change ALLOWED_HOSTS to default empty
- [ ] CSEC-42: Add message sender validation
- [ ] CSEC-43: Encrypt stored auth data
- [ ] CSEC-44: Filter tab broadcasts and strip console logs
- [ ] CSEC-45: Add explicit CSP and tighten permissions

---

## Monitoring & Alerts (Future)

Consider adding:
- CloudWatch alarms for ECS CPU/memory
- RDS connection and storage alerts
- CloudFront 4xx/5xx error rate alerts
- Budget alerts at $300/mo threshold

---

*Last updated: February 2026*
