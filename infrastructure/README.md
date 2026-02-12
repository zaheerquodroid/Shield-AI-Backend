# Coco TestAI Infrastructure

AWS infrastructure for deploying Coco TestAI across test, demo, and production environments.

## Architecture

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

## Cost Estimate

**Test & Demo** run on-demand (started/stopped as needed):

| Service | When Running | When Stopped |
|---------|-------------|--------------|
| ECS Fargate | ~$0.50-0.80/day | $0 |
| RDS (stopped) | ~$0.50/day | $0 |
| NAT Gateway | ~$1.10/day | ~$1.10/day |
| ALB | ~$0.55/day | ~$0.55/day |
| ElastiCache | ~$0.40/day | ~$0.40/day |
| **Daily cost** | **~$3.50/day** | **~$2.05/day** |

**Production** (always on):

| Service | Monthly |
|---------|---------|
| ECS Fargate (2 tasks) | ~$50/mo |
| RDS t3.micro | ~$15/mo |
| ElastiCache t3.micro | ~$12/mo |
| NAT Gateway | ~$32/mo |
| ALB | ~$16/mo |
| CloudFront + S3 | ~$6/mo |
| **Total** | **~$131/mo** |

**Example monthly cost (prod always on, test/demo 4 days/mo each):**
- Prod: $131
- Test: $2.05 × 26 (stopped) + $3.50 × 4 (running) = ~$67
- Demo: $2.05 × 26 (stopped) + $3.50 × 4 (running) = ~$67
- **Total: ~$265/mo** (vs $326 if all always on)

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Terraform** >= 1.5.0
3. **ECR repository** created for API images

## Quick Start

### 1. Create ECR Repository

```bash
aws ecr create-repository --repository-name coco-api --region us-east-1
```

### 2. Deploy Infrastructure

```bash
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Deploy test environment
terraform workspace new test || terraform workspace select test
terraform apply -var-file=environments/test/terraform.tfvars

# Deploy demo environment
terraform workspace new demo || terraform workspace select demo
terraform apply -var-file=environments/demo/terraform.tfvars

# Deploy prod environment
terraform workspace new prod || terraform workspace select prod
terraform apply -var-file=environments/prod/terraform.tfvars
```

### 3. Start/Stop Test or Demo

Test and demo environments deploy with ECS tasks stopped (desired_count=0) to save costs.

```bash
# Start environment when needed
./scripts/start-env.sh test
./scripts/start-env.sh demo

# Stop when done
./scripts/stop-env.sh test
./scripts/stop-env.sh demo

# Check status of all environments
./scripts/env-status.sh
```

Or use GitHub Actions: **Actions → Manage Environment → Run workflow**

### 4. Deploy Frontend Manually

```bash
# Build frontend
npm run build

# Upload to S3 (get bucket name from Terraform output)
aws s3 sync dist/ s3://coco-test-frontend-XXXX --delete

# Invalidate CloudFront (get distribution ID from Terraform output)
aws cloudfront create-invalidation --distribution-id EXXXX --paths "/*"
```

### 4. Configure GitHub Actions

Add these secrets to your GitHub repository:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

Add these variables per environment:
- `API_URL` - ALB or custom domain URL
- `FRONTEND_BUCKET` - S3 bucket name from Terraform output
- `CLOUDFRONT_DISTRIBUTION_ID` - From Terraform output

## Local Development

```bash
cd infrastructure/docker

# Start database and redis
docker-compose up -d db redis

# Frontend connects to localhost:8001 for API
docker-compose up frontend
```

## Directory Structure

```
infrastructure/
├── terraform/
│   ├── main.tf                 # Main configuration
│   ├── variables.tf            # Variable definitions
│   ├── environments/
│   │   ├── test/terraform.tfvars
│   │   ├── demo/terraform.tfvars
│   │   └── prod/terraform.tfvars
│   └── modules/
│       ├── vpc/                # VPC, subnets, NAT
│       ├── ecs/                # ECS cluster, ALB, tasks
│       ├── rds/                # PostgreSQL database
│       ├── elasticache/        # Redis cache
│       └── frontend/           # S3 + CloudFront
├── scripts/
│   ├── start-env.sh            # Start test/demo environment
│   ├── stop-env.sh             # Stop test/demo environment
│   └── env-status.sh           # Check all environment status
├── docker/
│   ├── api/Dockerfile          # API container
│   └── docker-compose.yml      # Local dev environment
└── README.md
```

## Customization

### Adding a Custom Domain

1. Create an ACM certificate in us-east-1 (required for CloudFront)
2. Add to your tfvars:
   ```hcl
   api_domain_name      = "api.yourdomain.com"
   frontend_domain_name = "app.yourdomain.com"
   certificate_arn      = "arn:aws:acm:us-east-1:..."
   ```
3. Create CNAME records pointing to ALB and CloudFront

### Scaling Production

```hcl
# In prod/terraform.tfvars
api_cpu           = 1024   # 1 vCPU
api_memory        = 2048   # 2 GB
api_desired_count = 3      # 3 instances
db_instance_class = "db.t3.small"
redis_node_type   = "cache.t3.small"
```

## Destroying Infrastructure

```bash
# Select workspace
terraform workspace select test

# Destroy (prod has deletion protection - disable first)
terraform destroy -var-file=environments/test/terraform.tfvars
```
