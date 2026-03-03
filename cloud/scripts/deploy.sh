#!/bin/bash
set -e

# SMTP Server CDK Deployment Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="dev"
SKIP_BUILD=false
AUTO_APPROVE=false

# Usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --environment ENV    Environment to deploy (dev, staging, production)"
    echo "  -s, --skip-build         Skip npm install and build"
    echo "  -y, --yes                Auto-approve deployment"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -e dev                Deploy to development"
    echo "  $0 -e staging -y         Deploy to staging with auto-approve"
    echo "  $0 -e production         Deploy to production (requires approval)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -s|--skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -y|--yes)
            AUTO_APPROVE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|production)$ ]]; then
    echo -e "${RED}Invalid environment: $ENVIRONMENT${NC}"
    echo "Must be one of: dev, staging, production"
    exit 1
fi

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  SMTP Server CDK Deployment            ║${NC}"
echo -e "${GREEN}║  Environment: $ENVIRONMENT                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed${NC}"
    echo "Install it from: https://aws.amazon.com/cli/"
    exit 1
fi

# Check if CDK is installed
if ! command -v cdk &> /dev/null; then
    echo -e "${RED}Error: AWS CDK is not installed${NC}"
    echo "Install it with: npm install -g aws-cdk"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    echo "Run: aws configure"
    exit 1
fi

# Get AWS account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "us-east-1")

echo -e "${YELLOW}AWS Account:${NC} $ACCOUNT_ID"
echo -e "${YELLOW}AWS Region:${NC} $REGION"
echo ""

# Build if not skipped
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install
    echo ""

    echo -e "${YELLOW}Building TypeScript...${NC}"
    npm run build
    echo ""
fi

# Run CDK synth to validate
echo -e "${YELLOW}Validating CDK stack...${NC}"
cdk synth --context environment=$ENVIRONMENT > /dev/null
echo -e "${GREEN}✓ Stack validation passed${NC}"
echo ""

# Show diff
echo -e "${YELLOW}Checking for changes...${NC}"
if cdk diff --context environment=$ENVIRONMENT; then
    echo ""
else
    echo -e "${YELLOW}No changes detected${NC}"
    echo ""
fi

# Confirmation for production
if [ "$ENVIRONMENT" = "production" ] && [ "$AUTO_APPROVE" = false ]; then
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  WARNING: Production Deployment        ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    echo ""
    read -p "Are you sure you want to deploy to PRODUCTION? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Deployment cancelled${NC}"
        exit 0
    fi
fi

# Deploy
echo -e "${GREEN}Deploying SMTP Server to $ENVIRONMENT...${NC}"
echo ""

if [ "$AUTO_APPROVE" = true ]; then
    cdk deploy --context environment=$ENVIRONMENT --require-approval never
else
    cdk deploy --context environment=$ENVIRONMENT
fi

# Get outputs
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Deployment Complete!                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# Fetch and display outputs
STACK_NAME="smtp-server-$ENVIRONMENT"
if [ "$ENVIRONMENT" = "dev" ]; then
    STACK_NAME="SmtpServerDevStack"
elif [ "$ENVIRONMENT" = "staging" ]; then
    STACK_NAME="SmtpServerStagingStack"
else
    STACK_NAME="SmtpServerProdStack"
fi

echo -e "${YELLOW}Stack Outputs:${NC}"
aws cloudformation describe-stacks --stack-name $STACK_NAME --query 'Stacks[0].Outputs' --output table

echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Wait 5-10 minutes for the instance to complete initialization"
echo "2. SSH to instance: aws ssm start-session --target <INSTANCE_ID>"
echo "3. Check service status: sudo systemctl status smtp-server"
echo "4. View logs: sudo journalctl -u smtp-server -f"
echo ""
echo -e "${YELLOW}CloudWatch Logs:${NC}"
echo "aws logs tail /aws/ec2/smtp-server-$ENVIRONMENT --follow"
echo ""
