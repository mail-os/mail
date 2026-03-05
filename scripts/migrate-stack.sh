#!/bin/bash
set -e

# Mail Server Stack Migration Script
# Migrates from smtp-server CloudFormation stack to mail-server stack
# while preserving all data (database, mailboxes, config, TLS certs)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ENVIRONMENT="${1:-production}"
MAIL_BIN="./packages/zig/zig-out/bin/mail"
OLD_SLUG="smtp-server"
NEW_SLUG="mail-server"
SKIP_DESTROY=false

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Mail Server Stack Migration                 ║${NC}"
echo -e "${CYAN}║  ${OLD_SLUG} -> ${NEW_SLUG}                      ║${NC}"
echo -e "${CYAN}║  Environment: ${ENVIRONMENT}                         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Verify prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI not installed${NC}"
    exit 1
fi

if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured${NC}"
    exit 1
fi

if [ ! -f "$MAIL_BIN" ]; then
    echo -e "${YELLOW}Mail CLI not built yet, building...${NC}"
    cd packages/zig && zig build -Doptimize=ReleaseFast && cd ../..
fi

echo -e "${GREEN}Prerequisites OK${NC}"
echo ""

# Step 1: Get current instance info
echo -e "${YELLOW}Step 1: Detecting current instance...${NC}"
OLD_INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=*mail*,*smtp*" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text 2>/dev/null || echo "None")

if [ "$OLD_INSTANCE_ID" = "None" ] || [ -z "$OLD_INSTANCE_ID" ]; then
    echo -e "${YELLOW}No running instance found. Deploying fresh...${NC}"
    SKIP_DESTROY=true
else
    echo -e "${GREEN}Found instance: ${OLD_INSTANCE_ID}${NC}"

    # Get Elastic IP if any
    OLD_EIP=$(aws ec2 describe-addresses \
        --filters "Name=instance-id,Values=${OLD_INSTANCE_ID}" \
        --query "Addresses[0].AllocationId" \
        --output text 2>/dev/null || echo "None")

    OLD_PUBLIC_IP=$(aws ec2 describe-addresses \
        --filters "Name=instance-id,Values=${OLD_INSTANCE_ID}" \
        --query "Addresses[0].PublicIp" \
        --output text 2>/dev/null || echo "None")

    if [ "$OLD_EIP" != "None" ]; then
        echo -e "${GREEN}Found Elastic IP: ${OLD_PUBLIC_IP} (${OLD_EIP})${NC}"
    fi
fi
echo ""

# Step 2: Create backup
if [ "$SKIP_DESTROY" = false ]; then
    echo -e "${YELLOW}Step 2: Creating backup of current instance...${NC}"
    $MAIL_BIN backup create --instance-id "$OLD_INSTANCE_ID" --env "$ENVIRONMENT"

    # Get the backup ID from the output
    BACKUP_ID=$($MAIL_BIN backup list --env "$ENVIRONMENT" 2>/dev/null | grep "mail-backup-" | tail -1 | awk '{print $NF}' | sed 's/\.tar\.gz//')

    if [ -z "$BACKUP_ID" ]; then
        echo -e "${RED}Failed to determine backup ID. Check backup list:${NC}"
        $MAIL_BIN backup list --env "$ENVIRONMENT"
        echo ""
        read -p "Enter the backup ID manually (e.g. mail-backup-20240101-120000): " BACKUP_ID
    fi

    echo -e "${GREEN}Backup created: ${BACKUP_ID}${NC}"
    echo ""

    # Step 3: Verify backup exists in S3
    echo -e "${YELLOW}Step 3: Verifying backup in S3...${NC}"
    $MAIL_BIN backup list --env "$ENVIRONMENT"
    echo ""
fi

# Step 4: Update cloud config slug and deploy new stack
echo -e "${YELLOW}Step 4: Deploying new mail-server stack...${NC}"
echo ""

# Temporarily update the slug in cloud.config.ts
CLOUD_CONFIG="packages/cloud/cloud.config.ts"
sed -i.bak "s/slug: 'smtp-server'/slug: 'mail-server'/" "$CLOUD_CONFIG"

echo -e "${YELLOW}Deploying new stack with slug 'mail-server'...${NC}"
cd packages/cloud && pantry run deploy 2>&1 && cd ../..

# Wait for the new instance to be ready
echo -e "${YELLOW}Waiting for new instance to initialize (this may take a few minutes)...${NC}"
sleep 30

# Detect new instance
NEW_INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=Mail Server" "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[?LaunchTime > '$(date -u -v-10M +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S)'].InstanceId" \
    --output text 2>/dev/null || echo "None")

if [ "$NEW_INSTANCE_ID" = "None" ] || [ -z "$NEW_INSTANCE_ID" ]; then
    # Fallback: find by mail-server tag
    NEW_INSTANCE_ID=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=*mail-server*" "Name=instance-state-name,Values=running" \
        --query "Reservations[0].Instances[0].InstanceId" \
        --output text 2>/dev/null || echo "None")
fi

if [ "$NEW_INSTANCE_ID" = "None" ] || [ -z "$NEW_INSTANCE_ID" ]; then
    echo -e "${RED}Could not find new instance. Check AWS console.${NC}"
    # Restore the config
    mv "$CLOUD_CONFIG.bak" "$CLOUD_CONFIG"
    exit 1
fi

echo -e "${GREEN}New instance: ${NEW_INSTANCE_ID}${NC}"

# Wait for SSM to be ready
echo -e "${YELLOW}Waiting for SSM agent on new instance...${NC}"
for i in $(seq 1 30); do
    SSM_STATUS=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=${NEW_INSTANCE_ID}" \
        --query "InstanceInformationList[0].PingStatus" \
        --output text 2>/dev/null || echo "None")
    if [ "$SSM_STATUS" = "Online" ]; then
        echo -e "${GREEN}SSM agent is online${NC}"
        break
    fi
    echo "  Waiting for SSM... (${i}/30)"
    sleep 10
done
echo ""

# Step 5: Restore backup to new instance
if [ "$SKIP_DESTROY" = false ] && [ -n "$BACKUP_ID" ]; then
    echo -e "${YELLOW}Step 5: Restoring backup to new instance...${NC}"
    $MAIL_BIN backup restore "$BACKUP_ID" --instance-id "$NEW_INSTANCE_ID" --env "$ENVIRONMENT"
    echo ""
fi

# Step 6: Re-associate Elastic IP if one existed
if [ "$SKIP_DESTROY" = false ] && [ "$OLD_EIP" != "None" ] && [ -n "$OLD_EIP" ]; then
    echo -e "${YELLOW}Step 6: Re-associating Elastic IP ${OLD_PUBLIC_IP}...${NC}"

    # Disassociate from old instance
    OLD_ASSOC=$(aws ec2 describe-addresses \
        --allocation-ids "$OLD_EIP" \
        --query "Addresses[0].AssociationId" \
        --output text 2>/dev/null || echo "None")

    if [ "$OLD_ASSOC" != "None" ] && [ -n "$OLD_ASSOC" ]; then
        aws ec2 disassociate-address --association-id "$OLD_ASSOC"
        echo "  Disassociated from old instance"
    fi

    # Associate with new instance
    aws ec2 associate-address --instance-id "$NEW_INSTANCE_ID" --allocation-id "$OLD_EIP"
    echo -e "${GREEN}Elastic IP ${OLD_PUBLIC_IP} associated with new instance${NC}"
    echo ""
fi

# Step 7: Verify
echo -e "${YELLOW}Step 7: Verifying new instance...${NC}"
$MAIL_BIN backup status --instance-id "$NEW_INSTANCE_ID" --env "$ENVIRONMENT"
echo ""

# Step 8: Ask about old stack
if [ "$SKIP_DESTROY" = false ]; then
    echo -e "${YELLOW}Step 8: Cleanup${NC}"
    echo ""
    echo "The old stack (${OLD_SLUG}-${ENVIRONMENT}) is still running."
    echo "Instance: ${OLD_INSTANCE_ID}"
    echo ""
    read -p "Do you want to destroy the old stack? (yes/no): " CONFIRM_DESTROY

    if [ "$CONFIRM_DESTROY" = "yes" ]; then
        echo -e "${YELLOW}Destroying old stack...${NC}"

        # First stop the old service to prevent mail delivery conflicts
        aws ssm send-command \
            --instance-ids "$OLD_INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["systemctl stop mail 2>/dev/null || systemctl stop smtp-server 2>/dev/null || true"]' \
            --output text > /dev/null 2>&1 || true

        sleep 5

        # Delete the old CloudFormation stack
        aws cloudformation delete-stack --stack-name "${OLD_SLUG}-${ENVIRONMENT}" 2>/dev/null || \
        aws cloudformation delete-stack --stack-name "SmtpServerProdStack" 2>/dev/null || \
        echo -e "${YELLOW}Could not auto-delete stack. Delete manually from AWS Console.${NC}"

        echo -e "${GREEN}Old stack deletion initiated${NC}"
    else
        echo "Keeping old stack. You can delete it later with:"
        echo "  aws cloudformation delete-stack --stack-name ${OLD_SLUG}-${ENVIRONMENT}"
    fi
fi

# Cleanup backup of config
rm -f "$CLOUD_CONFIG.bak"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Migration Complete!                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "New stack: ${NEW_SLUG}-${ENVIRONMENT}"
echo "Instance:  ${NEW_INSTANCE_ID}"
if [ "$OLD_PUBLIC_IP" != "None" ] && [ -n "$OLD_PUBLIC_IP" ]; then
    echo "Public IP: ${OLD_PUBLIC_IP} (Elastic IP preserved)"
fi
echo ""
echo "Verify with:"
echo "  $MAIL_BIN backup status --instance-id ${NEW_INSTANCE_ID}"
echo "  $MAIL_BIN user info <username> --instance-id ${NEW_INSTANCE_ID}"
echo ""
