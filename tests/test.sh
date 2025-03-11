#!/bin/bash

# Source environment variables from .env file
source ../.env

# Function to get AMI ID
fetch_ami_id() {
    local os=$1
    
    case "$os" in
        debian)
            os_filter="debian-12-amd64-*"
            owners="136693071363"
            ;;
        amazon-linux)
            os_filter="al2023-ami-*-x86_64"
            owners="137112412989"
            ;;
        arch-linux)
            os_filter="arch-linux-std-hvm-*"
            owners="647457786197" # Arch Linux owner ID
            ;;
        ubuntu)
            os_filter="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
            owners="099720109477"
            ;;
    esac

    ami_id=$(aws ec2 describe-images \
        --filters "Name=name,Values=$os_filter" "Name=state,Values=available" \
        --owners $owners \
        --query "Images | sort_by(@, &CreationDate)[-1].ImageId" \
        --output text)

    echo "$ami_id"
}

# Select OS to test (default to ubuntu if not specified)
OS=${1:-"ubuntu"}
echo "Testing OS: $OS"

# Configure AWS credentials
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY"
export AWS_DEFAULT_REGION="us-east-1"

# Fetch AMI ID
ami_id=$(fetch_ami_id "$OS")
echo "Using AMI ID: $ami_id"

# Initialize Terraform
cd ..
terraform init

# Apply Terraform
terraform apply -auto-approve \
    -var="access_key=$AWS_ACCESS_KEY" \
    -var="secret_key=$AWS_SECRET_KEY" \
    -var="ami_id=$ami_id"

# Get instance IP
instance_ip=$(terraform output -raw instance_ip)
echo "Instance IP: $instance_ip"

# Wait for instance to be ready
echo "Waiting for instance to be ready..."
sleep 90  # Increased wait time for instance to be fully ready

# Add instance to known hosts
ssh-keyscan -H $instance_ip >> ~/.ssh/known_hosts 2>/dev/null

# Determine SSH user based on OS
case "$OS" in
    debian)
        SSH_USER="admin"
        ;;
    amazon-linux)
        SSH_USER="ec2-user"
        ;;
    arch-linux)
        SSH_USER="arch"
        ;;
    ubuntu)
        SSH_USER="ubuntu"
        ;;
esac

echo "Using SSH user: $SSH_USER"

# Install pown.sh via SSH
max_retries=3
retry_count=0

while [ $retry_count -lt $max_retries ]; do
    if ssh -i ~/Downloads/mietest.pem -o StrictHostKeyChecking=no $SSH_USER@$instance_ip << EOF
export LDAP_BASE="$LDAP_BASE"
export LDAP_URI="$LDAP_URI"
export LDAP_ADMIN_DN="$LDAP_ADMIN_DN"
export LDAP_ADMIN_PW="$LDAP_ADMIN_PW"
export CA_CERT_CONTENT="$CA_CERT_CONTENT"

curl -O https://raw.githubusercontent.com/anishapant21/pown.sh/feature/update-tests/pown.sh
chmod +x pown.sh
./pown.sh
EOF
    then
        break
    else
        retry_count=$((retry_count+1))
        if [ $retry_count -eq $max_retries ]; then
            echo "Failed to connect after $max_retries attempts"
            exit 1
        fi
        echo "Connection failed, retrying in 10 seconds..."
        sleep 10
    fi
done

# Wait for pown.sh to complete setup
sleep 30

# Test SSH with ann user
echo "Testing SSH with ann user..."
if ssh -o StrictHostKeyChecking=no ann@$instance_ip "echo 'SSH as ann successful'" 2>/dev/null; then
    echo "SSH connection as ann succeeded"
else
    echo "Initial SSH attempt with ann failed, waiting and retrying..."
    sleep 10
    if ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no ann@$instance_ip "echo 'SSH as ann successful'"; then
        echo "SSH connection as ann succeeded on retry"
    else
        echo "Failed to SSH as ann user"
        exit 1
    fi
fi

# Cleanup
terraform destroy -auto-approve \
    -var="access_key=$AWS_ACCESS_KEY" \
    -var="secret_key=$AWS_SECRET_KEY" \
    -var="ami_id=$ami_id"