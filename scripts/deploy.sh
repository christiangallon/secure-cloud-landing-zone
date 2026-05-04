#!/usr/bin/env bash
# =============================================================================
# DEPLOY.SH - Secure Cloud Landing Zone Deployment Script
# =============================================================================
# This script automates the deployment of the Secure Cloud Landing Zone.
#
# USAGE:
#   ./deploy.sh [environment] [options]
#
# EXAMPLES:
#   ./deploy.sh dev              # Deploy to dev environment
#   ./deploy.sh prod             # Deploy to prod environment
#   ./deploy.sh dev --validate   # Validate only, don't apply
#
# REQUIREMENTS:
#   - Terraform >= 1.0
#   - AWS CLI >= 2.0
#   - Appropriate AWS credentials configured

set -e  # Exit on error
set -u  # Exit on undefined variable

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_DIR/terraform"
ENVIRONMENTS_DIR="$TERRAFORM_DIR/environments"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed. Please install Terraform >= 1.0"
        exit 1
    fi

    TERRAFORM_VERSION=$(terraform version -json | grep -o '"terraform_version":"[^"]*"' | cut -d'"' -f4)
    log_success "Terraform version: $TERRAFORM_VERSION"

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install AWS CLI >= 2.0"
        exit 1
    fi

    AWS_VERSION=$(aws --version 2>&1 | head -n1)
    log_success "AWS CLI version: $AWS_VERSION"

    # Check jq
    if ! command -v jq &> /dev/null; then
        log_warning "jq is not installed. Some features may be limited."
    fi

    log_success "All requirements met!"
}

check_aws_credentials() {
    log_info "Checking AWS credentials..."

    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials are not configured or are invalid."
        log_info "Please configure your AWS credentials using:"
        log_info "  aws configure"
        log_info "Or set environment variables:"
        log_info "  export AWS_ACCESS_KEY_ID=your_key"
        log_info "  export AWS_SECRET_ACCESS_KEY=your_secret"
        exit 1
    fi

    IDENTITY=$(aws sts get-caller-identity)
    ACCOUNT_ID=$(echo "$IDENTITY" | jq -r '.Account')
    USER_ARN=$(echo "$IDENTITY" | jq -r '.Arn')

    log_success "Authenticated as: $USER_ARN"
    log_success "Account ID: $ACCOUNT_ID"
}

validate_environment() {
    local env=$1

    if [ ! -f "$ENVIRONMENTS_DIR/${env}.tfvars" ]; then
        log_error "Environment file not found: $ENVIRONMENTS_DIR/${env}.tfvars"
        exit 1
    fi

    log_success "Environment file validated: $env"
}

# =============================================================================
# TERRAFORM COMMANDS
# =============================================================================

terraform_init() {
    log_info "Initializing Terraform..."

    cd "$TERRAFORM_DIR"
    terraform init

    log_success "Terraform initialized"
}

terraform_validate() {
    log_info "Validating Terraform configuration..."

    cd "$TERRAFORM_DIR"
    terraform validate

    log_success "Terraform configuration is valid"
}

terraform_plan() {
    local env=$1

    log_info "Creating execution plan for environment: $env"

    cd "$TERRAFORM_DIR"
    terraform plan \
        -var-file="$ENVIRONMENTS_DIR/${env}.tfvars" \
        -out="$env.tfplan"

    log_success "Execution plan created: $env.tfplan"
}

terraform_apply() {
    local env=$1

    log_info "Applying configuration for environment: $env"
    log_warning "This will create/modify AWS resources. Charges may apply."

    cd "$TERRAFORM_DIR"

    # Prompt for confirmation unless --auto-approve is passed
    if [[ "$*" == *"--auto-approve"* ]]; then
        terraform apply -auto-approve -var-file="$ENVIRONMENTS_DIR/${env}.tfvars" "$env.tfplan"
    else
        read -p "Do you want to continue? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            terraform apply -var-file="$ENVIRONMENTS_DIR/${env}.tfvars" "$env.tfplan"
        else
            log_info "Apply cancelled"
            exit 0
        fi
    fi

    log_success "Configuration applied successfully!"
}

terraform_destroy() {
    local env=$1

    log_warning "DESTROYING all resources for environment: $env"
    log_error "This will delete all resources created by Terraform!"

    cd "$TERRAFORM_DIR"

    if [[ "$*" == *"--auto-approve"* ]]; then
        terraform destroy -var-file="$ENVIRONMENTS_DIR/${env}.tfvars"
    else
        read -p "Type 'DELETE' to confirm destruction: " -r
        echo
        if [[ $REPLY == "DELETE" ]]; then
            terraform destroy -var-file="$ENVIRONIRONMENTS_DIR/${env}.tfvars"
        else
            log_info "Destroy cancelled"
            exit 0
        fi
    fi

    log_success "Resources destroyed"
}

terraform_output() {
    local env=$1
    local output_name=${2:-""}

    cd "$TERRAFORM_DIR"

    if [ -z "$output_name" ]; then
        terraform output
    else
        terraform output -raw "$output_name"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

usage() {
    echo "Usage: $0 [environment] [command] [options]"
    echo
    echo "Environments:"
    echo "  dev                 Deploy to development environment"
    echo "  prod                Deploy to production environment"
    echo
    echo "Commands:"
    echo "  plan                Create an execution plan"
    echo "  apply               Apply the configuration"
    echo "  destroy             Destroy all resources"
    echo "  output [name]       Show Terraform outputs"
    echo "  validate            Validate configuration only"
    echo
    echo "Options:"
    echo "  --auto-approve      Skip approval prompts"
    echo "  --check             Run pre-deployment checks only"
    echo
    echo "Examples:"
    echo "  $0 dev plan                    # Plan dev environment"
    echo "  $0 prod apply --auto-approve   # Apply prod with no prompts"
    echo "  $0 dev output vpc_id            # Show VPC ID for dev"
}

main() {
    # Parse arguments
    local env=""
    local command="plan"
    local auto_approve=false
    local check_only=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            dev|prod)
                env="$1"
                shift
                ;;
            plan|apply|destroy|output|validate)
                command="$1"
                shift
                ;;
            --auto-approve)
                auto_approve=true
                shift
                ;;
            --check)
                check_only=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Default to dev if no environment specified
    if [ -z "$env" ]; then
        log_warning "No environment specified, defaulting to 'dev'"
        env="dev"
    fi

    # Run checks
    check_requirements
    check_aws_credentials
    validate_environment "$env"

    if [ "$check_only" = true ]; then
        log_success "All checks passed!"
        exit 0
    fi

    # Execute command
    case $command in
        validate)
            terraform_init
            terraform_validate
            ;;
        plan)
            terraform_init
            terraform_validate
            terraform_plan "$env"
            ;;
        apply)
            terraform_init
            terraform_validate
            terraform_plan "$env"
            if [ "$auto_approve" = true ]; then
                terraform_apply "$env" --auto-approve
            else
                terraform_apply "$env"
            fi
            ;;
        destroy)
            log_warning "This will destroy all resources!"
            if [ "$auto_approve" = true ]; then
                terraform_destroy "$env" --auto-approve
            else
                terraform_destroy "$env"
            fi
            ;;
        output)
            terraform_output "$env" "${2:-""}"
            ;;
    esac
}

# Run main function
main "$@"
