#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e #x  #add x for debugging

# Error trap to capture failures
error_exit() {
    local exit_code=$?
    local line_number=$1
    log "ERROR: Command failed at line $line_number with exit code $exit_code"
    log "ERROR: Last command that failed: ${BASH_COMMAND}"
    exit $exit_code
}

# Set up error trap
trap 'error_exit $LINENO' ERR

# Check if run as root, if not re-execute with sudo
check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        # Check if running from pipe (curl | bash)
        if [ ! -t 0 ] || [[ "$0" == "bash" ]] || [[ "$0" == "/bin/bash" ]] || [[ "$0" == "/usr/bin/bash" ]]; then
            echo "ERROR: This script requires root privileges."
            echo "Please run with sudo:"
            echo "  curl -s https://pown.sh | sudo bash -s -- $*"
            exit 1
        else
            echo "Script requires root privileges. Re-executing with sudo..."  # cant use log yet
            exec sudo "$0" "$@"
        fi
    fi
}

# Function to show help
show_help() {
    cat << EOF
pown.sh - LDAP Client Automation Script

USAGE:
    pown.sh [OPTION] [DOMAIN]

OPTIONS:
    --undo              Undo LDAP configuration and restore original settings
    --help, -h          Show this help message

ARGUMENTS:
    DOMAIN              Domain name for LDAP configuration (optional)
                       If not provided, will be prompted interactively

EXAMPLES:
    pown.sh                          # Interactive setup
    pown.sh example.com              # Setup with domain
    pown.sh --undo                   # Undo LDAP configuration

DESCRIPTION:
    This script automates LDAP client setup across various platforms including
    Linux distributions (Debian, RHEL, Arch) and macOS. It configures LDAP
    authentication, SSH access, and certificate management.

    On first run, the script creates backups of original configuration files
    which can be restored using the --undo option.

EOF
}

# Check root privileges first (before parsing arguments so we can pass them along)
check_root_privileges "$@"

# Parse command line arguments
UNDO_MODE=false
DOMAIN_ARG=""

while [[ $# -gt 0 ]]; do
echo "Processing argument: $1"  # Debugging line
    case $1 in
        --undo)
        echo "Enabling undo mode"
            UNDO_MODE=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
        *)
            DOMAIN_ARG="$1"
            shift
            ;;
    esac
done

# Configuration variables
readonly LOGFILE="/etc/pown.sh.setup.log"
readonly ENV_FILE="/etc/pown.sh.env"
readonly BACKUP_DIR="/etc/pown.sh.backups"
readonly SSSD_CONF="/etc/sssd/sssd.conf"
readonly SSH_CONF="/etc/ssh/sshd_config"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"

# Load environment variables (after ENV_FILE is defined)
[ -f "$ENV_FILE" ] && export $(grep -v '^#' "$ENV_FILE" | xargs)

# Function to get packages for package manager
get_packages() {
    local pm=$1
    case $pm in
        apt)
            echo "ldap-utils openssh-client openssh-server sssd sssd-ldap sudo libnss-sss libpam-sss ca-certificates vim net-tools iputils-ping dnsutils"
            ;;
        yum)
            echo "openssh-clients openssh-server sssd sssd-ldap sudo openldap-clients ca-certificates vim net-tools iputils authselect authconfig bind-utils"
            ;;
        pacman)
            echo "openssh sssd openldap sudo ca-certificates vim net-tools iputils pam pambase bind"
            ;;
        dnf)
            echo "openssh-clients openssh-server sssd sssd-ldap sudo openldap-clients ca-certificates vim net-tools iputils authselect authconfig bind-utils"
            ;;
        macos-native)
            # macOS has native tools: dsconfigldap, dscl, openssl/LibreSSL, dig, ssh, etc.
            # No package installation needed - all tools are built-in
            echo ""
            ;;
        *)
            echo ""
            ;;
    esac
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOGFILE
}

# Function to log and execute commands
exec_log() {
    log "Executing: $*"
    "$@"
}

# Function to generate LDAP_BASE from domain
generate_ldap_base_from_domain() {
    local domain=$1
    # Convert domain to LDAP DN format (example.com -> dc=example,dc=com)
    echo "$domain" | sed 's/\./,dc=/g' | sed 's/^/dc=/'
}

# Function to ensure DNS tools are available
ensure_dns_tools() {
    if command -v dig >/dev/null 2>&1 || command -v nslookup >/dev/null 2>&1; then
        return 0
    fi
    
    log "DNS tools not found. Installing..."
    local package_manager=$(detect_package_manager)
    
    case $package_manager in
        apt)
            sudo apt-get update && sudo apt-get install -y dnsutils
            ;;
        yum)
            sudo yum install -y bind-utils
            ;;
        dnf)
            sudo dnf install -y bind-utils
            ;;
        pacman)
            sudo pacman -S --noconfirm bind
            ;;
        macos-native)
            log "DNS tools (dig, nslookup, host) are built into macOS"
            return 0
            ;;
        *)
            log "Warning: Could not install DNS tools for package manager: $package_manager"
            return 1
            ;;
    esac
}

# Function to perform SRV record lookup with fallbacks
lookup_srv_records() {
    local service=$1
    local domain=$2
    local srv_query="${service}.${domain}"
    
    if command -v dig >/dev/null 2>&1; then
        dig +short "$srv_query" SRV 2>/dev/null
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup -type=SRV "$srv_query" 2>/dev/null | grep -E '^[^;].*SRV' | awk '{print $5, $6, $7, $8}' | sed 's/\.$//'
    else
        log "Warning: No DNS tools available for SRV lookup"
        return 1
    fi
}

# Function to test if a host/port combination is reachable
test_ldap_port() {
    local host=$1
    local port=$2
    local timeout=3
    
    # Use nc (netcat) or timeout+bash to test connectivity
    if command -v nc >/dev/null 2>&1; then
        nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
    elif command -v timeout >/dev/null 2>&1; then
        timeout "$timeout" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    else
        # Fallback: try to connect with bash
        bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    fi
}

# Function to get certificate CN from LDAP server
get_certificate_cn() {
    local ldap_uri=$1
    local host port
    
    # Parse the LDAP URI to extract host and port
    if [[ "$ldap_uri" =~ ^ldaps?://([^:]+):?([0-9]+)?$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
        # Default ports if not specified
        if [ -z "$port" ]; then
            if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
                port=636
            else
                port=389
            fi
        fi
    else
        log "get_certificate_cn: Could not parse URI: $ldap_uri"
        return 1
    fi
    
    # Only try to extract certificate for LDAPS connections
    if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
        log "get_certificate_cn: Extracting CN from $host:$port..."
        # Extract the certificate and get CN
        local cert_content
        if cert_content=$(openssl s_client -connect "$host:$port" -showcerts < /dev/null 2>/dev/null | \
                         sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'); then
            if [ -n "$cert_content" ]; then
                # Get the first certificate block
                local ca_cert=$(echo "$cert_content" | sed -n '1,/-----END CERTIFICATE-----/p')
                if [ -n "$ca_cert" ]; then
                    # Extract CN from certificate subject
                    local cert_cn=$(echo "$ca_cert" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | head -1)
                    if [ -n "$cert_cn" ]; then
                        log "get_certificate_cn: Extracted CN: $cert_cn"
                        echo "$cert_cn"
                        return 0
                    else
                        log "get_certificate_cn: CN extraction failed"
                    fi
                else
                    log "get_certificate_cn: No certificate block found"
                fi
            else
                log "get_certificate_cn: No certificate content"
            fi
        else
            log "get_certificate_cn: OpenSSL connection failed"
        fi
    else
        log "get_certificate_cn: Not an LDAPS URI"
    fi
    return 1
}

# Function to display certificate details
display_certificate_details() {
    local cert_content="$1"
    local ldap_uri="$2"
    
    log "📋 Certificate details from $ldap_uri:"
    log "========================================"
    
    # Display comprehensive certificate details with openssl
    if echo "$cert_content" | openssl x509 -noout -text >/dev/null 2>&1; then
        log "🔒 Complete Certificate Details:"
        echo "$cert_content" | openssl x509 -noout -text 2>/dev/null | while IFS= read -r line; do
            log "   $line"
        done
        log ""
        log "🛡️  Certificate Fingerprints:"
        log "   MD5:    $(echo "$cert_content" | openssl x509 -noout -fingerprint -md5 2>/dev/null | cut -d= -f2)"
        log "   SHA1:   $(echo "$cert_content" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2)"
        log "   SHA256: $(echo "$cert_content" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    else
        log "⚠️  Cannot parse certificate with openssl, showing raw preview:"
        log "$cert_content" | head -5
        log "... [certificate content continues] ..."
        log "$cert_content" | tail -2
    fi
    
    log "========================================"
    log "⚠️  Please verify this certificate matches your expected LDAP server"
    log "   Check the Subject CN, SANs, and fingerprints above"
    log ""
}

# Function to extract CA certificate from LDAP server
extract_ca_certificate() {
    local ldap_uri=$1
    local host port
    
    # Parse the LDAP URI to extract host and port
    if [[ "$ldap_uri" =~ ^ldaps?://([^:]+):?([0-9]+)?$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
        # Default ports if not specified
        if [ -z "$port" ]; then
            if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
                port=636
            else
                port=389
            fi
        fi
    else
        log "Warning: Could not parse LDAP URI: $ldap_uri"
        return 1
    fi
    
    # Only try to extract certificate for LDAPS connections
    if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
        log "Attempting to extract CA certificate from $host:$port..."
        
        # Check if openssl is available
        if ! command -v openssl >/dev/null 2>&1; then
            log "Warning: openssl not available, cannot extract certificate automatically"
            return 1
        fi
        
        # Extract the certificate
        local cert_content
        local extract_ca_command="openssl s_client -connect \"$host:$port\" -showcerts < /dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'"
        log "Executing: $extract_ca_command"
        
        if ! cert_content=$(openssl s_client -connect "$host:$port" -showcerts < /dev/null 2>/dev/null | \
                           sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p'); then
            log "Warning: Certificate extraction command failed: $extract_ca_command"
            return 1
        fi
        
        if [ -n "$cert_content" ]; then
            log "Raw certificate content extracted (length: ${#cert_content} chars)"
            # Get the last certificate (usually the CA certificate)
            local ca_cert
            ca_cert=$(echo "$cert_content" | awk '/-----BEGIN CERTIFICATE-----/{cert=""} {cert=cert $0 "\n"} /-----END CERTIFICATE-----/{print cert}' | tail -1)
            
            log "Processed CA certificate (length: ${#ca_cert} chars)"
            if [ -n "$ca_cert" ]; then
                # Extract CN from certificate subject for hostname validation
                local cert_cn=$(echo "$ca_cert" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | head -1)
                if [ -n "$cert_cn" ]; then
                    log "Certificate CN: $cert_cn"
                    # Export CN for potential use in LDAP URI construction
                    export CERT_CN="$cert_cn"
                fi
                log "Successfully extracted CA certificate from server"
                echo "$ca_cert"
                return 0
            else
                log "Warning: awk processing returned empty certificate"
                log "Using first certificate block instead"
                ca_cert=$(echo "$cert_content" | sed -n '1,/-----END CERTIFICATE-----/p')
                if [ -n "$ca_cert" ]; then
                    # Extract CN from first certificate as well
                    local cert_cn=$(echo "$ca_cert" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p' | head -1)
                    if [ -n "$cert_cn" ]; then
                        log "Certificate CN: $cert_cn"
                        export CERT_CN="$cert_cn"
                    fi
                    log "Successfully extracted first certificate from server"
                    echo "$ca_cert"
                    return 0
                fi
            fi
        else
            log "Warning: cert_content is empty after extraction"
        fi
        
        log "Warning: Could not extract certificate from $host:$port"
        log "Certificate extraction command output: $cert_content"
        return 1
    else
        log "LDAP connection (non-TLS), no certificate extraction needed"
        return 1
    fi
}

# Function to discover LDAP servers - separates host discovery from port testing
discover_ldap_server() {
    local domain=$1
    local discovered_hosts=()
    local ldap_uri=""
    
    log "Discovering LDAP server for domain: $domain"
    
    # Ensure DNS tools are available
    ensure_dns_tools
    
    # Step 1: Collect all potential LDAP hosts from SRV records
    log "Checking DNS SRV records..."
    
    # Try LDAPS SRV records (port 636)
    local srv_records=$(lookup_srv_records "_ldaps._tcp" "$domain")
    if [ -n "$srv_records" ]; then
        while IFS= read -r srv_record; do
            if [ -n "$srv_record" ]; then
                local priority=$(echo "$srv_record" | awk '{print $1}')
                local weight=$(echo "$srv_record" | awk '{print $2}')
                local port=$(echo "$srv_record" | awk '{print $3}')
                local target=$(echo "$srv_record" | awk '{print $4}' | sed 's/\.$//')
                discovered_hosts+=("$target:$port:ldaps")
                log "Found LDAPS SRV record: $target:$port"
            fi
        done <<< "$srv_records"
    fi
    
    # Try LDAP SRV records (port 389)
    srv_records=$(lookup_srv_records "_ldap._tcp" "$domain")
    if [ -n "$srv_records" ]; then
        while IFS= read -r srv_record; do
            if [ -n "$srv_record" ]; then
                local priority=$(echo "$srv_record" | awk '{print $1}')
                local weight=$(echo "$srv_record" | awk '{print $2}')
                local port=$(echo "$srv_record" | awk '{print $3}')
                local target=$(echo "$srv_record" | awk '{print $4}' | sed 's/\.$//')
                discovered_hosts+=("$target:$port:ldap")
                log "Found LDAP SRV record: $target:$port"
            fi
        done <<< "$srv_records"
    fi
    
    # Step 2: Add common hostname patterns to test
    log "Adding common hostname patterns..."
    local common_hostnames=("ldap" "ad" "dc" "directory" "ds" "openldap")
    for hostname in "${common_hostnames[@]}"; do
        if nslookup "$hostname.$domain" >/dev/null 2>&1; then
            discovered_hosts+=("$hostname.$domain:636:ldaps")
            discovered_hosts+=("$hostname.$domain:389:ldap")
            log "Found hostname: $hostname.$domain"
        fi
    done
    
    # Step 3: Add localhost as final fallback
    log "Adding localhost as fallback..."
    local system_hostname=$(hostname -f 2>/dev/null || hostname)
    discovered_hosts+=("localhost:636:ldaps")
    discovered_hosts+=("localhost:389:ldap")
    discovered_hosts+=("127.0.0.1:636:ldaps")
    discovered_hosts+=("127.0.0.1:389:ldap")
    
    # Step 4: Test connectivity to discovered hosts
    log "Testing connectivity to discovered hosts..."
    for host_entry in "${discovered_hosts[@]}"; do
        IFS=':' read -r host port protocol <<< "$host_entry"
        log "Testing $protocol://$host:$port..."
        
        if test_ldap_port "$host" "$port"; then
            # For LDAPS, try to extract certificate CN and use it for hostname validation
            if [[ "$protocol" == "ldaps" ]]; then
                local temp_uri="$protocol://$host:$port"
                local cert_cn=$(get_certificate_cn "$temp_uri")
                if [ -n "$cert_cn" ]; then
                    log "Using certificate CN '$cert_cn' for LDAPS URI"
                    ldap_uri="$protocol://$cert_cn:$port"
                elif [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
                    # Fallback to system hostname for localhost if no CN available
                    ldap_uri="$protocol://$system_hostname:$port"
                    log "Found local LDAP server, using system hostname: $ldap_uri"
                else
                    ldap_uri="$protocol://$host:$port"
                fi
            else
                # For non-TLS LDAP, use discovered host or system hostname for localhost
                if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
                    ldap_uri="$protocol://$system_hostname:$port"
                    log "Found local LDAP server, using system hostname: $ldap_uri"
                else
                    ldap_uri="$protocol://$host:$port"
                fi
            fi
            log "Successfully connected to: $ldap_uri"
            echo "$ldap_uri"
            return 0
        else
            log "Failed to connect to: $protocol://$host:$port"
        fi
    done
    
    # No working LDAP server found
    log "Could not auto-discover LDAP server for domain: $domain"
    echo ""
    return 1
}

# Function to prompt for environment variables  
prompt_for_env_vars() {
    local provided_domain="$1"
    
    # Use provided domain or prompt for one
    if [ -n "$provided_domain" ]; then
        domain="$provided_domain"
        log "Using domain from command line: $domain"
    else
        # Get domain from user
        local hostname=$(hostname -f 2>/dev/null || hostname)
        log "Detected hostname: $hostname"
        local default_domain=""
        if [[ "$hostname" == *.* ]]; then
            default_domain=${hostname#*.}
        fi
        
        if [ -n "$default_domain" ]; then
            read -p "Domain name [$default_domain]: " domain
            domain=${domain:-$default_domain}
        else
            read -p "Domain name (e.g., example.com): " domain
        fi
        
        # Validate that domain is not empty
        if [ -z "$domain" ]; then
            log "Error: Domain name is required. Exiting."
            exit 1
        fi
    fi
    
    # Auto-discover LDAP server
    LDAP_URI=$(discover_ldap_server "$domain") || true
    
    if [ -z "$LDAP_URI" ]; then
        log ""
        log "⚠️  ALERT: Could not auto-discover LDAP server for domain: $domain"
        log "   - No DNS SRV records found (_ldaps._tcp.$domain or _ldap._tcp.$domain)"
        log "   - No common LDAP hostnames found (ldap.$domain, ad.$domain, etc.)"
        log ""
        log "Please provide the LDAP server information manually."
        log ""
        read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
        
        # Validate that LDAP_URI is not empty
        while [ -z "$LDAP_URI" ]; do
            log "Error: LDAP Server URI is required."
            read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
        done
    else
        log "✅ Auto-discovered LDAP server: $LDAP_URI"
        
        # Extract and show certificate for security verification
        PREVIEW_CERT=$(extract_ca_certificate "$LDAP_URI")
        
        if [ -n "$PREVIEW_CERT" ]; then
            display_certificate_details "$PREVIEW_CERT" "$LDAP_URI"
        else
            log "⚠️  Could not extract certificate from discovered server (non-LDAPS or connection failed)"
        fi
        
        read -p "Use this server? $LDAP_URI (Y/n): " use_discovered
        if [[ "$use_discovered" =~ ^[Nn]$ ]]; then
            read -p "Please enter LDAP Server URI manually: " LDAP_URI
            
            # Validate manual entry
            while [ -z "$LDAP_URI" ]; do
                log "Error: LDAP Server URI is required."
                read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
            done
            
            # Extract certificate from the manually entered server
            log "Extracting certificate from manually entered server: $LDAP_URI"
            PREVIEW_CERT=$(extract_ca_certificate "$LDAP_URI")
            
            if [ -n "$PREVIEW_CERT" ]; then
                display_certificate_details "$PREVIEW_CERT" "$LDAP_URI"
            else
                log "⚠️  Could not extract certificate from manually entered server"
                log "   Server may be using plain LDAP (non-TLS) or connection failed"
            fi
        fi
    fi
    
    # Generate LDAP_BASE from domain
    local default_ldap_base=$(generate_ldap_base_from_domain "$domain")
    read -p "LDAP Base DN [$default_ldap_base]: " LDAP_BASE
    LDAP_BASE=${LDAP_BASE:-$default_ldap_base}
    
    local default_admin_dn="cn=admin,$LDAP_BASE"
    read -p "LDAP Admin DN [$default_admin_dn]: " LDAP_ADMIN_DN
    LDAP_ADMIN_DN=${LDAP_ADMIN_DN:-$default_admin_dn}
    
    # Ask about SSH configuration
    log ""
    log "SSH Configuration:"
    if is_ssh_enabled; then
        log "SSH service is currently enabled."
        read -p "Configure SSH for LDAP authentication? (Y/n): " configure_ssh
        if [[ "$configure_ssh" =~ ^[Nn]$ ]]; then
            FORCE_SSHD="false"
        else
            FORCE_SSHD="true"
        fi
    else
        log "SSH service is currently disabled."
        read -p "Force SSH configuration anyway? (y/N): " force_ssh
        if [[ "$force_ssh" =~ ^[Yy]$ ]]; then
            FORCE_SSHD="true"
            log "Warning: SSH will be configured but not enabled. You'll need to enable it manually."
        else
            FORCE_SSHD="false"
        fi
    fi
    
    # Set CA_CERT path for display
    if [ -z "$CA_CERT" ]; then
        CA_CERT=$(get_ca_cert_path)
    fi
    
    # Export the variables for use in the current session
    export LDAP_URI LDAP_BASE LDAP_ADMIN_DN FORCE_SSHD CA_CERT
}

# Function to display configuration and confirm with user
confirm_configuration() {
    log ""
    log "========================================"
    log "LDAP Configuration Summary:"
    log "========================================"
    log "LDAP URI:        $LDAP_URI"
    log "LDAP Base DN:    $LDAP_BASE"
    log "LDAP Admin DN:   $LDAP_ADMIN_DN"
    log "CA Certificate:  $CA_CERT"
    log "SSH Config:      $([[ "$FORCE_SSHD" == "true" ]] && echo "Enabled" || echo "Disabled")"
    log "========================================="
    log ""
    
    read -p "Do you want to proceed with this configuration? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log "Configuration cancelled by user."
        exit 0
    fi
    
    # Save configuration to .env file
    save_env_file
}

# Function to save environment variables to .env file
save_env_file() {
    log "Saving configuration to $ENV_FILE..."
    cat > "$ENV_FILE" <<EOF
# LDAP Configuration
LDAP_URI=$LDAP_URI
LDAP_BASE=$LDAP_BASE
LDAP_ADMIN_DN=$LDAP_ADMIN_DN

# SSH Configuration
FORCE_SSHD=$FORCE_SSHD
EOF
    
    log "Configuration file $ENV_FILE created successfully."
}

# Function to detect package manager
detect_package_manager() {
    # Check for macOS first (regardless of whether brew is installed)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos-native"
        return 0
    fi
    
    local package_managers=("apt-get:apt" "dnf:dnf" "yum:yum" "pacman:pacman")
    
    for pm in "${package_managers[@]}"; do
        IFS=':' read -r cmd name <<< "$pm"
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$name"
            return 0
        fi
    done
    
    log "Error: Unsupported package manager"
    exit 1
}

# Function to detect OS and version
detect_os_version() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos-$(sw_vers -productVersion)"
    elif [ -f /etc/arch-release ]; then
        echo "arch-linux"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID-$VERSION_ID"
    else
        echo "unknown"
    fi
}

# Function to install packages based on package manager
install_packages() {
    local package_manager=$1
    local packages=$(get_packages "$package_manager")
    log "Installing packages with $package_manager..."
    
    case $package_manager in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            sudo apt-get update
            sudo apt-get install -y $packages
            sudo rm -rf /var/lib/apt/lists/*
            unset DEBIAN_FRONTEND
            ;;
        yum)
            sudo yum install -y $packages
            ;;
        dnf)
           sudo dnf install -y $packages
           ;;
        pacman)
            setup_pacman_keyring
            sudo pacman -Syy --noconfirm
            printf 'y\n' | sudo pacman -S --needed base-devel
            for package in $packages; do
                sudo pacman -S --noconfirm --needed "$package"
            done
            sudo pacman -Sc --noconfirm
            ;;
        macos-native)
            # No package installation needed on macOS - all tools are built-in
            log "Using native macOS tools - no package installation required"
            ;;
    esac
}

setup_pacman_keyring() {
    log "Setting up pacman keyring..."
    sudo mkdir -p /etc/pacman.d/gnupg
    sudo chmod 700 /etc/pacman.d/gnupg
    sudo pacman-key --init
    sudo pacman-key --populate archlinux
}

# Function to check if SSH service is enabled
is_ssh_enabled() {
    if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
        # On macOS, check if SSH is enabled in System Preferences
        sudo systemsetup -getremotelogin 2>/dev/null | grep -q "On"
    else
        local service_name="ssh"
        [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
        
        systemctl is-enabled "$service_name" >/dev/null 2>&1
    fi
}

# Function to set up SSH
setup_ssh() {
    log "Checking SSH service status..."
    
    # Check if SSH configuration is forced
    if [[ "$FORCE_SSHD" == "false" ]]; then
        log "SSH configuration is disabled by user preference (FORCE_SSHD=false). Skipping SSH setup."
        return 0
    fi
    
    local ssh_enabled=false
    if is_ssh_enabled; then
        ssh_enabled=true
    fi
    
    if [[ "$FORCE_SSHD" == "true" ]]; then
        if [ "$ssh_enabled" = true ]; then
            log "SSH service is enabled. Configuring SSH for LDAP authentication..."
        else
            log "SSH service is disabled, but FORCE_SSHD=true. Configuring SSH anyway..."
            log "Warning: You'll need to enable SSH manually after configuration:"
            if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
                log "  - System Preferences > Sharing > Remote Login"
                log "  - Or: sudo systemsetup -setremotelogin on"
            else
                local service_name="ssh"
                [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
                log "  - sudo systemctl enable $service_name"
                log "  - sudo systemctl start $service_name"
            fi
        fi
    else
        # FORCE_SSHD is not set, use default behavior
        if ! is_ssh_enabled; then
            log "SSH service is not enabled. Skipping SSH configuration to avoid unwanted exposure."
            log "If you want to enable SSH, please do so manually:"
            if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
                log "  - System Preferences > Sharing > Remote Login"
                log "  - Or: sudo systemsetup -setremotelogin on"
            else
                local service_name="ssh"
                [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
                log "  - sudo systemctl enable $service_name"
                log "  - sudo systemctl start $service_name"
            fi
            return 0
        fi
        
        log "SSH service is enabled. Configuring SSH for LDAP authentication..."
    fi
    
    sudo mkdir -p /var/run/sshd
    
    # Configure SSH
    configure_ssh_authentication
    generate_ssh_keys
    
    # Restart SSH service to apply changes (only if it's currently enabled)
    if [ "$ssh_enabled" = true ]; then
        if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
            # macOS uses launchctl for service management
            exec_log sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true
            exec_log sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || log "SSH service restart failed"
        else
            local service_name="ssh"
            [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
            
            if command -v service >/dev/null 2>&1; then
                exec_log sudo service "$service_name" restart
            else
                exec_log sudo /usr/sbin/sshd
            fi

        fi
    else
        log "SSH service is disabled - configuration applied but service not restarted."
    fi
}

configure_ssh_authentication() {
    # Define SSH configuration settings
    local ssh_settings=(
        "PasswordAuthentication yes"
        "PermitRootLogin yes"
        "PubkeyAuthentication yes"
        "UsePAM yes"
        "KbdInteractiveAuthentication yes"
        "Port 22"
        "Protocol 2"
    )

    # Apply each configuration setting
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "$setting" | cut -d' ' -f1)
        local value=$(echo "$setting" | cut -d' ' -f2-)
        
        if sudo grep -q "^$key" "$SSH_CONF"; then
            # Use macOS-compatible sed syntax with backup extension
            exec_log sudo sed -i.bak "s/^$key .*/$key $value/" "$SSH_CONF"
        else
            exec_log echo "$key $value" | sudo tee -a "$SSH_CONF" > /dev/null
        fi
    done
}


generate_ssh_keys() {
    log "Generating SSH keys if not present..."
    local key_types=("rsa" "ecdsa" "ed25519")
    
    for type in "${key_types[@]}"; do
        local key_file="/etc/ssh/ssh_host_${type}_key"
        if [ ! -f "$key_file" ]; then
            log "Generating $type SSH key..."
            sudo ssh-keygen -t "$type" -f "$key_file" -N ""
        fi
    done
}

# Function to set up LDAP client
setup_ldap_client() {
    if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
        log "Skipping LDAP client config on macOS - using native Directory Services instead"
        return 0
    fi

    log "Setting up LDAP client..."
    sudo mkdir -p /etc/ldap
    
    sudo tee /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT never
EOL
}

# Function to set up SSSD
setup_sssd() {
    if [ "$PACKAGE_MANAGER" = "macos-native" ]; then
        log "Skipping SSSD setup on macOS - using native Directory Services instead"
        return 0
    fi

    log "Setting up SSSD..."
    create_sssd_config
    configure_nss
    
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        configure_arch_pam
    elif [ "$PACKAGE_MANAGER" = "yum" ] || [ "$PACKAGE_MANAGER" = "dnf" ]; then
        configure_sssd_authselect
    fi
    
    exec_log sudo systemctl enable sssd
    if pidof systemd >/dev/null 2>&1; then
        exec_log sudo systemctl restart sssd
    else
        log "systemd not detected — starting SSSD manually..."
        sudo pkill sssd 2>/dev/null || true
        sudo sssd -D &
        sleep 2
    fi
}

create_sssd_config() {
    # Ensure CA_CERT path is set if not already done
    if [ -z "$CA_CERT" ]; then
        CA_CERT=$(get_ca_cert_path)
    fi
    
    sudo tee "$SSSD_CONF" <<EOL
[sssd]
domains = LDAP
config_file_version = 2
services = nss, pam, ssh

[domain/LDAP]
debug_level = 9
id_provider = ldap
auth_provider = ldap
ldap_uri = ${LDAP_URI}
ldap_enforce_password_policy = false
ldap_search_base = ${LDAP_BASE}

ldap_connection_expire_timeout = 30
ldap_connection_expire_offset = 0
ldap_account_expire_policy = ad
ldap_network_timeout = 30
ldap_opt_timeout = 30
ldap_timeout = 30

ldap_tls_cacert = ${CA_CERT}
ldap_tls_reqcert = never
ldap_id_use_start_tls = false
ldap_schema = rfc2307

cache_credentials = true
enumerate = true

ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_gecos = gecos
ldap_user_shadow_last_change = shadowLastChange

[pam]
pam_response_filter = ENV
pam_verbosity = 3
pam_id_timeout = 30
pam_pwd_response_prompt = Password: 
pam_pwd_response_timeout = 30

EOL

    sudo chmod 600 "$SSSD_CONF"
}

configure_nss() {
    sudo tee /etc/nsswitch.conf <<EOL
passwd: files sss
shadow: files sss
group:  files sss
hosts: files dns myhostname
EOL
}

configure_arch_pam() {
    log "Configuring PAM for Arch Linux..."
    
    # Configure PAM for SSSD
    sudo tee /etc/pam.d/system-auth <<EOL
#%PAM-1.0
auth     sufficient pam_sss.so forward_pass
auth     required  pam_unix.so try_first_pass nullok
auth     optional  pam_permit.so

account  sufficient pam_sss.so
account  required  pam_unix.so
account  optional  pam_permit.so

password sufficient pam_sss.so use_authtok
password required  pam_unix.so try_first_pass nullok sha512 shadow
password optional  pam_permit.so

session  required  pam_limits.so
session  required  pam_unix.so
session  optional  pam_sss.so
session  required  pam_mkhomedir.so skel=/etc/skel umask=0077
EOL

    # Configure PAM for SSHD
    sudo tee /etc/pam.d/sshd <<EOL
#%PAM-1.0
auth     include  system-auth
account  include  system-auth
password include  system-auth
session  include  system-auth
EOL
}


configure_sssd_authselect() {
    sudo authselect select sssd --force
}

# Function to get CA certificate path based on distribution
get_ca_cert_path() {
    case $PACKAGE_MANAGER in
        apt)
            echo "/etc/ssl/certs/ldap-ca-cert.pem"
            ;;
        yum|dnf)
            echo "/etc/pki/tls/certs/ldap-ca-cert.pem"
            ;;
        pacman)
            echo "/etc/ca-certificates/trust-source/anchors/ldap-ca-cert.pem"
            ;;
        macos-native)
            echo "/tmp/ldap-ca-cert.pem"  # Temporary location before adding to keychain
            ;;
        *)
            echo "/etc/ssl/certs/ldap-ca-cert.pem"
            ;;
    esac
}

# Function to set up TLS
setup_tls() {
    log "Setting up TLS..."
    
    # Set CA certificate path based on distribution
    CA_CERT=$(get_ca_cert_path)
    
    # Create directory if it doesn't exist
    sudo mkdir -p "$(dirname "$CA_CERT")"

    # Extract certificate directly to the target location
    if [[ "$LDAP_URI" =~ ^ldaps:// ]]; then
        log "Extracting certificate directly to $CA_CERT..."
        if ! extract_ca_certificate "$LDAP_URI" | sudo tee "$CA_CERT" > /dev/null; then
            log "Warning: Could not extract certificate for LDAPS connection"
            log "You may need to manually install the CA certificate"
        else
            sudo chmod 644 "$CA_CERT"
            update_ca_certificates
        fi
    else
        log "Non-LDAPS connection, no certificate setup needed"
    fi
}


update_ca_certificates() {
    log "Updating CA certificates..."
    case $PACKAGE_MANAGER in
        apt)
            # For Debian/Ubuntu, copy to the ca-certificates directory and update
            local src="$CA_CERT"
            local dst="/usr/local/share/ca-certificates/ldap-ca-cert.crt"

            # Only copy if source and destination are different
            if [ "$(realpath "$src")" != "$(realpath "$dst")" ]; then
                exec_log sudo cp -f "$src" "$dst"
            else
                log "Skipping copy — source and destination are the same file"
            fi

            exec_log sudo update-ca-certificates --fresh
            ;;
        yum|dnf)
            exec_log sudo cp "$CA_CERT" /etc/pki/ca-trust/source/anchors/ldap-ca-cert.pem
            exec_log sudo update-ca-trust extract
            ;;
        pacman)
            exec_log sudo update-ca-trust
            ;;
        macos-native)
            exec_log sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT"
            ;;
    esac
}

configure_pam_mkhomedir() {
    log "Configuring PAM for SSHD to enable pam_mkhomedir..."
    PAM_FILE="/etc/pam.d/sshd"

    if ! sudo grep -q "pam_mkhomedir.so" "$PAM_FILE"; then
        log "Adding pam_mkhomedir.so configuration to $PAM_FILE..."
        echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" | sudo tee -a "$PAM_FILE"
    else
        log "pam_mkhomedir.so is already configured in $PAM_FILE. Skipping."
    fi
}

configure_sudo_access() {
    log "Granting sudo access to LDAP group..."
    echo '%#9999 ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/proxmox-sudo
    sudo chmod 440 /etc/sudoers.d/proxmox-sudo
}

# Function to set up LDAP on macOS using native Directory Services
setup_macos_ldap() {
    log "Setting up LDAP on macOS using native Directory Services..."
    
    # Check if LDAP_URI is set
    if [ -z "$LDAP_URI" ]; then
        log "Error: LDAP_URI is not set. Cannot configure LDAP directory service."
        log "Debug: Current environment variables:"
        log "  LDAP_URI='$LDAP_URI'"
        log "  LDAP_BASE='$LDAP_BASE'"
        log "  LDAP_ADMIN_DN='$LDAP_ADMIN_DN'"
        return 1
    fi
    
    # Parse LDAP URI to get components
    local ldap_host port protocol
    if [[ "$LDAP_URI" =~ ^(ldaps?)://([^:]+):?([0-9]+)?$ ]]; then
        protocol="${BASH_REMATCH[1]}"
        ldap_host="${BASH_REMATCH[2]}"
        port="${BASH_REMATCH[3]}"
        
        # Default ports if not specified
        if [ -z "$port" ]; then
            if [ "$protocol" = "ldaps" ]; then
                port=636
            else
                port=389
            fi
        fi
    else
        log "Error: Could not parse LDAP URI: '$LDAP_URI'"
        return 1
    fi
    
    # Use dsconfigldap to configure LDAP directory service
    log "Configuring LDAP directory service with dsconfigldap..."
    log "  Server: $ldap_host:$port"
    log "  Base DN: $LDAP_BASE"
    log "  Protocol: $protocol"
    
    # Build dsconfigldap command
    local dsconfigldap_cmd="sudo dsconfigldap -v -a '$ldap_host' -n '/LDAPv3/$ldap_host'"
    
    # Add SSL option for LDAPS
    if [ "$protocol" = "ldaps" ]; then
        dsconfigldap_cmd="$dsconfigldap_cmd -x"  # -x enables SSL connection
    fi
    
    # Execute the configuration
    if exec_log eval "$dsconfigldap_cmd"; then
        log "Successfully configured LDAP directory service"
        
        # Set search base
        log "Setting LDAP search base to: $LDAP_BASE"
        exec_log sudo dscl localhost -create "/LDAPv3/$ldap_host" "SearchBase" "$LDAP_BASE"
        
        log "LDAP directory service configured successfully"
        log "You can manage this configuration using:"
        log "  - Directory Utility.app (GUI)"
        log "  - dscl localhost -read '/LDAPv3/$ldap_host' (command line)"
    else
        log "Warning: dsconfigldap failed. You may need to configure LDAP manually using Directory Utility.app"
        log "Manual configuration steps:"
        log "  1. Open Directory Utility.app"
        log "  2. Click the lock and authenticate"
        log "  3. Enable LDAPv3"
        log "  4. Add server: $ldap_host:$port"
        log "  5. Set search base: $LDAP_BASE"
        if [ "$protocol" = "ldaps" ]; then
            log "  6. Enable SSL/TLS"
        fi
    fi
}

# Function to create backups before making changes
create_backups() {
    log "Creating backups of original configuration files to $BACKUP_DIR ..."
    sudo mkdir -p "$BACKUP_DIR"
    
    # Backup SSH configuration
    if [ -f "$SSH_CONF" ]; then
        sudo cp "$SSH_CONF" "$BACKUP_DIR/sshd_config.backup"
        log "Backed up SSH configuration"
    fi
    
    # Backup PAM files
    if [ -f "$PAM_SSHD" ]; then
        sudo cp "$PAM_SSHD" "$BACKUP_DIR/pam_sshd.backup"
        log "Backed up PAM SSHD configuration"
    fi
    
    if [ -f "$PAM_SYSTEM_AUTH" ]; then
        sudo cp "$PAM_SYSTEM_AUTH" "$BACKUP_DIR/pam_system_auth.backup"
        log "Backed up PAM system-auth configuration"
    fi
    
    # Backup NSS configuration
    if [ -f "/etc/nsswitch.conf" ]; then
        sudo cp "/etc/nsswitch.conf" "$BACKUP_DIR/nsswitch.conf.backup"
        log "Backed up NSS configuration"
    fi
    
    # Create undo info file
    sudo tee "$BACKUP_DIR/undo_info.txt" > /dev/null <<EOF
# LDAP Configuration Undo Information
# Created: $(date)
LDAP_URI=${LDAP_URI:-}
LDAP_BASE=${LDAP_BASE:-}
LDAP_ADMIN_DN=${LDAP_ADMIN_DN:-}
CA_CERT=${CA_CERT:-}
PACKAGE_MANAGER=${PACKAGE_MANAGER:-}
EOF
    
    log "Backup completed in $BACKUP_DIR"
}

# Function to undo LDAP configuration
undo_ldap_setup() {
    log "Starting LDAP configuration undo..."
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log "Error: No backup directory found at $BACKUP_DIR"
        log "Cannot undo without backups. Please run the script normally first."
        exit 1
    fi
    
    # Load undo information
    if [ -f "$BACKUP_DIR/undo_info.txt" ]; then
        source "$BACKUP_DIR/undo_info.txt"
        log "Loaded configuration from backups"
    fi
    
    # Detect current package manager
    local current_pm=$(detect_package_manager)
    
    case $current_pm in
        macos-native)
            undo_macos_ldap
            ;;
        *)
            undo_linux_ldap "$current_pm"
            ;;
    esac
    
    # Restore configuration files
    restore_config_files
    
    # Remove environment file
    if [ -f "$ENV_FILE" ]; then
        exec_log sudo rm -f "$ENV_FILE"
        log "Removed LDAP environment configuration"
    fi
    
    log "LDAP configuration undo completed successfully"
}

# Function to undo macOS LDAP configuration
undo_macos_ldap() {
    # Parse LDAP URI if available
    if [ -n "$LDAP_URI" ]; then
        local ldap_host
        if [[ "$LDAP_URI" =~ ^ldaps?://([^:]+) ]]; then
            ldap_host="${BASH_REMATCH[1]}"
            
            # Remove LDAP directory configuration
            if dscl localhost -list /LDAPv3 | grep -q "$ldap_host"; then
                log "Removing LDAP directory: /LDAPv3/$ldap_host"
                exec_log sudo dscl localhost -delete "/LDAPv3/$ldap_host" 2>/dev/null || log "LDAP directory already removed"
            fi
        fi
    fi
    
    # Remove certificate from keychain if it exists
    if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
        local cert_name=$(openssl x509 -noout -subject -in "$CA_CERT" 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
        if [ -n "$cert_name" ]; then
            exec_log sudo security delete-certificate -c "$cert_name" /Library/Keychains/System.keychain 2>/dev/null || log "Certificate not found in keychain"
            log "Removed certificate for $cert_name from keychain"
        fi
        exec_log sudo rm -f "$CA_CERT"
    fi    
}

# Function to undo Linux LDAP configuration
undo_linux_ldap() {
    local package_manager=$1
    log "Undoing Linux LDAP configuration for $package_manager..."
    
    # Stop and disable SSSD service
    if systemctl is-active --quiet sssd 2>/dev/null; then
        exec_log sudo systemctl stop sssd
        log "Stopped SSSD service"
    fi
    
    if systemctl is-enabled --quiet sssd 2>/dev/null; then
        exec_log sudo systemctl disable sssd
        log "Disabled SSSD service"
    fi
    
    # Remove SSSD configuration
    if [ -f "$SSSD_CONF" ]; then
        exec_log sudo rm -f "$SSSD_CONF"
        log "Removed SSSD configuration"
    fi
    
    # Remove LDAP client configuration
    if [ -f "/etc/ldap/ldap.conf" ]; then
        exec_log sudo rm -f "/etc/ldap/ldap.conf"
        log "Removed LDAP client configuration"
    fi
    
    # Remove CA certificate
    if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
        exec_log sudo rm -f "$CA_CERT"
        log "Removed LDAP CA certificate"
        
        # Update CA certificates
        case $package_manager in
            apt)
                exec_log sudo rm -f /usr/local/share/ca-certificates/ldap-ca-cert.crt
                exec_log sudo update-ca-certificates --fresh
                ;;
            yum|dnf)
                exec_log sudo rm -f /etc/pki/ca-trust/source/anchors/ldap-ca-cert.pem
                exec_log sudo update-ca-trust extract
                ;;
            pacman)
                sudo update-ca-trust
                ;;
        esac
    fi
    
    # Clear SSSD cache
    exec_log sudo rm -rf /var/lib/sss/db/* 2>/dev/null || true
    
    log "Linux LDAP configuration removed"
}

# Function to restore original configuration files
restore_config_files() {
    # Restore SSH configuration
    if [ -f "$BACKUP_DIR/sshd_config.backup" ]; then
        exec_log sudo cp "$BACKUP_DIR/sshd_config.backup" "$SSH_CONF"
        log "Restored SSH configuration"
        
        # Restart SSH service
        local package_manager=$(detect_package_manager)
        if [ "$package_manager" = "macos-native" ]; then
            exec_log sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true
            exec_log sudo launchctl load /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true
        else
            local service_name="ssh"
            [[ "$package_manager" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
            exec_log sudo systemctl restart "$service_name" 2>/dev/null || log "Could not restart SSH service"
        fi
    fi
    
    # Restore PAM configurations
    if [ -f "$BACKUP_DIR/pam_sshd.backup" ]; then
        sudo cp "$BACKUP_DIR/pam_sshd.backup" "$PAM_SSHD"
        log "Restored PAM SSHD configuration"
    fi
    
    if [ -f "$BACKUP_DIR/pam_system_auth.backup" ]; then
        sudo cp "$BACKUP_DIR/pam_system_auth.backup" "$PAM_SYSTEM_AUTH"
        log "Restored PAM system-auth configuration"
    fi
    
    # Restore NSS configuration
    if [ -f "$BACKUP_DIR/nsswitch.conf.backup" ]; then
        sudo cp "$BACKUP_DIR/nsswitch.conf.backup" "/etc/nsswitch.conf"
        log "Restored NSS configuration"
    fi
    
    # Remove sudo access file
    if [ -f "/etc/sudoers.d/proxmox-sudo" ]; then
        exec_log sudo rm -f "/etc/sudoers.d/proxmox-sudo"
        log "Removed LDAP sudo access configuration"
    fi
}

# Main execution
main() {
    # Handle undo mode
    echo 
    if [ "$UNDO_MODE" = true ]; then
        log "Starting LDAP configuration undo..."
        undo_ldap_setup
        return 0
    fi
    
    log "Starting system setup..."
    
    # Get domain from command line argument if provided
    local provided_domain="$DOMAIN_ARG"
    
    # Check for .env file and prompt if missing
    if [ ! -f "$ENV_FILE" ]; then
        log "Environment file $ENV_FILE not found. Starting interactive configuration..."
        prompt_for_env_vars "$provided_domain"
        confirm_configuration
    else
        log "Loading environment variables from $ENV_FILE..."
        log "Environment file contents:"
        cat "$ENV_FILE" | while read line; do log "  $line"; done
        log "Loaded variables: LDAP_URI='$LDAP_URI' LDAP_BASE='$LDAP_BASE' LDAP_ADMIN_DN='$LDAP_ADMIN_DN'"
    fi
    
    # Detect system configuration
    PACKAGE_MANAGER=$(detect_package_manager)
    OS_VERSION=$(detect_os_version)
    log "Detected package manager: $PACKAGE_MANAGER"
    log "Detected OS version: $OS_VERSION"
    
    # Create backups before making changes
    create_backups
    
    # Install necessary packages
    install_packages "$PACKAGE_MANAGER"
    
    # Set up services
    setup_ssh
    setup_ldap_client
    setup_sssd
    setup_tls
    configure_pam_mkhomedir
    configure_sudo_access
    
    # Additional setup for specific distributions
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        exec_log sudo systemctl enable --now sssd
        exec_log sudo systemctl enable --now sshd
        exec_log sudo sss_cache -E
        exec_log sudo rm -rf /var/lib/sss/db/*
        exec_log sudo systemctl restart sssd
    elif [ "$PACKAGE_MANAGER" = "macos-native" ]; then
        setup_macos_ldap
        log "macOS setup complete. LDAP directory service configured."
        log "You can verify the configuration using Directory Utility.app or 'dscl localhost -list /LDAPv3'"
    fi
    
    log "Setup completed successfully."
}

# Execute main function
main