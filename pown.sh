#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Load environment variables from .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
    echo "Successfully imported environment variables from .env"
else
    echo "Warning: .env file not found, skipping environment variable import"
fi

# Configuration variables
readonly SSSD_CONF="/etc/sssd/sssd.conf"
readonly SSH_CONF="/etc/ssh/sshd_config"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"

# Package lists for different package managers
declare -A PACKAGES
PACKAGES[apt]="ldap-utils openssh-client openssh-server sssd sssd-ldap sudo libnss-sss libpam-sss ca-certificates vim net-tools iputils-ping"
PACKAGES[yum]="openssh-clients openssh-server sssd sssd-ldap sudo openldap-clients ca-certificates vim net-tools iputils authselect authconfig"
PACKAGES[pacman]="openssh sssd openldap sudo ca-certificates vim net-tools iputils pam pambase"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to detect package manager
detect_package_manager() {
    local package_managers=("apt-get:apt" "yum:yum" "pacman:pacman")
    
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
    if [ -f /etc/arch-release ]; then
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
    log "Installing packages with $package_manager..."
    
    case $package_manager in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            sudo apt-get update
            sudo apt-get install -y ${PACKAGES[apt]}
            sudo rm -rf /var/lib/apt/lists/*
            unset DEBIAN_FRONTEND
            ;;
        yum)
            sudo yum install -y ${PACKAGES[yum]}
            ;;
        pacman)
            setup_pacman_keyring
            sudo pacman -Syy --noconfirm
            printf 'y\n' | sudo pacman -S --needed base-devel
            for package in ${PACKAGES[pacman]}; do
                sudo pacman -S --noconfirm --needed "$package"
            done
            sudo pacman -Sc --noconfirm
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

# Function to set up SSH
setup_ssh() {
    log "Setting up SSH..."
    sudo mkdir -p /var/run/sshd
    
    # Configure SSH
    configure_ssh_authentication
    generate_ssh_keys
    
    # Start and enable SSH service
    local service_name="ssh"
    [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman)$ ]] && service_name="sshd"
    
    sudo systemctl enable "$service_name"
    sudo systemctl restart "$service_name"
}

configure_ssh_authentication() {
    # Define desired SSH configuration as key-value pairs
    declare -A ssh_config=(
        ["PasswordAuthentication"]="yes"
        ["PermitRootLogin"]="yes"
        ["PubkeyAuthentication"]="yes"
        ["UsePAM"]="yes"
        ["KbdInteractiveAuthentication"]="yes"
        ["Port"]="22"
        ["Protocol"]="2"
    )

    # Iterate through each configuration and update or add it
    for key in "${!ssh_config[@]}"; do
        if sudo grep -q "^$key" "$SSH_CONF"; then
            sudo sed -i "s/^$key .*/$key ${ssh_config[$key]}/" "$SSH_CONF"
        else
            echo "$key ${ssh_config[$key]}" | sudo tee -a "$SSH_CONF" > /dev/null
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
    log "Setting up LDAP client..."
    sudo mkdir -p /etc/ldap
    
    # Different config based on OS
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        sudo tee /etc/openldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
TLS_REQCERT never
EOL
    else
        sudo tee /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
TLS_REQCERT allow
EOL
    fi
}

# Function to set up SSSD
setup_sssd() {
    log "Setting up SSSD..."
    create_sssd_config
    configure_nss
    
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        configure_arch_pam
    elif [ "$PACKAGE_MANAGER" = "yum" ] && [[ "$OS_VERSION" == "amzn-2023" ]]; then
        configure_amazon_linux_auth
    fi
    
    sudo systemctl enable sssd
    sudo systemctl restart sssd
}

create_sssd_config() {
    # Determine CA cert path based on OS
    local ca_cert_path="/etc/ssl/certs/ca-cert.pem"
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        ca_cert_path="/etc/pki/ca-trust/source/anchors/ca-cert.pem"
    fi
    
    sudo tee "$SSSD_CONF" <<EOL
[sssd]
domains = LDAP
config_file_version = 2
services = nss, pam

[domain/LDAP]
debug_level = 9
id_provider = ldap
auth_provider = ldap
ldap_uri = $LDAP_URI
ldap_enforce_password_policy = false
ldap_search_base = dc=mieweb,dc=com

ldap_connection_expire_timeout = 30
ldap_connection_expire_offset = 0
ldap_account_expire_policy = ad
ldap_network_timeout = 30
ldap_opt_timeout = 30
ldap_timeout = 30

ldap_tls_cacert = ${ca_cert_path}
ldap_tls_reqcert = never
ldap_id_use_start_tls = false
ldap_schema = rfc2307

cache_credentials = True
enumerate = True

ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_gecos = gecos
ldap_user_shadow_last_change = shadowLastChange
ldap_referrals = false

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
    echo "Configuring PAM for Arch Linux..."
    
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

configure_amazon_linux_auth() {
    log "Configuring Amazon Linux authentication..."
    sudo authselect select sssd --force
    sudo authselect enable-feature with-mkhomedir
    
    # Ensure home directory creation works
    sudo systemctl restart oddjobd
    sudo systemctl enable oddjobd
}

# Function to set up TLS
setup_tls() {
    log "Setting up TLS..."
    
    # Write cert to different locations based on OS
    echo "$CA_CERT_CONTENT" | sudo tee /etc/ssl/certs/ca-cert.pem > /dev/null
    sudo chmod 644 /etc/ssl/certs/ca-cert.pem
    sudo chown root:root /etc/ssl/certs/ca-cert.pem
    
    # Special handling for Amazon Linux
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        # Create Amazon Linux specific cert directories
        sudo mkdir -p /etc/pki/ca-trust/source/anchors/
        echo "$CA_CERT_CONTENT" | sudo tee /etc/pki/ca-trust/source/anchors/ca-cert.pem > /dev/null
        sudo chmod 644 /etc/pki/ca-trust/source/anchors/ca-cert.pem
        
        # Create OpenLDAP cert directory
        sudo mkdir -p /etc/openldap/certs/
        echo "$CA_CERT_CONTENT" | sudo tee /etc/openldap/certs/ca-cert.pem > /dev/null
        sudo chmod 644 /etc/openldap/certs/ca-cert.pem
        
        # Also create a symbolic link to ensure cert is found
        sudo ln -sf /etc/pki/ca-trust/source/anchors/ca-cert.pem /etc/pki/tls/certs/ca-cert.pem
    fi
    
    update_ca_certificates
}

update_ca_certificates() {
    log "Updating CA certificates..."
    case $PACKAGE_MANAGER in
        apt)    
            sudo update-ca-certificates 
            ;;
        yum)    
            sudo update-ca-trust extract
            if [[ "$OS_VERSION" == "amzn-2023" ]]; then
                # Amazon Linux specific - rehash OpenLDAP certs
                if command -v cacertdir_rehash >/dev/null 2>&1; then
                    sudo cacertdir_rehash /etc/openldap/certs/
                fi
                # Try alternatives for cert rehashing
                if command -v c_rehash >/dev/null 2>&1; then
                    sudo c_rehash /etc/openldap/certs/
                fi
            fi
            ;;
        pacman) 
            sudo update-ca-trust 
            ;;
    esac
}

configure_pam_mkhomedir() {
    echo "Configuring PAM for SSHD to enable pam_mkhomedir..."
    PAM_FILE="/etc/pam.d/sshd"

    if ! sudo grep -q "pam_mkhomedir.so" "$PAM_FILE"; then
        echo "Adding pam_mkhomedir.so configuration to $PAM_FILE..."
        echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" | sudo tee -a "$PAM_FILE"
    else
        echo "pam_mkhomedir.so is already configured in $PAM_FILE. Skipping."
    fi
}

# Test LDAP connection
test_ldap_connection() {
    log "Testing LDAP connection..."
    
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        # Test with specified cert path for Amazon Linux
        ldapsearch -H "$LDAP_URI" -x -b "$LDAP_BASE" -Z -o ldap.tls_cacert=/etc/pki/ca-trust/source/anchors/ca-cert.pem -d 1 || true
    else
        # Standard test for other distros
        ldapsearch -H "$LDAP_URI" -x -b "$LDAP_BASE" -d 1 || true
    fi
}

fix_ldap_permissions() {
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        log "Fixing LDAP permissions for Amazon Linux..."
        sudo chmod 600 /etc/openldap/certs/ca-cert.pem
        sudo chown root:root /etc/openldap/certs/ca-cert.pem
        sudo chmod 644 /etc/openldap/ldap.conf
        sudo chown root:root /etc/openldap/ldap.conf
        
        # Fix SSSD file permissions
        sudo chmod 600 "$SSSD_CONF"
        sudo chown root:root "$SSSD_CONF"
        
        # Clear SSSD cache
        sudo sss_cache -E
        sudo rm -rf /var/lib/sss/db/*
        sudo systemctl restart sssd
    fi
}

# Main execution
main() {
    log "Starting system setup..."
    
    # Detect system configuration
    PACKAGE_MANAGER=$(detect_package_manager)
    OS_VERSION=$(detect_os_version)
    log "Detected package manager: $PACKAGE_MANAGER"
    log "Detected OS version: $OS_VERSION"
    
    # Install necessary packages
    install_packages "$PACKAGE_MANAGER"
    
    # Set up services
    setup_ssh
    setup_tls # Setup TLS before LDAP to ensure certs are available
    setup_ldap_client
    setup_sssd
    configure_pam_mkhomedir
    
    # Additional setup for Amazon Linux
    if [[ "$PACKAGE_MANAGER" == "yum" && "$OS_VERSION" == "amzn-2023" ]]; then
        fix_ldap_permissions
        
        # Restart services in proper order for Amazon Linux
        sudo systemctl restart sssd
        sudo systemctl restart sshd
        
        # Test LDAP connection
        test_ldap_connection
    fi
    
    # Additional setup for Arch Linux
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        sudo systemctl enable --now sssd
        sudo systemctl enable --now sshd
        sudo sss_cache -E
        sudo rm -rf /var/lib/sss/db/*
        sudo systemctl restart sssd
    fi
    
    log "Setup completed successfully."
}

# Execute main function
main