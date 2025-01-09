#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs)
else
    echo "Error: .env file not found in the current directory."
    exit 1
fi

# Configuration variables
readonly SSSD_CONF="/etc/sssd/sssd.conf"
readonly SSH_CONF="/etc/ssh/sshd_config"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"

# Package lists for different package managers
declare -A PACKAGES
PACKAGES[apt]="ldap-utils openssh-client openssh-server sssd sssd-ldap sssd-tools sudo libnss-sss libpam-sss ca-certificates vim net-tools iputils-ping oddjob oddjob-mkhomedir"
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
        # Add specific detection for Ubuntu
        if [[ "$ID" == "ubuntu" ]]; then
            echo "ubuntu-$VERSION_ID"
        else
            echo "$ID-$VERSION_ID"
        fi
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
              # Verify sssd-tools installation
    if ! command -v sss_cache >/dev/null 2>&1; then
        echo "sss_cache not found after installation. Attempting to install sssd-tools separately..."
        sudo apt-get install -y sssd-tools
    fi
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
    # Update or add PasswordAuthentication
    if sudo grep -q "^PasswordAuthentication no" "$SSH_CONF"; then
        sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$SSH_CONF"
    else
        echo "PasswordAuthentication yes" | sudo tee -a "$SSH_CONF"
    fi
    
    # Add standard SSH configuration
    sudo tee -a "$SSH_CONF" <<EOL
Port 22
PermitRootLogin yes
UsePAM yes
EOL
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
    
    sudo tee /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT allow
EOL
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
    sudo tee "$SSSD_CONF" <<EOL
[sssd]
config_file_version = 2
services = nss, pam, ssh
domains = LDAP

[domain/LDAP]
debug_level = 9
access_provider = ldap
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = $LDAP_URI
ldap_search_base = $LDAP_BASE
ldap_default_bind_dn = $LDAP_ADMIN_DN
ldap_default_authtok = $LDAP_ADMIN_PW
ldap_tls_reqcert = never
cache_credentials = true
enumerate = true
ldap_id_use_start_tls = false
ldap_tls_cacert = $CA_CERT
ldap_user_object_class = posixAccount
ldap_group_object_class = posixGroup
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_uid = uid
ldap_user_name = uid
ignore_missing_attributes = True
ldap_access_order = filter
ldap_access_filter = (objectClass=posixAccount)
ldap_user_ssh_public_key = sshPublicKey
ldap_auth_disable_tls_never_use_in_production = true
ldap_group_name = cn
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
    sudo authselect select sssd --force
    sudo authselect enable-feature with-mkhomedir
}

# Add Ubuntu-specific PAM configuration
configure_ubuntu_pam() {
    if [[ "$OS_VERSION" == ubuntu* ]]; then
        echo "Configuring PAM for Ubuntu..."
        
        # Configure common-session for home directory creation
        if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
            echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" | \
                sudo tee -a /etc/pam.d/common-session
        fi
        
        # Configure common-auth for SSSD
        sudo sed -i '/^auth.*pam_unix.so/i auth sufficient pam_sss.so use_first_pass' /etc/pam.d/common-auth
        
        # Configure common-account for SSSD
        sudo sed -i '/^account.*pam_unix.so/i account [default=bad success=ok user_unknown=ignore] pam_sss.so' /etc/pam.d/common-account
        
        # Configure common-password for SSSD
        sudo sed -i '/^password.*pam_unix.so/i password sufficient pam_sss.so use_authtok' /etc/pam.d/common-password
    fi
}

# Function to set up TLS
setup_tls() {
    log "Setting up TLS..."
    echo "$CA_CERT_CONTENT" | sudo tee /etc/ssl/certs/ca-cert.pem > /dev/null
    sudo chmod 644 /etc/ssl/certs/ca-cert.pem
    
    update_ca_certificates
}

update_ca_certificates() {
    log "Updating CA certificates..."
    case $PACKAGE_MANAGER in
        apt)    sudo update-ca-certificates ;;
        yum)    sudo update-ca-trust extract ;;
        pacman) sudo update-ca-trust ;;
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
    setup_ldap_client
    setup_sssd
    if [[ "$OS_VERSION" == ubuntu* ]]; then
    configure_ubuntu_pam
    
    # Ensure SSSD service is properly configured
    sudo systemctl enable sssd
    sudo systemctl restart sssd
    
    # Clear SSSD cache after configuration
    sudo sss_cache -E
    sudo rm -rf /var/lib/sss/db/*
    sudo systemctl restart sssd
fi
    setup_tls
    configure_pam_mkhomedir
    
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