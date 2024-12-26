#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Load environment variables from .env file
if [ -f .env ]; then
    echo "Loading environment variables from .env file..."
    set -o allexport
    source .env
    set +o allexport
else
    echo ".env file not found. Exiting."
    exit 1
fi

echo "Environment variables loaded."

# Function to detect package manager
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "Unsupported package manager. Exiting."
        exit 1
    fi
}

echo "Starting script..."
# Detect the package manager
PACKAGE_MANAGER=$(detect_package_manager)
echo "Detected package manager: $PACKAGE_MANAGER"

# Environment variables
echo "Setting environment variables..."
export LDAP_BASE="dc=mieweb,dc=com"
export LDAP_DOMAIN="mieweb.com"
export LDAP_ORG="MIE"
export LDAP_ADMIN_DN="cn=admin,dc=mieweb,dc=com"
export LDAP_ADMIN_PW="secret"
export LDAP_CERT_SUBJ="/C=US/ST=IN/L=City/O=MIE/CN=localhost"
export LDAP_URI="ldap://8.tcp.ngrok.io:19611"
export CA_CERT="/etc/ssl/certs/ca-cert.pem"
echo "Environment variables set."

# Common configurations
setup_ssh() {
    echo "Setting up SSH..."
    mkdir -p /var/run/sshd

       # Check if PasswordAuthentication is set to 'no' and replace it with 'yes'
    if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo "Updating PasswordAuthentication to 'yes' in sshd_config..."
        sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo "Adding PasswordAuthentication yes to sshd_config..."
        echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi

    cat >> /etc/ssh/sshd_config <<EOL
Port 22
PermitRootLogin yes
UsePAM yes
EOL
    echo "SSH config written."
    if [ "$PACKAGE_MANAGER" = "yum" ]; then
        systemctl enable sshd
        systemctl restart sshd
    elif [ "$PACKAGE_MANAGER" = "apt" ]; then
        systemctl enable ssh
        systemctl restart ssh
    fi
    generate_ssh_keys
}

generate_ssh_keys() {
    echo "Generating SSH keys if not already present..."
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        echo "Generating RSA SSH key..."
        ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ecdsa_key ]; then
        echo "Generating ECDSA SSH key..."
        ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        echo "Generating ED25519 SSH key..."
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi
}

setup_ldap_client() {
    echo "Setting up LDAP client..."
    mkdir -p /etc/ldap
    cat > /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT allow
EOL
    echo "LDAP client config written."
}

setup_sssd() {
    echo "Setting up SSSD..."
    cat > /etc/sssd/sssd.conf <<EOL
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
    chmod 600 /etc/sssd/sssd.conf

 # Configure SSSD based on the package manager
if [ "$PACKAGE_MANAGER" = "yum" ]; then
    # Add Red Hat specific authentication configuration
    authselect select sssd --force
    authselect enable-feature with-mkhomedir
fi

# Ensure SSSD service is enabled and restarted
systemctl enable sssd
systemctl restart sssd
  
    echo "SSSD config written and permissions set."
}

setup_tls() {
    echo "Setting up TLS..."

     if [ -z "$CA_CERT_CONTENT" ]; then
        echo "Error: CA_CERT_CONTENT environment variable is not set"
        exit 1
    fi

    # Write the certificate directly
    echo "$CA_CERT_CONTENT" > /etc/ssl/certs/ca-cert.pem

    chmod 644 /etc/ssl/certs/ca-cert.pem
    echo "TLS certificate written."

    # Update CA certificates based on the package manager
    echo "Updating CA certificates..."
    if [ "$PACKAGE_MANAGER" = "apt" ]; then
        update-ca-certificates
    elif [ "$PACKAGE_MANAGER" = "yum" ]; then
        update-ca-trust extract
    elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
        update-ca-trust
    fi
    echo "CA certificates updated."
}

configure_pam_mkhomedir() {
    echo "Configuring PAM for SSHD to enable pam_mkhomedir..."
    
    PAM_FILE="/etc/pam.d/sshd"

    # Check if the pam_mkhomedir.so line already exists
    if ! grep -q "pam_mkhomedir.so" "$PAM_FILE"; then
        # Add the pam_mkhomedir.so configuration to the PAM file
        echo "Adding pam_mkhomedir.so configuration to $PAM_FILE..."
        echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" >> "$PAM_FILE"
    else
        echo "pam_mkhomedir.so is already configured in $PAM_FILE. Skipping."
    fi
}


install_packages_apt() {
    echo "Installing packages with apt..."
    apt-get update && apt-get install -y \
        ldap-utils \
        openssh-client \
        openssh-server \
        sssd \
        sssd-ldap \
        sudo \
        libnss-ldap \
        libpam-ldap \
        ca-certificates \
        vim \
        net-tools \
        iputils-ping && \
        rm -rf /var/lib/apt/lists/*
    echo "Packages installed."
}

install_packages_yum() {
    echo "Installing packages with yum..."
    yum install -y \
        openssh-clients \
        openssh-server \
        sssd \
        sssd-ldap \
        sudo \
        openldap-clients \
        ca-certificates \
        vim \
        net-tools \
        iputils \
        authselect
    echo "Packages installed."
}

install_packages_pacman() {
    echo "Installing packages with pacman..."
    pacman -Sy --noconfirm \
        openssh \
        sssd \
        openldap \
        sudo \
        nsswitch \
        ca-certificates \
        vim \
        net-tools \
        iputils
    echo "Packages installed."
}

# Install the necessary packages
echo "Installing necessary packages..."
echo $PACKAGE_MANAGER
if [ "$PACKAGE_MANAGER" = "apt" ]; then
    install_packages_apt
elif [ "$PACKAGE_MANAGER" = "yum" ]; then
    install_packages_yum
elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    install_packages_pacman
else
    echo $PACKAGE_MANAGER
    echo "No valid package manager found. Exiting."
    exit 1
fi

# Run the setup functions
setup_ssh
setup_ldap_client
setup_sssd
setup_tls
configure_pam_mkhomedir

echo "Setup completed successfully."
