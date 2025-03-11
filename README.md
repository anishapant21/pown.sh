# LDAP Client Automation

This project provides automated LDAP client setup across different Linux distributions (Debian, Amazon Linux) with AWS infrastructure testing capabilities.

## Features

- Automated LDAP client configuration
- SSH setup with secure defaults
- SSSD configuration
- TLS certificate management
- Supports multiple package managers (apt, yum, pacman)
- AWS infrastructure testing with Terraform

## Prerequisites

- AWS credentials (access key and secret key)
- SSH key pair named "test" in AWS
- `.env` file with LDAP configuration:

```
LDAP_BASE=<your-ldap-base>
LDAP_URI=<your-ldap-uri>
LDAP_ADMIN_DN=<your-admin-dn>
LDAP_ADMIN_PW=<your-admin-password>
CA_CERT=<path-to-ca-cert>
CA_CERT_CONTENT=<certificate-content>
```

## Testing

Run the test script to verify infrastructure deployment:

```bash
./test.sh
```

The script will create test instances on AWS , verify their accessibility, and clean up automatically.
