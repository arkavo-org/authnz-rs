# Production Deployment Guide

This guide covers deploying the authnz-rs service to production with SSL/TLS support using Let's Encrypt.

## Server Information

- **Production Server IP**: 71.179.48.230
- **Domain**: identity.arkavo.net
- **Service**: WebAuthn authentication/authorization server
- **Port**: 443 (HTTPS)

## Prerequisites

1. **Server Access**: SSH access to 71.179.48.230 with sudo privileges
2. **DNS Configuration**: A record pointing identity.arkavo.net → 71.179.48.230
3. **Firewall**: Ports 80 (HTTP) and 443 (HTTPS) open for incoming traffic
4. **Rust**: Rust toolchain installed on the server

## SSL/TLS Certificate Setup with Let's Encrypt

### Step 1: Install Certbot

On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install certbot -y
```

On CentOS/RHEL:
```bash
sudo yum install certbot -y
```

On macOS (for testing):
```bash
brew install certbot
```

### Step 2: Verify DNS Configuration

Before requesting a certificate, verify that the DNS A record is properly configured:

```bash
# Check DNS resolution
dig identity.arkavo.net +short
# Should return: 71.179.48.230

# Alternative using nslookup
nslookup identity.arkavo.net
```

### Step 3: Stop Any Service Using Port 80

Certbot needs port 80 temporarily for domain validation:

```bash
# Check if anything is using port 80
sudo lsof -i :80

# Stop any conflicting service (example with nginx)
sudo systemctl stop nginx
# Or with apache
sudo systemctl stop apache2
```

### Step 4: Generate Let's Encrypt Certificate

Use Certbot's standalone mode to obtain a certificate:

```bash
sudo certbot certonly --standalone \
  -d identity.arkavo.net \
  --non-interactive \
  --agree-tos \
  --email your-email@example.com
```

Replace `your-email@example.com` with your actual email for renewal notifications.

**Certificate Files Location**:
- Certificate chain: `/etc/letsencrypt/live/identity.arkavo.net/fullchain.pem`
- Private key: `/etc/letsencrypt/live/identity.arkavo.net/privkey.pem`

### Step 5: Verify Certificate Files

```bash
# List certificate files
sudo ls -la /etc/letsencrypt/live/identity.arkavo.net/

# Check certificate expiration date
sudo openssl x509 -in /etc/letsencrypt/live/identity.arkavo.net/fullchain.pem -noout -enddate
```

The certificate is valid for 90 days from the issue date.

## Cryptographic Key Generation

The service requires three additional EC keys for WebAuthn and JWT operations (separate from TLS):

```bash
# Create a directory for application keys
sudo mkdir -p /etc/authnz-rs/keys
cd /etc/authnz-rs/keys

# Generate signing key for attestation envelope
sudo openssl ecparam -genkey -name prime256v1 -noout -out signkey.pem

# Generate JWT encoding key (PKCS8 format)
sudo openssl ecparam -genkey -noout -name prime256v1 | sudo openssl pkcs8 -topk8 -nocrypt -out encodekey.pem

# Extract public key for JWT decoding
sudo openssl ec -in encodekey.pem -pubout -out decodekey.pem

# Set appropriate permissions
sudo chmod 600 /etc/authnz-rs/keys/*.pem
sudo chown $(whoami):$(whoami) /etc/authnz-rs/keys/*.pem
```

## Service Configuration

### Environment Variables

Create a production environment configuration file:

```bash
sudo nano /etc/authnz-rs/production.env
```

Add the following content:

```bash
# Server Configuration
BIND_ADDRESS=192.0.2.6  # Specific IP address to bind to (optional, defaults to 0.0.0.0)
PORT=443

# TLS Certificate Paths
TLS_CERT_PATH=/etc/letsencrypt/live/identity.arkavo.net/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/identity.arkavo.net/privkey.pem

# WebAuthn/JWT Cryptographic Keys
SIGN_KEY_PATH=/etc/authnz-rs/keys/signkey.pem
ENCODING_KEY_PATH=/etc/authnz-rs/keys/encodekey.pem
DECODING_KEY_PATH=/etc/authnz-rs/keys/decodekey.pem

# DynamoDB Configuration (adjust as needed)
DYNAMODB_CREDENTIALS_TABLE=credentials
DYNAMODB_HANDLES_TABLE=handles
DYNAMODB_DEVICE_BINDINGS_TABLE=device_bindings
DYNAMODB_IDENTITY_LINKS_TABLE=identity_links

# AWS Region (if using AWS DynamoDB)
AWS_REGION=us-east-1

# Optional: DynamoDB Endpoint (for local development)
# DYNAMODB_ENDPOINT=http://localhost:8000

# OIDC (required for AuthZEN PEP service CWTs — see docs/pep-service-clients.md)
# OIDC_ISSUER=https://identity.arkavo.net
# OIDC_PLATFORM_AUDIENCE=https://platform.arkavo.net
# catalog-node is already registered; do not recreate it.
# mcp-edge is not: OIDC_CLIENT_MCPEDGE_ID/SECRET/REDIRECT_URIS + restart.
```

#### `identity_links` Table

Required for the `POST /oauth/apple/link` endpoint (and any future third-party
identity-linkage endpoint). Stores the mapping between an arkavo `user_id` and
a third-party identity provider's `subject` claim.

**Minimum-PII posture**: only the join key is persisted. No email, display
name, private-relay address, or `real_user_status` is written here, even if
the upstream IdP supplies it. Sign in with Apple is treated as an
authentication signal, not an identity source.

**Schema**

| Attribute   | Type   | Purpose                                                     |
|-------------|--------|-------------------------------------------------------------|
| `link_pk`   | String | Primary key. Format: `<provider>#<subject>` (e.g. `apple#001234.abc…`). |
| `user_id`   | String | UUID of the arkavo account the identity is bound to.        |
| `provider`  | String | IdP name (`apple`, future: `google`, `github`, …).          |
| `subject`   | String | The IdP's stable subject identifier (Apple's `sub` claim).  |
| `linked_at` | Number | Unix timestamp of the link operation.                       |

A conditional put on `link_pk` enforces uniqueness: re-linking the same
identity to the same user is idempotent, but binding it to a different user
returns HTTP `409 Conflict` (the conflicting `user_id` is not disclosed).

**Provisioning**

```bash
aws dynamodb create-table \
    --table-name identity_links \
    --attribute-definitions AttributeName=link_pk,AttributeType=S \
    --key-schema AttributeName=link_pk,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
```

**Future GSI** (not required for this release): a `user_id-index` on
`user_id` will be needed when an authenticated user wants to enumerate all
identities bound to their account ("which providers have I linked?"). Add it
when that endpoint ships — no rows need backfilling, GSI population happens
asynchronously on the existing data.

**Audit log → X-Forwarded-For trust**: `/oauth/apple/link` records the
originating client IP in its audit log by reading `X-Forwarded-For`. The
deployment **must** put a reverse proxy (HAProxy, nginx) in front of
authnz-rs that strips any client-supplied `X-Forwarded-For` header and
prepends the real peer address. If clients can reach authnz-rs directly,
they can forge this header and poison the audit log. The audit value is
not used for any authorization decision — it is operator-correlation
only — but log integrity still matters for incident response.

### Systemd Service Setup

Create a systemd service file for automatic startup and management:

```bash
sudo nano /etc/systemd/system/authnz-rs.service
```

Add the following content:

```ini
[Unit]
Description=Arkavo AuthNZ Service
After=network.target

[Service]
Type=simple
User=authnz
Group=authnz
WorkingDirectory=/opt/authnz-rs
EnvironmentFile=/etc/authnz-rs/production.env
ExecStart=/opt/authnz-rs/target/release/authnz-rs
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/authnz-rs

# Allow binding to port 443
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Create Service User and Directories

```bash
# Create service user (no login shell)
sudo useradd -r -s /bin/false authnz

# Create application directory
sudo mkdir -p /opt/authnz-rs
sudo mkdir -p /var/log/authnz-rs

# Set ownership
sudo chown -R authnz:authnz /opt/authnz-rs
sudo chown -R authnz:authnz /var/log/authnz-rs

# Grant read access to certificate files
sudo chmod 644 /etc/letsencrypt/live/identity.arkavo.net/fullchain.pem
sudo chmod 640 /etc/letsencrypt/live/identity.arkavo.net/privkey.pem
sudo chown root:authnz /etc/letsencrypt/live/identity.arkavo.net/privkey.pem
```

## Application Deployment

### Build and Deploy the Application

```bash
# On development machine: build release binary
cargo build --release

# Copy to production server
scp target/release/authnz-rs user@71.179.48.230:/tmp/

# On production server: move to application directory
sudo mv /tmp/authnz-rs /opt/authnz-rs/authnz-rs
sudo chown authnz:authnz /opt/authnz-rs/authnz-rs
sudo chmod 755 /opt/authnz-rs/authnz-rs
```

### Start the Service

```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable authnz-rs

# Start the service
sudo systemctl start authnz-rs

# Check status
sudo systemctl status authnz-rs

# View logs
sudo journalctl -u authnz-rs -f
```

## Certificate Renewal

Let's Encrypt certificates expire after 90 days. Set up automatic renewal:

### Automated Renewal with Cron

```bash
# Test renewal (dry run)
sudo certbot renew --dry-run

# Create renewal script
sudo nano /usr/local/bin/renew-authnz-cert.sh
```

Add the following content:

```bash
#!/bin/bash
set -e

# Renew certificate
certbot renew --quiet --deploy-hook "systemctl reload authnz-rs"

# Log renewal
echo "$(date): Certificate renewal completed" >> /var/log/authnz-rs/cert-renewal.log
```

Make it executable:

```bash
sudo chmod +x /usr/local/bin/renew-authnz-cert.sh
```

### Add Cron Job

```bash
# Edit root's crontab
sudo crontab -e

# Add the following line to run renewal check daily at 2:30 AM
30 2 * * * /usr/local/bin/renew-authnz-cert.sh
```

Alternatively, use systemd timers:

```bash
# Create timer unit
sudo nano /etc/systemd/system/certbot-renewal.timer
```

```ini
[Unit]
Description=Certbot Renewal Timer

[Timer]
OnCalendar=daily
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# Create service unit
sudo nano /etc/systemd/system/certbot-renewal.service
```

```ini
[Unit]
Description=Certbot Renewal

[Service]
Type=oneshot
ExecStart=/usr/local/bin/renew-authnz-cert.sh
```

Enable the timer:

```bash
sudo systemctl enable certbot-renewal.timer
sudo systemctl start certbot-renewal.timer
```

## Firewall Configuration

Ensure ports 80 (for renewal) and 443 are open:

### Using UFW (Ubuntu/Debian)

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

### Using firewalld (CentOS/RHEL)

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

### Using iptables

```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

## Verification

### Test HTTPS Connection

```bash
# Test with curl
curl -v https://identity.arkavo.net

# Check certificate details
openssl s_client -connect identity.arkavo.net:443 -servername identity.arkavo.net < /dev/null

# Test WebAuthn registration endpoint
curl -v https://identity.arkavo.net/register/testuser?handle=testuser.arkavo.social&did=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

### Monitoring and Logs

```bash
# View service logs
sudo journalctl -u authnz-rs -n 100 --no-pager

# Follow logs in real-time
sudo journalctl -u authnz-rs -f

# Check certificate expiration
sudo certbot certificates
```

## Troubleshooting

### Certificate Issues

**Problem**: Certificate not found or permission denied

```bash
# Verify certificate paths
sudo ls -la /etc/letsencrypt/live/identity.arkavo.net/

# Fix permissions
sudo chmod 644 /etc/letsencrypt/live/identity.arkavo.net/fullchain.pem
sudo chmod 640 /etc/letsencrypt/live/identity.arkavo.net/privkey.pem
sudo chown root:authnz /etc/letsencrypt/live/identity.arkavo.net/privkey.pem
```

**Problem**: Certbot fails to verify domain

```bash
# Check DNS
dig identity.arkavo.net +short

# Ensure port 80 is accessible
sudo lsof -i :80

# Check firewall
sudo ufw status
```

### Service Issues

**Problem**: Service fails to start

```bash
# Check service status and logs
sudo systemctl status authnz-rs
sudo journalctl -u authnz-rs -n 50 --no-pager

# Verify environment variables
sudo systemctl show authnz-rs | grep Environment

# Test configuration manually
source /etc/authnz-rs/production.env
/opt/authnz-rs/authnz-rs
```

**Problem**: Port 443 permission denied

```bash
# Option 1: Use systemd with AmbientCapabilities (recommended)
# Already configured in the systemd service file above

# Option 2: Set capability on binary (alternative)
sudo setcap 'cap_net_bind_service=+ep' /opt/authnz-rs/authnz-rs

# Option 3: Use reverse proxy (nginx/caddy) on port 443 → 8080
```

### DynamoDB Connection Issues

**Problem**: Cannot connect to DynamoDB

```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify DynamoDB tables exist
aws dynamodb list-tables --region us-east-1

# Test table access
aws dynamodb describe-table --table-name credentials --region us-east-1
```

## Security Best Practices

1. **Keep Software Updated**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   cargo update
   ```

2. **Regular Security Audits**:
   ```bash
   cargo audit
   cargo clippy
   ```

3. **Backup Cryptographic Keys**:
   ```bash
   sudo tar czf /root/authnz-keys-backup-$(date +%Y%m%d).tar.gz /etc/authnz-rs/keys/
   ```

4. **Monitor Certificate Expiration**:
   - Set up alerts for certificate expiration (30 days before)
   - Monitor renewal cron job logs

5. **Rate Limiting**:
   - Consider adding rate limiting via reverse proxy (nginx, caddy)
   - Or implement rate limiting in the application

6. **HSTS Headers**:
   - Consider adding Strict-Transport-Security headers via reverse proxy

## Maintenance Schedule

- **Daily**: Automatic certificate renewal check (cron job)
- **Weekly**: Review service logs for errors or unusual activity
- **Monthly**:
  - Verify certificate validity
  - Test backup and restore procedures
  - Review and rotate access logs
- **Quarterly**:
  - Update Rust dependencies
  - Security audit with `cargo audit`
  - Review and test disaster recovery plan

## Support and Monitoring

### Health Check Endpoint

The service doesn't currently expose a health check endpoint. Consider adding one:

```bash
# Test basic connectivity
curl -v https://identity.arkavo.net/
```

### Monitoring Tools

Consider integrating:
- **Prometheus** + **Grafana**: Metrics and dashboards
- **Loki**: Log aggregation
- **Alertmanager**: Alert notifications for certificate expiration, service downtime

### Contact

For issues or questions:
- GitHub: https://github.com/arkavo/authnz-rs
- Documentation: See CLAUDE.md and README.md

---

**Last Updated**: 2025-11-11
