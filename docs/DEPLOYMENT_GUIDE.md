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
DYNAMODB_AGENT_DELEGATIONS_TABLE=agent_delegations
DYNAMODB_GUARDIANS_TABLE=guardians

# Agent credentials (docs/agent-credentials-contract.md v2)
# Agent tokens go to every audience listed here, and only the platform checks
# agent status, so list exactly these two. Never the KAS
# (https://kas.arkavo.net) nor "arkavo": either one stops startup.
AGENT_TOKEN_AUDIENCES=https://platform.arkavo.net,https://kg.arkavo.net
AGENT_AUTHORIZED_ACTORS=https://kg.arkavo.net
AGENT_DELEGATE_CLIENT_IDS=arkavo-edge
# The platform's status client: a confidential OIDC client that mints its
# service CWT with client_credentials. Register it with the triple below
# (_REDIRECT_URIS is required by the parser even for client_credentials; an
# unused URI is fine) and list the same client_id in AGENT_STATUS_CLIENT_IDS.
# Its secret goes into the platform's agent_status.client_secret. Without the
# triple the platform cannot mint the CWT, every status call fails, and every
# agent's entitlements are withheld.
OIDC_CLIENT_PLATFORMSTATUS_ID=<platform agent_status client_id>
OIDC_CLIENT_PLATFORMSTATUS_SECRET=<confidential; never paste>
OIDC_CLIENT_PLATFORMSTATUS_REDIRECT_URIS=https://identity.arkavo.net/oauth/unused
AGENT_STATUS_CLIENT_IDS=<platform agent_status client_id>
# AGENT_OWNER_APPRAISAL_TTL_SECONDS=43200
# AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS=900

# App Attest registration gate — see docs/app-attest-gate-deployment.md before
# setting these. The table is inert until the gate ships; APP_ATTEST_APP_ID is
# not, and the gate fails closed when it is unset.
# DYNAMODB_DEVICE_ATTEST_KEYS_TABLE=device_attest_keys
# APP_ATTEST_APP_ID=<comma-separated sha256(TeamID.BundleID), lower-case hex>

# AWS Region (if using AWS DynamoDB)
AWS_REGION=us-east-1

# Optional: DynamoDB Endpoint (for local development)
# DYNAMODB_ENDPOINT=http://localhost:8000

# OIDC (required for AuthZEN PEP service CWTs — see docs/pep-service-clients.md)
# OIDC_ISSUER=https://identity.arkavo.net
# OIDC_PLATFORM_AUDIENCE=https://platform.arkavo.net
# catalog-node and mcp-edge are registered; do not recreate them.
# Mint: python3 scripts/mint-pep-cwt.py catalog-node --eval

# Sign in with Google as an upstream IdP for /oauth/authorize?idp=google
# (browser redirect flow; see docs/google-signin.md). Create a "Web
# application" OAuth client in Google Cloud Console and register
# https://identity.arkavo.net/oauth/google/callback as an authorized
# redirect URI. Both vars must be set or the idp=google path fails closed.
# GOOGLE_CLIENT_ID=<...>.apps.googleusercontent.com
# GOOGLE_CLIENT_SECRET=<...>
# GOOGLE_REDIRECT_URI=https://identity.arkavo.net/oauth/google/callback   # default

# ClosureKB Android: public PKCE client, signs in via Google, custom-scheme
# redirect. Access tokens carry aud = [client_id, OIDC_PLATFORM_AUDIENCE].
# OIDC_CLIENT_CLOSUREKB_ID=closurekb-android
# OIDC_CLIENT_CLOSUREKB_REDIRECT_URIS=com.closurekb:/oauth2redirect
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

#### `guardians` Table and Agent Trust State

Required before deploying 0.13.0: `POST /guardians` writes the table named
by `DYNAMODB_GUARDIANS_TABLE`. Create it, and grant the IAM actions below,
under exactly that name: `guardians` with the environment file above, or the
prefixed name when the other tables are prefixed (`prod-guardians` alongside
`prod-credentials` and `prod-agent-delegations`, as in the README). A table
under any other name leaves the owner paths working while every Guardian
enrollment and signed request fails with 503. The agent trust state
(contract v2) lives on the existing `agent_delegations` rows, so there is no
other new table; `agent_workloads` is not used (v1 was never deployed;
delete it if a staging environment created one). See
[docs/agent-credentials-contract.md](agent-credentials-contract.md) (v2) and
`.claude/rules/dynamodb-schema.md` for the full attribute list.

```bash
# The same value the server runs with, e.g. guardians or prod-guardians.
DYNAMODB_GUARDIANS_TABLE=guardians
aws dynamodb create-table --table-name "$DYNAMODB_GUARDIANS_TABLE" \
  --attribute-definitions AttributeName=guardian_id,AttributeType=S \
  --key-schema AttributeName=guardian_id,KeyType=HASH --billing-mode PAY_PER_REQUEST
```

`AGENT_TOKEN_AUDIENCES` must not list the KAS: agent status is checked by
the platform's entity resolver, never by the KAS, so a KAS that accepted
agent tokens would honour a quarantined or suspended agent's token until it
expires. The server refuses to start when the list contains
`https://kas.arkavo.net` or `arkavo` (the passkey CWT audience). Remove
the KAS from a running environment's list before deploying this release.

IAM: every trust-state write is a single conditional `UpdateItem`; nothing
uses `TransactWriteItems`, so `ConditionCheckItem` is not needed. The service
role needs, in addition to the actions track 1 already uses on
`agent_delegations` (`PutItem`, `UpdateItem`, `GetItem`, `Query` on
`root_user_id-index`, `Scan`):

| Table | Actions |
|---|---|
| `agent_delegations` | nothing new (`UpdateItem` and `GetItem` carry authorize, quarantine, recovery and appraisal) |
| the `DYNAMODB_GUARDIANS_TABLE` table | `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:GetItem` |

Existing (track-1) delegation rows carry no trust state. They read as
`unassessed`: `/agents/challenge` and `/agents/token` answer 403
`Forbidden: agent is unassessed; it needs an appraisal` until the owner runs
`POST /agents/authorize` for the same DID once (no DELETE needed), which is
the owner's bootstrap appraisal.

Optional appraisal lifetimes (out of range fails startup):
`AGENT_OWNER_APPRAISAL_TTL_SECONDS` (default 43200, at most 86400) and
`AGENT_GUARDIAN_APPRAISAL_MAX_SECONDS` (default and at most 900). Until a
Guardian is enrolled, every agent needs an owner passkey appraisal at least
every `AGENT_OWNER_APPRAISAL_TTL_SECONDS` (counted from the passkey tap) or
it is suspended and stops minting; the owner renews with
`POST /agents/{did}/appraisal`, which resends no entitlements.

An appraisal — owner or Guardian — renews eligibility only; it never extends
the delegation itself. The delegation expires `AGENT_DELEGATION_DAYS` (30
days) after the identity's last owner authorize, and only a fresh
`POST /agents/authorize` by the owner resets that clock. This matters most
after recovery: a recovered key can never be re-authorized by its owner
(only a Guardian may appraise it from then on), so a recovered key stops
minting at most 30 days after its last authorize even while a Guardian
keeps appraising it — the owner authorizes a new key before then.

### Systemd Service Setup

> **Not the live deployment.** `identity.arkavo.net` runs on macOS, where there
> is no systemd and no `/etc/authnz-rs/`. It is started by `sudo ./start.sh`
> from `production/`, in the foreground, with its environment set inside that
> script. This section is a reference for a Linux host; do not follow it when
> operating the current production box.

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
