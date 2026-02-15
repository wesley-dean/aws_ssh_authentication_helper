# AWS SSH Authentication Helper

## Overview

This helper uses AWS IAM SSH public keys (commonly used for CodeCommit access)
as the source of truth for authentication purposes when connecting to an AWS
EC2 instance via SSH.

AWS's Code Commit service allows users to associate SSH keys with their
AWS accounts.  This tool allows a system to authenticate incoming SSH
connections using the public portion of users' SSH keys from AWS Code
Commit.

The users' public keys do not need to be synchronized to the local system
in advance -- this helper acquires the public portions of the keys
on-demand and in real-time.  As a result, changes made in AWS Code Commit
(e.g., the user uploads a new key, an administrator disables a key, etc.)
are reflected immediately.

However, this also necessitates a connection to AWS's APIs; if they're
unavailable (e.g., there's an outage), new connections will not authenticate
even if the user has already logged in (i.e., the public keys are not
saved to users ~/.ssh/authorized_keys).

Additionally, when the user attempts to connect, if an AWS IAM group is
specified (via `-g`), the user must be a member of that IAM group in order to
authenticate.  The group to query may be specified via '-g' followed by the
name of the AWS IAM group.

### Script Output

The script writes only valid public keys to STDOUT. All logging is directed
to syslog or STDERR to preserve SSH authentication integrity.

### Failure Conditions

The following conditions may result in the helper script failing:

- If AWS CLI is missing
- If IAM permissions are insufficient
- If dependency probe detects missing commands and hard-fail is enabled
- If IAM throttling occurs

### AWS Setup

It is strongly recommended to use an EC2 instance profile (IAM role) rather
than static AWS credentials.

### Performance Note

Each SSH login:

- Calls AWS IAM
- Performs multiple lookups
- May perform provisioning

Under heavy SSH load (bastion host scenarios), this can:

- Add latency
- Hit IAM API rate limits

Therefore, in high-volume environments (e.g., bastion hosts), consider
monitoring IAM API rate limits and SSH authentication latency.

## Automated installation during provisioning (EC2 user_data)

This helper is often easiest to deploy at instance provisioning time.  The
pattern below installs the script into `/usr/local/bin`, configures sshd to use
it as `AuthorizedKeysCommand`, and restarts `sshd`.

Two design notes matter:
- `AuthorizedKeysCommand` is executed during SSH authentication.  It must output
  only public keys to STDOUT.  All logging should go to syslog or STDERR.
- Use `AuthorizedKeysCommandUser nobody` when you are not enabling local
  user/group management.  Use root when you enable `-u`, `-r`, `-c`, or `-m`,
  because those modes require local account/group changes.

## Example user_data (cloud-init shell script)

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="/usr/local/bin/aws_ssh_authentication_helper.bash"
SCRIPT_URL="https://raw.githubusercontent.com/wesley-dean/aws_ssh_authentication_helper/refs/heads/master/aws_ssh_authentication_helper.bash"

# Configuration: set these to match your environment.
REMOTE_IAM_GROUP="ssh-users"      # IAM group required for login (optional)
LOCAL_GROUP="users"               # Local group to manage (optional)

# Feature flags (match the script flags):
# -u create local user
# -r remove local user when remote checks fail
# -c create local group if missing
# -m manage local group membership (add user to local group)
CREATE_USER="false"
REMOVE_USER="false"
CREATE_GROUP="false"
MANAGE_GROUP="false"

mkdir -p /usr/local/bin

# Install dependencies (optional but recommended).
# Uncomment the relevant block for your distro/AMI.
#
# Amazon Linux 2023 / Fedora / RHEL family:
# dnf -y install awscli
#
# Amazon Linux 2:
# yum -y install awscli
#
# Ubuntu/Debian:
# apt-get update -y
# apt-get install -y awscli
#
# Alpine:
# apk add --no-cache aws-cli

# Fetch the helper.
if ! wget -q -O "${SCRIPT_PATH}" "${SCRIPT_URL}" ; then
  echo "ERROR: Failed to download aws_ssh_authentication_helper.bash" >&2
  exit 1
fi
chmod 0755 "${SCRIPT_PATH}"

# Build the AuthorizedKeysCommand with flags.
# Start with the script path and add flags conditionally.
AKC_CMD="${SCRIPT_PATH}"

if [ -n "${REMOTE_IAM_GROUP}" ]; then
  AKC_CMD="${AKC_CMD} -g ${REMOTE_IAM_GROUP}"
fi

if [ -n "${LOCAL_GROUP}" ]; then
  AKC_CMD="${AKC_CMD} -l ${LOCAL_GROUP}"
fi

if [ "${CREATE_USER}" = "true" ]; then
  AKC_CMD="${AKC_CMD} -u"
fi

if [ "${REMOVE_USER}" = "true" ]; then
  AKC_CMD="${AKC_CMD} -r"
fi

if [ "${CREATE_GROUP}" = "true" ]; then
  AKC_CMD="${AKC_CMD} -c"
fi

if [ "${MANAGE_GROUP}" = "true" ]; then
  AKC_CMD="${AKC_CMD} -m"
fi

# Choose the AuthorizedKeysCommandUser.
# Provisioning features require root.
AKC_USER="nobody"
if [ "${CREATE_USER}" = "true" ] || \
   [ "${REMOVE_USER}" = "true" ] || \
   [ "${CREATE_GROUP}" = "true" ] || \
   [ "${MANAGE_GROUP}" = "true" ]; then
  AKC_USER="root"
fi

# Update sshd_config in an idempotent way.
SSHD_CONFIG="/etc/ssh/sshd_config"

# Remove any existing AuthorizedKeysCommand / AuthorizedKeysCommandUser lines.
sed -i.bak -E \
  -e '/^[[:space:]]*AuthorizedKeysCommand[[:space:]]+/d' \
  -e '/^[[:space:]]*AuthorizedKeysCommandUser[[:space:]]+/d' \
  "${SSHD_CONFIG}"

# Append our configuration at the end of the file.
printf '%s\n' "AuthorizedKeysCommand ${AKC_CMD}" >> "${SSHD_CONFIG}"
printf '%s\n' "AuthorizedKeysCommandUser ${AKC_USER}" >> "${SSHD_CONFIG}"

# Validate and restart sshd.
if command -v sshd >/dev/null 2>&1; then
  sshd -t
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart sshd || systemctl restart ssh
else
  service sshd restart || service ssh restart
fi
```

## User Creation

When users attempt to connect, this tool can create their accounts
automatically.  Accounts will only be created if the username matches
an AWS IAM user.  Moreover, if an AWS IAM group is provided, they will
only be created if that AWS IAM user exists in that AWS IAM group.

User creation is disabled by default but may be enabled via '-u'

## Local Groups

The tool also supports group management in that when users attempt to
authenticate, they can be automatically added to a local (non-IAM) group.
If the group doesn't exist, it will be created.  This functionality
is disabled by default but may be enabled via '-m' while the name
of the local group to manage may be specified via '-l'

The adding of users to groups, while it takes place at authentication
time, is not restricted to only new users being created for the first
time.  That is, if the manage group setting is enabled and a previously
seen user attempts to login, they will be added to that group.

## User Removal

When a user attempts to authenticate and either they do not belong to
the required AWS IAM group or there is no corresponding AWS IAM user
account, their local account can be removed.  Account removal
functionality is disabled by default but may be enabled via '-r'

Regardless of the remove user setting, users who do not have an
enabled AWS IAM user account or are not in a specified
AWS IAM group will be denied authentication.

## AWS IAM Access

It's notable that changes made in AWS only affect new connections;
that is, if a user is already logged in and then their AWS IAM
account is disabled, their connection won't be dropped, interrupted,
etc..  Manual intervention would be required to terminate current,
active sessions.

The following AWS IAM permissions are required for this script to
interact with AWS's APIs:

* iam:GetSSHPublicKey
* iam:ListSSHPublicKeys
* iam:ListGroupsForUser
* iam:GetGroup
* iam:GetUser

Consider the following AWS IAM policy:

```JSON
{
 "Version": "2012-10-17",
 "Statement" : [
   {
     "Sid": "IAMUserSSHKeys",
     "Effect" : "Allow",
     "Action" : [
       "iam:GetSSHPublicKey",
       "iam:ListSSHPublicKey",
       "iam:ListGroupsForUser",
       "iam:GetGroup",
       "iam:GetUser"
     ],
     "Resource" : [
       "*"
     ]
   }
 ]
}
```

In more restrictive environments, this policy can be scoped to specific
IAM users or groups.

Also, the AWS CLI must have credentials available. On EC2, it is strongly
recommended to use an instance profile (IAM role) rather than static
credentials.

## SSHD setup

The SSH daemon needs to be configured to use this script to acquire
the "authorized_keys" files (i.e., the list of public portions of
SSH keys that are allowed access).  This can be done by setting the
`AuthorizedKeysCommand` in `/etc/ssh/sshd_config` as follows:

```
AuthorizedKeysCommand /path/to/aws_ssh_authentication_helper.bash
AuthorizedKeysCommandUser nobody
```

Use `root`only if user or group management features are enabled.
Otherwise, use `nobody` (recommended).  If the script will be managing users
or groups, then `root` needs to be used.  If, however, accounts and groups
will be managed manually, then `nobody` may be used.  Using nobody reduces the
privilege level of the authentication helper and is recommended unless local
account management features are required.

On systems that support `/etc/ssh/sshd_config.d/`, you may prefer placing
these directives in a dedicated file instead of modifying
`/etc/ssh/sshd_config` directly.

The `AuthorizedKeysCommand` must use an absolute path. The script must not
write anything except public keys to STDOUT.

## Parameters

* -c : allow creating the local group if it does not exist
* -g : the remote group to query
* -h : show help text
* -l : the local group to create
* -m : manage local group members
* -r : remove local user
* -u : create local user

## Defaults

* CREATE_USER:  default for whether to create local users
  (default: "false")
* REMOVE_USER:  default for whether to remove local users
  (default: "false")
* CREATE_GROUP:  default for whether to create local groups
  (default: "false")
* MANAGE_GROUP:  default for whether to manage local group members
  (default: "false")
* REMOTE_GROUP:  defaut remote group to query
  (default: "")
* LOCAL_GROUP:  default local group to manage
  (default: "users")

## Author

Wes Dean


