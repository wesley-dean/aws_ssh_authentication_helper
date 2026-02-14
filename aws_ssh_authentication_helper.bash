#!/usr/bin/env bash

## @file aws_ssh_authentication_helper.bash
## @brief allow users to authenticate via SSH public keys in AWS Code Commit
## @details
## AWS's Code Commit service allows users to associate SSH keys with their
## AWS accounts.  This tool allows a system to authenticate incoming SSH
## connections using the public portion of users' SSH keys from AWS Code
## Commit.
##
## The users' public keys do not need to be synchronized to the local system
## in advance -- this helper acquires the public portions of the keys
## on-demand and in real-time.  As a result, changes made in AWS Code Commit
## (e.g., the user uploads a new key, an administrator disables a key, etc.)
## are reflected immediately.
##
## However, this also necessitates a connection to AWS's APIs; if they're
## unavailable (e.g., there's an outage), new connections will not authenticate
## even if the user has already logged in (i.e., the public keys are not
## saved to users ~/.ssh/authorized_keys).
##
## Additionally, when the user attempts to connect, an AWS IAM group may be
## provided; if so, the tool will verify that the user exists in that group
## before permitting authentication.  The group to query may be specified
## via '-g' followed by the name of the AWS IAM group.
##
## User Creation
## -------------
##
## When users attempt to connect, this tool can create their accounts
## automatically.  Accounts will only be created if the username matches
## an AWS IAM user.  Moreover, if an AWS IAM group is provided, they will
## only be created if that AWS IAM user exists in that AWS IAM group.
##
## User creation is disabled by default but may be enabled via '-u'
##
## Local Groups
## ------------
##
## The tool also supports group management in that when users attempt to
## authenticate, they can be automatically added to a local (non-IAM) group.
## If the group doesn't exist, it will be created.  This functionality
## is disabled by default but may be enabled via '-m' while the name
## of the local group to manage may be specified via '-l'
##
## The adding of users to groups, while it takes place at authentication
## time, is not restricted to only new users being created for the first
## time.  That is, if the manage group setting is enabled and a previously
## seen user attempts to login, they will be added to that group.
##
## User Removal
## ------------
##
## When a user attempts to authenticate and either they do not belong to
## the required AWS IAM group or there is no corresponding AWS IAM user
## account, their local account can be removed.  Account removal
## functionality is disabled by default but may be enabled via '-r'
##
## Regardless of the remove user setting, users who do not have an
## enabled AWS IAM user account or are not in a specified
## AWS IAM group will be denied authentication.
##
## AWS IAM Access
## --------------
##
## It's notable that changes made in AWS only affect new connections;
## that is, if a user is already logged in and then their AWS IAM
## account is disabled, their connection won't be dropped, interrupted,
## etc..  Manual intervention would be required to terminate current,
## active sessions.
##
## The following AWS IAM permissions are required for this script to
## interact with AWS's APIs:
##
## * iam:GetSSHPublicKey
## * iam:ListSSHPublicKey
## * iam:ListGroupsForUser
## * iam:GetGroup
## * iam:GetUser
##
## Consider the following AWS IAM policy:
##
## ```json
##
## {
##  "Version": "2012-10-17",
##  "Statement" : [
##    {
##      "Sid": "IAMUserSSHKeys",
##      "Effect" : "Allow",
##      "Action" : [
##        "iam:GetSSHPublicKey",
##        "iam:ListSSHPublicKey",
##        "iam:ListGroupsForUser",
##        "iam:GetGroup",
##        "iam:GetUser"
##      ],
##      "Resource" : [
##        "*"
##      ]
##    }
##  ]
## }
##
## ```
##
## SSHD setup
## ----------
##
## The SSH daemon needs to be configured to use this script to acquire
## the "authorized_keys" files (i.e., the list of public portions of
## SSH keys that are allowed access).  This can be done by setting the
## `AuthorizedKeysCommand` in `/etc/ssh/sshd_config` as follows:
##
## ```
##
## AuthorizedKeysCommand /path/to/aws_ssh_authentication_helper.bash
## AuthorizedKeysCommandUser nobody
##
## ```
##
## Note: either `nobody` or `root` should be used depending on whether
## or not this script will be managing users or groups (i.e., creating
## new users, adding users to groups, removing users, etc.) or not.  If
## the script will be managing users or groups, then `root` needs to be
## used.  If, however, accounts and groups will be managed manually,
## then `nobody` may be used.  Using `nobody` is much more secure;
## however, it also requires manual work to create accounts and such.
##
## @author Wes Dean <wdean@flexion.us>

## @var DEFAULT_CREATE_USER default for whether to create local users
DEFAULT_CREATE_USER="false"

## @var DEFAULT_REMOVE_USER default for whether to remove local users
DEFAULT_REMOVE_USER="false"

## @var DEFAULT_CREATE_GROUP default for whether to create local groups
DEFAULT_CREATE_GROUP="false"

## @var DEFAULT_MANAGE_GROUP default for whether to manage local group members
DEFAULT_MANAGE_GROUP="false"

## @var DEFAULT_REMOTE_GROUP default remote group to query
DEFAULT_REMOTE_GROUP=""

## @var DEFAULT_LOCAL_GROUP default local group to manage
DEFAULT_LOCAL_GROUP="users"


## @fn command_exists()
## @brief Determine whether a command is available in PATH.
## @details
## This helper provides a consistent and readable mechanism for probing
## runtime dependencies.  Minimal container images and BusyBox-based systems
## frequently omit commands that are assumed present on full distributions.
##
## This function performs a simple PATH lookup and does not attempt to
## validate version, permissions, or behavior.  It is intentionally small
## and side-effect free so that it can be safely used inside other
## dependency checks.
## @param cmd The command name to check for in PATH.
## @returns No output is written to STDOUT.
## @retval 0 The command exists and is executable.
## @retval 1 The command is not found in PATH.
##
## @par Examples
## @code
## if command_exists aws ; then
##   logger -s -p authpriv.info -t "$0" "aws CLI detected"
## fi
## @endcode
command_exists() {
  command -v "$1" >/dev/null 2>&1
}


## @fn log_message()
## @brief Write a structured log message with logger fallback support.
## @details
## This helper centralizes all operational logging for the script.
## The script frequently runs in sshd's AuthorizedKeysCommand context,
## where writing to STDOUT would interfere with key delivery and cause
## authentication failure.  Therefore, all logging must go to syslog
## or STDERR only.
##
## When the logger(1) command is available, this function emits the
## message using logger with the provided syslog priority.  When logger
## is unavailable (for example, in minimal BusyBox environments), the
## message is written to STDERR instead.
##
## This design ensures that:
## - missing logger does not suppress critical diagnostics,
## - dependency_probe() remains useful even in constrained images,
## - and no logging path contaminates STDOUT.
##
## This function does not perform formatting beyond simple message
## forwarding.  Callers are responsible for composing meaningful,
## operator-friendly messages.
##
## @param priority The syslog priority (for example: authpriv.info).
## @param message The message string to log.
## @returns No output is written to STDOUT.
## @retval 0 Message delivery attempted via logger or STDERR.
##
## @par Examples
## @code
## log_message "authpriv.info" \
##   "Dependency probe completed successfully."
##
## log_message "authpriv.warning" \
##   "Dependency missing: aws CLI not found."
## @endcode
log_message() {
  local priority="$1"
  shift
  local message="$*"

  if command_exists logger ; then
    logger -s -p "$priority" -t "$0" "$message"
  else
    echo "$message" >&2
  fi

  return 0
}


## @fn validate_username()
## @brief Validate that an SSH username is structurally safe and policy-compliant.
## @details
## This helper is a safety mechanism used by the AuthorizedKeysCommand entrypoint.
## sshd provides the username argument, but this script treats all inputs as
## untrusted.  Validation reduces incident risk by failing closed when a username
## is malformed, surprising, or likely to cause ambiguous behavior.
##
## Validation is intentionally conservative:
## - The username must begin with a lowercase letter or underscore.
## - Remaining characters may include lowercase letters, digits, underscore,
##   dot, or hyphen.
## - Usernames longer than 32 characters are rejected.
## - Reserved accounts (e.g., 'root') are rejected explicitly.
## - Special path tokens '.' and '..' are rejected explicitly.
##
## This function validates only.  It does not normalize, mutate, or attempt to
## "fix" a username because implicit normalization can mask upstream problems and
## lead to hard-to-debug access failures.
##
## @param username Candidate username to validate.
## @retval 0 The username is acceptable and may be processed further.
## @retval 1 The username is invalid.  A warning is logged; auth should denied
## @par Examples
## @code
## validate_username "alice"   # returns 0
## validate_username "root"    # returns 1
## validate_username "../x"    # returns 1
## @endcode
validate_username() {
  local username="$1"

  # Reject empty input early to avoid ambiguous log messages downstream.
  if [[ -z "$username" ]]; then
    logger -s -p authpriv.warning -t "$0" "Username validation failed: empty input"
    return 1
  fi

  # Reject explicit special path markers.  These are not meaningful usernames and
  # are commonly used in path traversal attempts.
  if [[ "$username" == "." || "$username" == ".." ]]; then
    log_message authpriv.warning "Username validation failed: reserved path token '$username'"
    return 1
  fi

  # Reject selected reserved local system accounts.
  # This list is intentionally minimal and conservative.
  case "$username" in
    root|nobody|daemon|bin|sys|sync|shutdown|halt)
      log_message authpriv.warning "Username validation failed: reserved account '$username'"
      return 1
      ;;
  esac

  # Enforce a bounded maximum length.  Many Linux systems cap usernames at 32
  # characters.  This is a safety posture choice rather than a strict POSIX
  # guarantee.
  if (( ${#username} > 32 )); then
    log_message authpriv.warning "Username validation failed: exceeds 32 character limit ('$username')"
    return 1
  fi

  # Enforce allowed character policy:
  # - must begin with lowercase letter or underscore
  # - subsequent characters may include lowercase letters, digits, underscore,
  #   dot, or hyphen
  if [[ ! "$username" =~ ^[a-z_][a-z0-9._-]*$ ]]; then
    log_message authpriv.warning "Username validation failed: invalid character set ('$username')"
    return 1
  fi

  return 0
}


## @fn is_true()
## @brief if we're passed a true value, return 0 (True)
## @details
## True values start with a 0, the letters T or Y (True or Yes),
## or the number 0.  Anything else returns 1 (False).  Leading
## spaces and case are ignored.
##
## The number '0' is considered True because in Bash, 0s are
## considered True and non-zeros are considered False.
## @param string the string to evaluate
## @retval 0 (True) if the string is considered "true"
## @retval 1 (False) if the string is not considered "true"
## @par Example
## @code
## if is_true "Yes" ; then echo "Yay" ; else echo "Booooo" ; fi
## @endcode
is_true() {
  [[ "$1" =~ ^[[:space:]]*[TtYy0] ]]
}

## @fn is_false()
## @brief if we're passed a false value, return 1 (False)
## @details
## This is like is_true() but will only return a true value if
## the string passed starts with the letters F or N (False or No),
## of the number 1.  Anything else returns a 1 (False).  Leading
## spaces and case are ignored.
##
## The decision was made to look for specific patterns and not
## simply return '! is_true()'.  For example, suppose the user
## passes the string 'help'; this string is not true, but it's
## also not false.  Otherwise, this functions just like is_true()
## but with a different pattern.  Caveat emptor.
## @param string the string to evaluate
## @retval 0 (True) if the string is considered "false"
## @retval 1 (False) if the string is not considered "false"
## @par Example
## @code
## is_false "$response" && exit 1
## @endcode
is_false() {
  [[ "$1" =~ ^[[:space:]]*[FfNn1] ]]
}


## @fn md_header()
## @brief display a given header along with the appropriate markdown
## @details
## Long story short, it became problematic to use the prefix notation
## for markdown headers (prepending a '#' for each level of header)
## and the show_help() function plus it looked ugly to have underlines
## that were a different length than the header PLUS it sucked to have
## to include extra newlines after the underline to make the markdown
## lint properly, so this silly function handles all of that for us.
## @param header string to use as a header
## @param character the character to use as an underline ('-' or '=')
## @retval 0 (True) if echo worked
## @retval 1 (False) if echo failed somehow
## @par Example
## @code
## md_header "Awesomeness" "-"
## @endcode
md_header() {
  local header="${1:-header}"
  local character="${2:-=}"

  echo ""
  echo -e "$header"
  # shellcheck disable=SC2034
  for n in $(seq 1 "${#header}"); do
    echo -n "$character"
  done
  echo ""
  echo ""
}


## @fn ensure_local_group_exists()
## @brief Ensure a local group exists, creating it when allowed and necessary.
## @details
## This function is part of the "portability layer" for local provisioning.
## It prefers standard shadow tools (groupadd) when available, but also supports
## Alpine/BusyBox patterns (addgroup).
##
## This function is idempotent:
## - If the group already exists, it returns success without making changes.
## - If the group does not exist, it attempts to create it using the first
##   supported backend tool it finds.
##
## The caller controls whether creation is permitted (for example via
## the script's $create_group flag).  This function does not consult that flag
## directly so that it remains a pure "mechanism" primitive.
##
## @param group_name the local group name to ensure exists
## @param gid optional numeric GID.  Pass an empty string to use system defaults
## @returns status via exit code
## @retval 0 the group exists or was created successfully
## @retval 1 the group does not exist and could not be created
## @par Examples
## @code
## ensure_local_group_exists "sshusers" "1003" || exit 1
## ensure_local_group_exists "users" "" || exit 1
## @endcode
ensure_local_group_exists() {
  local group_name="${1?No group name provided}"
  local gid="${2:-}"

  if getent group "$group_name" >/dev/null 2>&1; then
    return 0
  fi

  if command_exists groupadd; then
    if [[ -n "$gid" ]]; then
      groupadd -g "$gid" "$group_name" >/dev/null 2>&1 && return 0
    else
      groupadd "$group_name" >/dev/null 2>&1 && return 0
    fi

    log_message authpriv.err "Failed to create group '$group_name' using groupadd"
    return 1
  fi

  # Alpine / BusyBox commonly provides addgroup.  Many builds support -g for GID.
  if command_exists addgroup; then
    if [[ -n "$gid" ]]; then
      addgroup -g "$gid" "$group_name" >/dev/null 2>&1 && return 0
    else
      addgroup "$group_name" >/dev/null 2>&1 && return 0
    fi

    log_message authpriv.err "Failed to create group '$group_name' using addgroup"
    return 1
  fi

  log_message authpriv.err "Cannot create group '$group_name': missing groupadd/addgroup"
  return 1
}


## @fn ensure_local_user_exists()
## @brief Ensure a local user exists, creating it when allowed and necessary.
## @details
## This function is part of the "portability layer" for local provisioning.
## It prefers useradd (RHEL/Debian/Ubuntu) when available, but also supports
## Alpine/BusyBox patterns (adduser).
##
## This function is idempotent:
## - If the user already exists, it returns success without making changes.
## - If the user does not exist, it attempts to create it using the first
##   supported backend tool it finds.
##
## Home directory creation is requested when the backend supports it because SSH
## deployments commonly assume a home directory exists (for example to place
## .ssh metadata).  If a target environment deliberately omits home directories,
## adjust this mechanism in a controlled and reviewable way.
##
## Note: on BusyBox/Alpine backends, primary group assignment may not be
## supported; membership updates are handled separately.
##
## @param username the local username to ensure exists
## @param uid optional numeric UID.  Pass an empty string to use system defaults
## @param primary_group optional primary group name or numeric GID.  Pass an empty string to use defaults
## @returns status via exit code
## @retval 0 the user exists or was created successfully
## @retval 1 the user does not exist and could not be created
## @par Examples
## @code
## ensure_local_user_exists "wes" "1001" "" || exit 1
## ensure_local_user_exists "alice" "" "" || exit 1
## @endcode
ensure_local_user_exists() {
  local username="${1?No username provided}"
  local uid="${2:-}"
  local primary_group="${3:-}"

  if getent passwd "$username" >/dev/null 2>&1; then
    return 0
  fi

  if command_exists useradd; then
    local args=()
    args+=("-m") # create home directory

    if [[ -n "$uid" ]]; then
      args+=("-u" "$uid")
    fi

    if [[ -n "$primary_group" ]]; then
      args+=("-g" "$primary_group")
    fi

    useradd "${args[@]}" "$username" >/dev/null 2>&1 && return 0

    log_message authpriv.err "Failed to create user '$username' using useradd"
    return 1
  fi

  # Alpine / BusyBox adduser syntax varies.  We use the most portable subset:
  # -D: do not assign a password (non-interactive creation)
  # -u: set UID (supported on Alpine and many BusyBox builds)
  # -G: set supplementary group (primary group control is not consistent)
  if command_exists adduser; then
    local args=()
    args+=("-D")

    if [[ -n "$uid" ]]; then
      args+=("-u" "$uid")
    fi

    # If the caller requested a primary group, we attempt to set it as a
    # supplementary group here.  The caller should still call
    # ensure_user_in_local_group() to enforce membership idempotently.
    if [[ -n "$primary_group" ]]; then
      args+=("-G" "$primary_group")
    fi

    adduser "${args[@]}" "$username" >/dev/null 2>&1 && return 0

    log_message authpriv.err "Failed to create user '$username' using adduser"
    return 1
  fi

  log_message authpriv.err "Cannot create user '$username': missing useradd/adduser"
  return 1
}


## @fn ensure_user_in_local_group()
## @brief Add a local user to a local group, idempotently.
## @details
## This function manages supplementary group membership in a cross-distro way.
## It first verifies that both the user and group exist locally, then checks
## whether the user is already a member of the target group.  If membership is
## already present, the function returns success without making changes.
##
## This function supports the following backends:
## - usermod -aG GROUP USER (RHEL, Debian/Ubuntu, many others)
## - addgroup USER GROUP (Alpine / BusyBox)
## - adduser USER GROUP (Debian-style helper, when present)
##
## The user and group existence checks are defensive.  They reduce confusing
## failures if a caller invokes this function without first ensuring that the
## user and group have been created.
##
## @param username Existing local username.
## @param group_name Existing local group name.
## @returns No output is written to STDOUT.
## @retval 0 Membership exists or was added successfully.
## @retval 1 Membership could not be verified or updated.
##
## @par Examples
## @code
## ensure_local_group_exists "developers"
## ensure_local_user_exists "alice" "" ""
## ensure_user_in_local_group "alice" "developers"
## @endcode
ensure_user_in_local_group() {
  local username="$1"
  local group_name="$2"

  # Defensive input validation.  This is not a replacement for validate_username().
  # It prevents confusing behavior when called incorrectly.
  if [[ -z "$username" || -z "$group_name" ]]; then
    log_message authpriv.err \
      "Cannot update group membership: missing username or group name"
    return 1
  fi

  # Defensive existence checks.  Callers should normally ensure these first.
  if ! getent passwd "$username" >/dev/null 2>&1; then
    log_message authpriv.err  \
      "Cannot update group membership: user '$username' does not exist"
    return 1
  fi

  if ! getent group "$group_name" >/dev/null 2>&1; then
    log_message authpriv.err \
      "Cannot update group membership: group '$group_name' does not exist"
    return 1
  fi

  # Fast-path: if the user is already a member, exit without changes.
  # id -nG prints group names; we normalize to one name per line for exact match.
  if id -nG "$username" 2>/dev/null | tr ' ' '\n' | grep -Fx "$group_name" >/dev/null 2>&1; then
    return 0
  fi

  # Preferred backend: usermod is widely available on RHEL/Debian/Ubuntu.
  if command_exists usermod; then
    if usermod -aG "$group_name" "$username" >/dev/null 2>&1; then
      return 0
    fi
    log_message authpriv.err \
      "Failed to add user '$username' to group '$group_name' using usermod"
    return 1
  fi

  # Alpine / BusyBox backend: addgroup USER GROUP.
  if command_exists addgroup; then
    if addgroup "$username" "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    log_message authpriv.err \
      "Failed to add user '$username' to group '$group_name' using addgroup"
    return 1
  fi

  # Debian helper backend: adduser USER GROUP.
  if command_exists adduser; then
    if adduser "$username" "$group_name" >/dev/null 2>&1; then
      return 0
    fi
    log_message authpriv.err \
      "Failed to add user '$username' to group '$group_name' using adduser"
    return 1
  fi

  log_message authpriv.err \
    "Cannot update group membership: no supported backend (usermod/addgroup/adduser missing)"
  return 1
}


## @fn remove_local_user_account()
## @brief Remove a local user account, including home directory when supported.
## @details
## This is a destructive operation and should only be invoked when explicitly
## enabled (for example via the script's $remove_user flag).
##
## Tool support differs across distributions:
## - userdel -r <user> is common with shadow tools (RHEL/Debian/Ubuntu)
## - deluser exists on Debian and some BusyBox/Alpine builds, with differing flags
##
## This function prefers userdel when available and falls back to deluser using
## multiple flag patterns.  If no supported tool exists, the function fails
## closed and logs an explicit error.
##
## @param username existing local username to remove
## @returns status via exit code
## @retval 0 user does not exist, or was removed successfully
## @retval 1 user exists and removal failed
## @par Examples
## @code
## remove_local_user_account "formeruser" || exit 1
## @endcode
remove_local_user_account() {
  local username="${1?No username provided}"

  if ! getent passwd "$username" >/dev/null 2>&1; then
    return 0
  fi

  if command_exists userdel; then
    userdel -r "$username" >/dev/null 2>&1 && return 0
    log_message authpriv.err "Failed to remove user '$username' using userdel -r"
    return 1
  fi

  if command_exists deluser; then
    # Debian: deluser --remove-home <user>
    deluser --remove-home "$username" >/dev/null 2>&1 && return 0
    # Some builds: deluser -r <user>
    deluser -r "$username" >/dev/null 2>&1 && return 0
    # BusyBox/Alpine: deluser <user>
    deluser "$username" >/dev/null 2>&1 && return 0

    log_message authpriv.err "Failed to remove user '$username' using deluser"
    return 1
  fi

  log_message authpriv.err "Cannot remove user '$username': missing userdel/deluser"
  return 1
}


## @fn create_local_group()
## @brief if we're allowed, create a local group
## @details
## If we're allowed to create groups (via $create_group) and
## the group doesn't exist locally, then create it.
## @param local_group the name of the group to create
## @param local_gid the GID of the group to create
## @retval 0 (True) if the group was created or it already existed
## @retval 1 (False) if the group could not be created
## @par Example
## @code
## create_local_group "sshusers" 1003
## @endcode
create_local_group() {
  local local_group="${1?No group provided}"
  local local_gid="${2?No GID provided}"

  if is_true "$create_group" &&
    [ -n "$local_group" ] &&
    is_false "$local_group_exists"; then
    ensure_local_group_exists "$local_group" "$local_gid" || return 1
  fi

  return 0
}


## @fn add_user_to_local_group()
## @brief if we're allowed to manage groups, adds user to a local group
## @details
## This does exactly what it says.  Permission via $manage_group.
## @param username the username to add to the group
## @param local_group the group to which the user should be added
## @retval 0 (True) if the user was added or they were already in the group
## @retval 1 (False) if the user couldn't be added
## @par Example
## @code
## add_user_to_local_group "wes" "sshusers" || exit 1
## @endcode
add_user_to_local_group() {
  local username="${1?No username provided}"
  local local_group="${2?No group name provided}"

  if is_true "$manage_group" &&
    [ -n "$local_group" ]; then
    ensure_user_in_local_group "$username" "$local_group" || return 1
  fi

  return 0
}


## @fn create_local_user()
## @brief if we're allowed to create a user, create the user
## @details
## This will create a user if we're allowed to create users if
## we're allowed (via create_user), the user exists remotely,
## and the user does NOT exist locally.
## @param username the username to create locally
## @retval 0 (True) if the user was created or they already existed
## @retval 1 (False) if the user could not be created
## @par Example
## @code
## create_local_user "wes" || exit 1
## @endcode
create_local_user() {
  local username="${1?No username provided}"
  if is_true "$create_user" &&
    is_true "$remote_user_exists" &&
    is_false "$local_user_exists"; then
    ensure_local_user_exists "$username" "$numeric_uid" "" || return 1
  fi

  return 0
}


# @fn remove_local_user()
## @brief if we're allowed to remove a user, remove the user
## @details
## This will remove a user IF the user exists both locally AND
## remotely, plus we're given permission (via remote_user).
##
## When removing the user, the user's home directory and
## associated spool files (cron, mail, etc.) will be removed
## first, then the user will be removed from the passwd
## database.
##
## This really isn't necessary for authentication purposes as
## if the user doesn't exist remotely (i.e., they're not in
## the remote group to check), they won't be able to login.
## It's really just for cleaning up after the user is gone. If
## space isn't a problem (cost, quota, etc.), it's recommended
## to leave this disabled) for name/id consistency mapping
## reasons.
## @param username the username to remove
## @retval 0 (True) if we removed the user or we didn't need to
## @retval 1 (False) if we were unable to remove the user
## @par Example
## @code
## remove_local_user "lastguy"
## @endcode
remove_local_user() {
  local username="${1?No username provided}"
  if is_true "$remove_user" &&
    is_true "$remote_user_exists" &&
    is_true "$local_user_exists"; then
    remove_local_user_account "$username" || return 1
  fi

  return 0
}


## @fn hex_to_dec()
## @brief convert a hexadecimal number (base 16) to decimal (base 10)
## @details
## Yes, printf and $(( )) can be used to do this.  However, we use
## bc because the hexadecimal numbers returned by sha1sum are way too
## large for the builtins and they overflow.  Boo.  Also, bc is pedantic
## about the case of the hexadecimal digits, so we use tr to make sure
## they're capitalized.  Work.
##
## The decimal (base 10) result is written to STDOUT.
## @param in the hexadecimal number to convert
## @retval 0 (True) if bc was happy
## @retval 1 (False) if bc decided to throw another fit
## @par Example
## @code
## echo "DEADBEEF in decimal is $(hex_to_dec "DEADBEEF")"
## @endcode
hex_to_dec() {
  in="${1?No input provided}"

  echo "scale=0; ibase=16; obase=10; $(echo "$in" | tr '[:lower:]' '[:upper:]')" | bc
}


## @fn name_to_id()
## @brief convert a user/group name, create a uid/gid from it
## @details
## We need to semi-reliably create users and groups whose
## uids and gids are consistent across multiple systems.  So,
## to generate an id, we hash the name that was provided and
## convert that hash into base-10 numbers (the hashes are hex)
## that we can use.
##
## To make sure we only use ids that are allowed for standard
## (non-system) use, we only allow ids that are between a
## minimum id and the maximum id using modulo.
##
## It's possible for there to be a collision between two
## names and a single id.  Therefore, when after we generate
## an id, we check to see if a name has already been mapped
## to that id on this system.  If so, we add one and try
## again up to max_tries (the third positional argument with a
## default value of 10) until we either find a match or we run
## out of tries at which point we fail.
##
## If we successfully find a name to id mapping, return it
## via STDOUT.
## @param string the string (user or group name) to use
## @param database the entity database (e.g., passwd or group) to query
## @param max_tries try this many times before returning failure (default = 10)
## @retval 0 (True) if we found a good mapping
## @retval 1 (False) if we could not find a good mapping
## @par Example
## @code
## uid="$(name_to_uid "wes" "passwd")" || exit 1
## @endcode
name_to_id() {
  string="${1?No string provided}"
  database="${2?No database provided}"
  max_tries="${3:-10}"

  local max_id=65535
  local min_id=2000
  local mod_id=$((max_id - min_id))

  local try=0

  while [ "$try" -lt "$max_tries" ]; do
    local hash_string
    hash_string="$(echo -n "$string" | sha1sum | head -c40)"
    id="$(echo "$min_id + $(hex_to_dec "$hash_string") % $mod_id" | bc)"

    if check_id "$string" "$id" "$database"; then
      echo "$id"
      return 0
    else
      ((try++))
    fi
  done

  return 1
}


## @fn check_id()
## @brief see if there's a collison between this name and this id
## @details
## This will check the local entity databases for the given name;
## if that name doesn't exist in the database, return true (if
## it doesn't exist, it can't be a collision by definition).  If
## the name does exist, look to see if it matches the given id; if
## so, return true.  If the name exists but it does NOT match the
## given id, we have a problem, so return false.
## @param name the entity name to check
## @param id the id the entity is expected to have
## @param database the database to query
## @retval 0 (True) if the name/id is good to use
## @retval 1 (False) if the name/id does NOT match
## @par Example
## @code
## if check_id "wes" 1000 passwd ; then echo "Cool" ; fi
## @endcode
check_id() {
  name="${1?No name provided}"
  id="${2?No id provided}"
  database="${3?No database provided}"

  if ! output="$(getent "$database" "$name")"; then
    return 0 # true -- if it doesn't exist yet, we're good
  else

    if [[ "$output" =~ :${id}: ]]; then
      return 0 # if the name matches the id, we're good
    else
      return 1 # if the name doesn't match the id, something's wrong
    fi
  fi
}


## @fn check_remote_group()
## @brief determine if a username belongs to an AWS IAM group
## @details
## This will check to see if, for an AWS IAM user's AWS IAM groups,
## there exists an entry for the remote_group.
## @param username the AWS IAM user to check
## @param remote_group the AWS IAM group to find
## @retval 0 (True) if the user's groups includes the provided group
## @retval 1 (False) if the user's groups does Not include the provided group
## @par Example
## @code
## if [ -n "remote_group" ] \
## && check_remote_group "$username" "$remote_group" ; then
##   echo "Congratulations on belonging to the group"
## else
##   echo "You don't belong to the group.  Talk to an admin."
## fi
##@endcode
check_remote_group() {

  username="${1?No username passed}"
  remote_group="${2?No remote_group passed}"

  remote_group_exists="$(
    aws iam get-group --group-name "$remote_group" >/dev/null 2>&1
    echo $?
  )"

  if is_true "$remote_group_exists"; then
    if ! aws iam list-groups-for-user --user-name "${username}" --output text --query "Groups[?GroupName=='${remote_group}'].GroupName" | grep -q "${remote_group}"; then
      remove_local_user "$username"
      return 1
    fi
  fi

  return 0
}


## @fn check_remote_user()
## @brief determine if a username exists remotely
## @param username the username to check
## @retval 0 (True) if the user exists (and has an ARN)
## @retval 1 (False) if the user does not exist
## @par Example
## @code
## if check_remote_user "wes" ; then
##   echo "Yay"
## else
##   echo "Boooooo"
## fi
## @endcode
check_remote_user() {
  username="${1?No username provided}"

  user_data="$(aws iam get-user --user-name "$username" --output text)"

  if [[ "$user_data" =~ arn:aws ]]; then
    return 0
  else
    return 1
  fi
}

## @fn get_public_keys()
## @brief write the public portion of the user's SSH keys to STDOUT
## @details
## For a given user, query AWS for all of their active SSH public keys
## and write them all to STDOUT.  If there are no public keys for the
## user, don't write anything (and return failure).
## @param username the username to query
## @retval 0 (True) and all active public keys written to STDOUT
## @retval 1 (False)
get_public_keys() {

  local found_public_key=1
  for key_id in $(aws iam list-ssh-public-keys --user-name "${username}" --query "SSHPublicKeys[?Status=='Active'].SSHPublicKeyId" --output text); do
    aws iam get-ssh-public-key --user-name "${username}" --ssh-public-key-id "${key_id}" --encoding SSH --query "SSHPublicKey.SSHPublicKeyBody" --output text
    found_public_key=0
  done

  if [ $found_public_key -eq 0 ]; then
    return 0 # True
  else
    return 1 # False
  fi
}


## @fn dependency_probe()
## @brief Probe runtime dependencies and document missing commands clearly.
## @details
## This script runs in sshd's AuthorizedKeysCommand context, often during
## authentication.  When failures occur, operators may be under cognitive
## load.  The primary goal of this function is clarity: every missing
## dependency is explicitly logged with the feature that requires it.
##
## Hard failure is secondary.  The caller controls whether missing
## dependencies are fatal via the hard_fail parameter.
##
## The probe evaluates:
## - Base dependencies required for key retrieval and ID mapping.
## - Conditional dependencies required only when provisioning features
##   such as local user creation or group management are enabled.
##
## The function writes only to syslog (and stderr via logger -s).
## It never writes to STDOUT, preserving AuthorizedKeysCommand integrity.
##
## @param create_user "true"/"false" indicating whether user creation is enabled.
## @param remove_user "true"/"false" indicating whether user removal is enabled.
## @param create_group "true"/"false" indicating whether group creation is enabled.
## @param manage_group "true"/"false" indicating whether group membership updates are enabled.
## @param hard_fail "true"/"false" indicating whether missing dependencies cause non-zero return.
## @returns No output is written to STDOUT.
## @retval 0 All required commands exist, or hard_fail is false.
## @retval 1 One or more required commands are missing and hard_fail is true.
##
## @par Examples
## @code
## dependency_probe "$create_user" "$remove_user" \
##   "$create_group" "$manage_group" "false"
##
## dependency_probe "$create_user" "$remove_user" \
##   "$create_group" "$manage_group" "true" || exit 1
## @endcode
dependency_probe() {
  local create_user="${1:-false}"
  local remove_user="${2:-false}"
  local create_group="${3:-false}"
  local manage_group="${4:-false}"
  local hard_fail="${5:-false}"

  local missing_any="false"

  _report_missing() {
    local cmd="$1"
    local context="$2"

  log_message authpriv.warning \
        "Dependency missing: '${cmd}' (required for: ${context})"

    missing_any="true"
  }

  _require_any_backend() {
    local capability="$1"
    shift
    local found="false"
    local cmd
    for cmd in "$@"; do
      if command_exists "$cmd"; then
        found="true"
        break
      fi
    done

    if is_false "$found"; then
      _report_missing "$*" "no supported backend found for ${capability}"
    fi
  }

  # Base dependencies required for core operation.
  if ! command_exists aws; then
    _report_missing "aws" "AWS IAM key and group queries"
  fi

  if ! command_exists sha1sum; then
    _report_missing "sha1sum" "deterministic name->ID mapping"
  fi

  if ! command_exists head; then
    _report_missing "head" "deterministic name->ID mapping"
  fi

  if ! command_exists bc; then
    _report_missing "bc" "deterministic name->ID mapping"
  fi

  if ! command_exists getent; then
    _report_missing "getent" "local account existence checks"
  fi

  if ! command_exists grep; then
    _report_missing "grep" "text filtering and parsing"
  fi

  if ! command_exists sed; then
    _report_missing "sed" "text normalization and parsing"
  fi

  if ! command_exists sort; then
    _report_missing "sort" "stable ordering of key material"
  fi

  if ! command_exists tr; then
    _report_missing "tr" "text normalization and parsing"
  fi

  # Conditional dependencies for provisioning features.
  if is_true "$create_group"; then
    _require_any_backend "local group creation" groupadd addgroup
  fi

  if is_true "$create_user"; then
    _require_any_backend "local user creation" useradd adduser
  fi

  if is_true "$remove_user"; then
    _require_any_backend "local user removal" userdel deluser
  fi

  if is_true "$manage_group"; then
    if ! command_exists id; then
      _report_missing "id" "local group membership verification (id -nG)"
    fi

    # Group membership updates require at least one supported backend.
    # Use _report_missing so logger absence still produces clear output.
    if command_exists usermod || command_exists addgroup || command_exists adduser; then
      :
    else
      _report_missing "usermod/addgroup/adduser" \
        "local group membership updates (no supported backend found)"
    fi
  fi

  if is_true "$missing_any"; then
    log_message authpriv.warning \
      "Dependency probe detected missing commands. Review prior log lines."

    if is_true "$hard_fail"; then
      return 1
    fi

    return 0
  fi

  log_message authpriv.info \
    "Dependency probe completed successfully. All required commands detected."

  return 0
}


## @fn show_help()
## @brief display a help message then exit the program
## @details
## The first sed script takes line starting with the first Doxygen-
## style 'file' parameter up to and including the first line with
## the 'author' parameter; this becomes the first part of the help
## message.
##
## So, to use this, the first part of the Bash script needs to
## be Doxygen-style markup starting with the 'file' parameter
## and should end with the 'author' parameter's line (that is,
## we use the entire line that the 'author' parameter uses).
##
## Next, we use another sed script that looks for options to
## getopts that have comments starting with ##- and extracts
## the option followed by the comment.
## @retval 0 (True) if sed was happy
## @retval 1 (False) if sed was NOT happy
## @par Example
## @code
## show_help ; exit 0
## @endcode
show_help() {

  md_header "$(basename "$0")" "="

  sed \
    --zero-terminated \
    --regexp-extended \
    --expression='s/.*@[Bb]rief *(.*)@[Aa]uthor *([^\n]*).*/Overview\n--------\n\n\1Author\n------\n\n\2\n/' \
    --regexp-extended --expression='s/\B@[a-z]* *//g' \
    --regexp-extended --expression='s/##[^ ]/\n/g' \
    --regexp-extended --expression 's/## //g' \
    "$0"

  md_header "Parameters" "-"

  sed \
    --quiet \
    --regexp-extended \
    --expression='s/^ *([A-Z]) * \).*#{2}- */* -\1 : /ip' \
    "$0" |
    sort --ignore-case

  md_header "Defaults" "-"

  sed \
    --regexp-extended \
    --quiet \
    --expression='
      /^[[:space:]]*##[[:space:]]*@var/ {
        s/^[[:space:]]*##[[:space:]]*@var[[:space:]]*((DEFAULT_)?([^[:space:]]+))(.*)/* \3: \4/;
        p;
        n;
        s/([^=]*=)(.*)$/  (default: \2)/;
        p;
      }' \
    "$0"
}

create_user="$(is_true "$DEFAULT_CREATE_USER")"   # -u
remove_user="$(is_true "$DEFAULT_REMOVE_USER")"   # -r
create_group="$(is_true "$DEFAULT_CREATE_GROUP")" # -c
manage_group="$(is_true "$DEFAULT_MANAGE_GROUP")" # -m
remote_group="$DEFAULT_REMOTE_GROUP"              # -g
local_group="$DEFAULT_LOCAL_GROUP"                # -l

while getopts "urcmg:l:h" option; do
  case "$option" in
  u) create_user=$((1 - create_user)) ;; ##- create local user
  r) remove_user=$((1 - remove_user)) ;; ##- remove local user
  h)
    show_help
    exit 0
    ;;                                      ##- show help text
  g) remote_group="$OPTARG" ;;             ##- the remote group to query
  l) local_group="$OPTARG" ;;              ##- the local group to create
  c) create_group=$((1 - create_group)) ;; ##- create local group
  m) manage_group=$((1 - manage_group)) ;; ##- mange local group members
  *)
    echo "Invalid option '$option'" 1>&2
    show_help 1>&2
    exit 1
    ;;
  esac
done

shift $((OPTIND - 1))

username="${1?No username provided}"

# Verify that our dependencies are present
dependency_probe


if ! validate_username "$username"; then
  # Invalid usernames are denied authentication by failing closed.
  exit 1
fi

if ! numeric_uid="$(name_to_id "$username" "passwd")"; then
  log_message authpriv.err "Could not find an appropriate UID for '$username'"
  exit 1
fi

if [ -n "$local_group" ] &&
  ! numeric_gid="$(name_to_id "$local_group" "group")"; then
  log_message authpriv.err "Could not find an appropriate GID for '$local_group'"
  exit 1
fi

local_user_exists="$(
  getent passwd "$username" >/dev/null
  echo "$?"
)"

local_group_exists="1"  # assume group does not exist

if [[ -n "$local_group" ]]; then
  if getent group "$local_group" >/dev/null 2>&1 ; then
    local_group_exists="0"
  else
    local_group_exists="1"
  fi
fi

if check_remote_user "$username" ; then
  remote_user_exists=0
else
  log_message authpriv.err "User '$username' does not exist remotely."
  exit 1
fi

if [ -n "$remote_group" ] &&
  ! check_remote_group "$username" "$remote_group"; then
  log_message authpriv.err "This user does not belong to the provided group"
  exit 1
fi

if ! create_local_user "$username" "$numeric_uid"; then
  log authpriv.err "Could not create local user '$username' (uid: $numeric_uid)"
  exit 1
fi

if ! create_local_group "$local_group" "$numeric_gid"; then
  log_message authpriv.err "Could not create local group '$local_group' (gid: $numeric_gid)"
  exit 1
fi

if ! add_user_to_local_group "$username" "$local_group"; then
  log_message authpriv.err "Could not add user '$username' to group '$local_group'"
  exit 1
fi

if ! get_public_keys "$username"; then
  log_message authpriv.err "Could not retrieve SSH public keys for '$username'"
  exit 1
fi
