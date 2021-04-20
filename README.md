# aws_ssh_authentication_helper

This is a Bash script to allow users to authenticate over SSH
with their AWS Code Commit public keys.
Usage: aws_ssh_authentication_helper.bash
allow users to authenticate via SSH public keys in AWS Code Commit

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

Additionally, when the user attempts to connect, an AWS IAM group may be
provided; if so, the tool will verify that the user exists in that group
before permitting authentication.

When users attempt to connect, this tool can create their accounts
automatically.  Accounts will only be created if the username matches
an AWS IAM user.  Moreover, if an AWS IAM group is provided, they will
only be created if that AWS IAM user exists in that AWS IAM group.  This
functionality is enabled by default but may be disabled via the
'create_user' environment variable (set it to "false" or "no").

The tool also supports group management in that when users attempt to
authenticate, they can be automatically added to a local (non-IAM) group.
If the group doesn't exist, it will be created.  By default, this group
is 'users' but that can be changed via environment variable (local_group).

The adding of users to groups, while it takes place at authentication
time, is not restricted to only new users being created for the first
time.  That is, if the local_group setting is updated and a previously
seen user attempts to login, they will be added to that group.

When a user attempts to authenticate and either they do not belong to
the required AWS IAM group or there is no corresponding AWS IAM user
account, their local account can be removed.  This functionality is
disabled by default but can be enabled via an environment variable
(remove_user).  Regardless of that environment variable, users who
do not have an enabled AWS IAM user account or are not in a specified
AWS IAM group will be denied authentication.

It's notable that changes made in AWS only affect new connections;
that is, if a user is already logged in and then their AWS IAM
account is disabled, their connection won't be dropped, interrupted,
etc..  Manual intervention would be required to terminate current,
active sessions.

Environment variables:

* local_group: the name of the local group users to which users
should be added (default = 'users')

* create_user: whether or not to create accounts for previously
unseen users when they attempt to connect (default = true)

* remove_user: whether or not to delete accounts disabled or
removed from the AWS side when they attempt to connect (default = false)

* create_group: whether or not to create the local_group when the
user attempts to login (default = true)

* manage_group: wheether or not to add users to the local_group when
they attempt to login (default = true)

Author: Wes Dean <wdean@flexion.us>

Usage:
    -c : create local group
    -g : the remote group to query
    -h : show help text
    -m : mange local group members
    -r : remove local user
    -u : create local user

Defaults:
    create_user   = 'false'
    remove_user   = 'false'
    create_group  = 'false'
    manage_group  = 'false'
    remote_group  = 'sshusers'
