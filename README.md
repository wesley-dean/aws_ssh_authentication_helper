
aws_ssh_authentication_helper.bash
==================================

Overview
--------

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
before permitting authentication.  The group to query may be specified
via '-g' followed by the name of the AWS IAM group.

User Creation
-------------

When users attempt to connect, this tool can create their accounts
automatically.  Accounts will only be created if the username matches
an AWS IAM user.  Moreover, if an AWS IAM group is provided, they will
only be created if that AWS IAM user exists in that AWS IAM group.

User creation is disabled by default but may be enabled via '-u'

Local Groups
------------

The tool also supports group management in that when users attempt to
authenticate, they can be automatically added to a local (non-IAM) group.
If the group doesn't exist, it will be created.  This functionality
is disabled by default but may be enabled via '-m' while the name
of the local group to manage may be specified via '-l'

The adding of users to groups, while it takes place at authentication
time, is not restricted to only new users being created for the first
time.  That is, if the manage group setting is enabled and a previously
seen user attempts to login, they will be added to that group.

User Removal
------------

When a user attempts to authenticate and either they do not belong to
the required AWS IAM group or there is no corresponding AWS IAM user
account, their local account can be removed.  Account removal
functionality is disabled by default but may be enabled via '-r'

Regardless of the remove user setting, users who do not have an
enabled AWS IAM user account or are not in a specified
AWS IAM group will be denied authentication.

AWS IAM Access
--------------

It's notable that changes made in AWS only affect new connections;
that is, if a user is already logged in and then their AWS IAM
account is disabled, their connection won't be dropped, interrupted,
etc..  Manual intervention would be required to terminate current,
active sessions.

The following AWS IAM permissions are required for this script to
interact with AWS's APIs:

* iam:GetSSHPublicKey
* iam:ListSSHPublicKey
* iam:ListGroupsForUser
* iam:GetGroup
* iam:GetUser

Consider the following AWS IAM policy:

```json

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

SSHD setup
----------

The SSH daemon needs to be configured to use this script to acquire
the "authorized_keys" files (i.e., the list of public portions of
SSH keys that are allowed access).  This can be done by setting the
`AuthorizedKeysCommand` in `/etc/ssh/sshd_config` as follows:

```

AuthorizedKeysCommand /path/to/aws_ssh_authentication_helper.bash
AuthorizedKeysCommandUser nobody

```

Note: either `nobody` or `root` should be used depending on whether
or not this script will be managing users or groups (i.e., creating
new users, adding users to groups, removing users, etc.) or not.  If
the script will be managing users or groups, then `root` needs to be
used.  If, however, accounts and groups will be managed manually,
then `nobody` may be used.  Using `nobody` is much more secure;
however, it also requires manual work to create accounts and such.

Author
------

Wes Dean <wdean@flexion.us>

Parameters
----------

* -c : create local group
* -g : the remote group to query
* -h : show help text
* -l : the local group to create
* -m : mange local group members
* -r : remove local user
* -u : create local user

Defaults
--------

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
