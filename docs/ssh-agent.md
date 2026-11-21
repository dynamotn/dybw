# The SSH agent

`dybw-agent` also speaks the OpenSSH agent protocol, for the SSH key items in your vault. It replaces key files and
`ssh-agent`. It signs, and it never returns or accepts a private key.

## Setup

1. Store your SSH keys as SSH key items in the vault (for example from the Bitwarden desktop app or web vault).
2. List the profiles to offer, in order, in `~/.config/dybw/config.toml`:

   ```toml
   [ssh_agent]
   profiles = ["personal", "work"]
   ```

3. Point `SSH_AUTH_SOCK` at the socket, which sits next to the agent's own socket:

   ```sh
   export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/dybw/ssh-agent.sock"        # Linux
   export SSH_AUTH_SOCK="${TMPDIR%/}/dybw-$(id -u)/ssh-agent.sock"    # macOS, or wherever XDG_RUNTIME_DIR is unset
   ```

4. Check it:

   ```sh
   dybw ssh list     # name, fingerprint, type and profile of each offered key; locked profiles named on stderr
   ssh-add -l
   dybw doctor       # checks the socket, and that SSH_AUTH_SOCK points at it
   ```

## Which keys are offered

- The personal SSH key items of the profiles in `[ssh_agent] profiles`, while those profiles are unlocked.
  Organization keys are not offered.
- Listing decrypts only names and public keys. A key held by several items is offered once.
- A locked profile offers no keys. A signature request for a key the agent does not offer asks, in the pinentry, to
  unlock the locked profiles one at a time and in order, until one holds the key. The question names the SSH client.
  If you cancel it, that client is not asked again until the profile is unlocked some other way, for example with
  `dybw unlock`. An AI-class client is never asked: its request is refused and audited.

## Confirming signatures

The first use of a key by a client process asks for confirmation. The prompt names:

- the profile;
- the client: the SSH program and the program that ran it, the AI agent for an AI-class client, or that it cannot be
  identified;
- the key: item name and `SHA256:` fingerprint;
- what is signed. For a login, that is the user and, through `session-bind@openssh.com` (OpenSSH 8.9 and later), the
  destination host-key fingerprint, or a note that the host is not verified. Anything else (a git commit signed with
  `ssh-keygen -Y sign`, a file, a challenge) is labelled "NOT an SSH login". Forwarded requests and failed
  session-binds are called out.

On a Mac, the Touch ID sheet asks first. These are asked in the pinentry only: a forwarded request, a failed
session-bind, and a login to a host that is not verified.

**"Always for this session"** is remembered in memory for that client process (pid, start time and executable), that
key and that kind of request (a login, or data that is not one), until the profile locks. It is offered only where a
value read could be remembered. So it is never offered to `ssh` itself (a launcher, and one login signs once anyway),
a bare interpreter, a relative script, or an AI-class, unidentifiable or detached client. Those are asked every time.
It is never offered for, nor used by, a forwarded request (`ssh -A`).

**Refusals.** A client that says no three times is asked nothing more until the profile locks or unlocks. Its
requests are refused and logged. A connection whose session-bind failed, and that has no other binding, signs
nothing.

**Caller policy.** A `dybw policy deny` entry for a program refuses its signatures without a question. An allow entry
never skips the confirmation.

## Algorithms

Ed25519, ECDSA P-256, P-384 and P-521, and RSA with `rsa-sha2-256` or `rsa-sha2-512`. A SHA-1 `ssh-rsa` request is
refused. Every signature is checked against the item's public key before it is returned.

## `ssh-add`

- `ssh-add -l` lists the keys.
- `ssh-add -d` and `ssh-add -D` remove keys from the agent's view, in memory, until the agent restarts. A lock does
  not restore them. `-D` removes only the keys offered at that moment, so the keys of a profile that was locked come
  back when it unlocks. The vault is never changed. AI-class clients cannot remove keys, and every removal is logged
  (`op: ssh-remove`).
- `ssh-add <file>` is refused.

## Forwarding

Agent forwarding (`ssh -A`) offers the same keys and asks the same confirmations, and the prompt shows that the
request is forwarded.

## Audit

Every signature decision is logged with `op: ssh-sign`: login or data, item id, key fingerprint, the destination
host-key fingerprint for a login bound to its session, whether it was forwarded, the client programs and the verdict.
A request refused before any key was found (not offered, unlock refused or cancelled) is logged with the requested
key's fingerprint and no item. Key listings are not logged one by one. See [policy.md](policy.md#the-audit-log).
