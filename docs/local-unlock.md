# Local unlock: Touch ID, PIN and login password

Each profile can have local unlock protectors, so you type the master password less often. Each one is enrolled
with the master password once, is bound to this device, and can only unlock. An item that asks for the master
password again (a reprompt item) still needs the master password.

`dybw unlock` tries the protectors in this order, and you can cancel one to move on to the next:

1. `login`, which needs no question: logging in or unlocking the screen has already unlocked the profile;
2. `biometric`, the Touch ID sheet;
3. `pin`;
4. the master password.

| Command | What it does |
|---------|--------------|
| `dybw unlock add pin` | Enrol a PIN |
| `dybw unlock add biometric [--any] [--watch]` | Enrol Touch ID (macOS) |
| `dybw unlock add login` | Enrol your login password (Linux, `pam_bwss`) |
| `dybw unlock remove pin\|biometric\|login` | Drop a protector |
| `dybw unlock list` | The profile's protectors, and the wrong attempts each has left |
| `dybw status` | Shows the protectors among the profile's state |

An AI-class or unnamed caller cannot add a PIN or Touch ID protector, nor remove any protector. In
`dybw unlock list`, an AI-class caller sees names only.

## PIN

```sh
dybw unlock add pin
```

The agent's pinentry asks for the master password, then for the PIN twice. The PIN must be at least 6 characters.

- It lives in the agent's memory only. `dybw lock` and the idle lock keep it.
- `dybw agent stop`, `dybw login`, `rbw purge`, a user-key rotation and 5 wrong PINs drop it.
- `dybw unlock list` shows how many wrong tries are left.

## Touch ID (macOS)

```sh
dybw unlock add biometric
```

This needs a Mac with a Secure Enclave. After the master password, the agent makes a P-256 key in the Secure
Enclave, with no Touch ID at enrolment. The user key is wrapped to it and kept in
`~/.local/state/dybw/profiles/<profile>/unlock/biometric` (0600), with the key's handle. Only this Mac's Secure
Enclave can use it.

- Every unlock shows a Touch ID sheet that names the profile ("Unlock dybw profile <profile>").
- A cancel, no sensor (the lid is closed), a lockout or another error moves on to the PIN or the master password, and
  keeps the protector. An unknown caller's unlock shows no sheet. An AI-class caller never raises it.
- Adding or removing a fingerprint makes the key unusable. The next unlock deletes the protector and asks for the
  master password. With `--any`, any finger enrolled at the time of use opens it instead, which is weaker.
- `--watch` lets an Apple Watch open it too. On macOS 15 and later, another paired device can as well.
- A file bound to another device or machine, or found on a machine without a Secure Enclave, is deleted before any
  sheet shows. A user-key rotation, `dybw login` and `rbw purge` delete it too. Enrolling again needs the master
  password.

### Touch ID for confirmations

On a Mac with Touch ID, a read confirmation for a caller with a stable identity shows the Touch ID sheet first. A
stable identity means a plain program, or an interpreter running a script by its absolute path, not detached. The
sheet says what is done to which item (the field, or the full item) and the profile, then the program's file name.

- A matching finger is a yes, for this request only. A finger that does not match is a no.
- A cancel, no sensor or a closed lid moves the whole question to the pinentry, which offers "always" where it can.
- These are asked in the pinentry only: AI-class, unknown and detached callers; a bare interpreter, a launcher or a
  relative script; a policy change; `rbw purge`; the removal of a marked item; a forwarded SSH request; a failed
  session-bind; and a login to a host that is not verified.
- Each audit line of a confirmation records where it was answered: `"channel": "touch-id"` or `"pinentry"`.
- `[agent] touch_id_confirm = false` in `config.toml` turns Touch ID confirmations off.

## Login password (Linux, `pam_bwss`)

```sh
dybw unlock add login
```

This needs `pam_bwss` (from bwss) in your PAM stack. The agent asks for the master password, then for your login
password twice. The login password is not checked against the system, so type it exactly. The key is wrapped by
Argon2id over that password and kept in `~/.local/state/dybw/profiles/<profile>/unlock/login` (0600), bound to this
device.

- Logging in or unlocking the screen then unlocks the profile without a question. `pam_bwss` puts the password in
  your kernel keyring. The agent takes it (it polls every second while a profile has this protector) and
  invalidates it at once.
- A password change re-wraps the key. The old wrap stays until you log in with the new password.
- A login password that opens neither the protector nor a pending re-wrap (a reset by root, say) deletes the
  protector. Another machine, a rotation, `dybw login` and `rbw purge` delete it too. The next unlock then asks for
  the PIN or the master password, and enrolling again needs the master password.
- When your last logind session closes, every profile locks.
- Without a TPM2, someone who takes the disk can guess the login password offline.
