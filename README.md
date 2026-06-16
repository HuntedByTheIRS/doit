# doit — temporary root access, like doas

`doit` is a setuid-root binary that allows authorized users to execute commands
as root, controlled by `/etc/doit.conf`.

## Configuration

Edit `/etc/doit.conf` with lines of the form:

```
<user> permit [nopass|extend]
```

The qualifier (`nopass` or `extend`) is optional.  Three modes are available:

| Line | Behaviour |
|---|---|
| `user permit` | Password required **every** time |
| `user permit nopass` | No password ever required |
| `user permit extend` | 10 password-free uses, then password required (counter resets on auth) |

Comments (`#`) and blank lines are ignored.

### Example

```
# Alice needs a password every time
alice permit

# Bob can run anything without a password
bob permit nopass

# Carol gets 10 free uses, then needs her password
carol permit extend
```

## Installation

### 1. Build

```sh
cargo build --release
```

### 2. Install the binary

```sh
sudo cp target/release/doit /usr/local/bin/doit
sudo chown root:root /usr/local/bin/doit
sudo chmod u+s /usr/local/bin/doit
```

The `u+s` (setuid) bit is required so the binary runs as root regardless of
who invokes it.

### 3. Create the configuration file

```sh
sudo mkdir -p /etc
# Edit the file to add your rules
sudo tee /etc/doit.conf <<'EOF'
alice permit nopass
bob permit extend
EOF
```

### 4. (For `extend` users) Create the counter directory

```sh
sudo mkdir -p /var/lib/doit
sudo chmod 700 /var/lib/doit
```

The binary creates this directory automatically if it doesn't exist, but the
above ensures the correct permissions upfront.

## Usage

```sh
doit <command> [args...]
```

The command is executed verbatim as root. Because the binary uses `exec()`,
it replaces itself with the requested command; signals and exit codes behave
as if the command were run directly.

### Examples

```sh
doit whoami                                 # prints "root"
doit systemctl restart nginx
doit pacman -Syu
```

## How it works

1. `doit` is a setuid-root binary. When invoked, the kernel runs it as root,
   but `getuid()` still returns the *real* user ID (the caller).
2. It reads `/etc/doit.conf` and checks whether the real user is permitted.
3. Depending on the permit mode:
   - **bare `permit`** — prompts for the password every time.
   - **`nopass`** — proceeds immediately.
   - **`extend`** — reads a persistent counter (`/var/lib/doit/counter.json`).
     If the counter is positive it decrements and allows nopass. If zero, it
     prompts for the user's password (verified against `/etc/shadow`) and
     resets the counter to 10.
4. Once authorized, it calls `exec()` on the requested command, replacing the
   `doit` process with the command running as root.

## Security notes

- The binary **must** be owned by `root` and have the setuid bit set.
- The config file `/etc/doit.conf` should be owned by `root:root` with mode
  `644` or `600`.
- The counter directory `/var/lib/doit` should be owned by `root:root` with
  mode `700` to prevent other users from tampering with usage counts.
- Password verification uses the `sha-crypt` Rust crate and compares hashes
  using the same SHA-512-crypt algorithm that glibc uses. Only `$6$` (SHA-512)
  hashes are supported.
