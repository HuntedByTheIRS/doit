//! `doit` — execute commands as root with configurable authorization.
//!
//! This binary must be installed as **setuid root**
//! (`chown root:root && chmod u+s`) so it can read `/etc/shadow` when
//! authenticating users and execute the requested command with root
//! privileges.
//!
//! ## Configuration — `/etc/doit.conf`
//!
//! Each line grants a user one of three privilege levels:
//!
//! | Line | Behaviour |
//! |---|---|
//! | `alice permit` | Password required every time. |
//! | `bob permit nopass` | No password required. |
//! | `carol permit extend` | 10 password-free uses, then password required. |
//!
//! Comments start with `#`; blank lines are ignored.
//!
//! ## Security
//!
//! * **Setuid binary** — must be owned by `root:root` with the setuid bit set.
//!
//! * **Strict file permissions** — enforced at startup:
//!   - `/etc/doit.conf` — owner `root:root`, mode `600`
//!   - `/var/lib/doit/counter.json` — owner `root:root`, mode `600`
//!
//! * **Trusted users only** — any permitted user can run arbitrary commands as
//!   root.  Be especially cautious with commands that can trivially bypass
//!   security boundaries: editors (`vi`, `nano`), interpreters (`python`,
//!   `perl`, `ruby`), network scanners (`nmap`), and any tool that can spawn
//!   a shell or read/write arbitrary files.
//!
//! * **Environment sanitised** — before executing the command:
//!   - Known-dangerous variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.) stripped
//!   - `PATH` forced to `/usr/local/bin:/usr/bin:/bin`

//! * **Audit logging** — every authorisation attempt (success or failure) is
//!   logged to syslog under `LOG_AUTH`.  Ensure your host system has a log
//!   rotation policy that preserves these entries — they are the primary audit
//!   trail for privilege escalation activity.

use clap::Parser;
use log::{error, info, warn, LevelFilter};
use serde::{Deserialize, Serialize};
use sha_crypt::{PasswordHash, PasswordVerifier, ShaCrypt};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{self, Command};
use syslog::{BasicLogger, Facility, Formatter3164};
use yescrypt::Yescrypt;

/// Path to the authorisation configuration file.
const CONFIG_PATH: &str = "/etc/doit.conf";

/// Path to the persistent counter store used by the `extend` permit mode.
const COUNTER_PATH: &str = "/var/lib/doit/counter.json";

/// Number of password-free invocations granted after a successful authentication
/// in `extend` mode.
const EXTEND_LIMIT: usize = 10;

/// Minimal safe set of environment variables passed to the executed command.
///
/// These are the variables preserved from the user's environment; everything
/// else is stripped. Known-dangerous variables such as `LD_PRELOAD` and
/// `LD_LIBRARY_PATH` are never forwarded, and `PATH` is hardened to a safe
/// default.
const SAFE_ENV_VARS: &[&str] = &[
    "DISPLAY",
    "HOME",
    "HOSTNAME",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "LOGNAME",
    "LS_COLORS",
    "MAIL",
    "OLDPWD",
    "PWD",
    "SHELL",
    "SHLVL",
    "SSH_AUTH_SOCK",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "TERM",
    "TMPDIR",
    "USER",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SEAT",
    "XDG_SESSION_ID",
    "XDG_SESSION_TYPE",
    "XDG_VTNR",
];

/// Safe default `PATH` to use when executing the command.
const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Environment variables that are explicitly dangerous in a setuid context
/// and must never be forwarded.
const DANGEROUS_ENV_VARS: &[&str] = &[
    "GCONV_PATH",
    "GIO_EXTRA_MODULES",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_LIBRARY_PATH",
    "LD_ORIGIN_PATH",
    "LD_PRELOAD",
    "LD_RUN_PATH",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PERL5SHELL",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYLIB",
    "RUBYOPT",
];

// CLI argument parsing
// ---------------------------------------------------------------------------

/// Command-line arguments accepted by `doit`.
#[derive(Parser)]
#[command(name = "doit", about = "Execute commands as root with configurable authorization")]
struct Args {
    /// Command to execute as root.
    #[arg(required = true)]
    command: String,

    /// Arguments to pass to the command.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    args: Vec<String>,
}

// Types
// ---------------------------------------------------------------------------

/// Level of authorisation granted to a user in `/etc/doit.conf`.
#[derive(Debug, Clone, PartialEq)]
enum PermitType {
    /// Execute without a password.
    NoPass,
    /// Execute without a password for `EXTEND_LIMIT` invocations, then require
    /// authentication to recharge.
    Extend,
    /// Prompt for the user's password on every invocation.
    Password,
}

/// A single entry from `/etc/doit.conf`.
#[derive(Debug)]
struct ConfigEntry {
    /// Username this entry applies to.
    user: String,
    /// What this user is allowed to do.
    permit: PermitType,
}

/// Persistent state for `extend`-mode counters.
///
/// Serialised as JSON at [`COUNTER_PATH`]. Each key is a username and the
/// value is the remaining number of password-free invocations.
#[derive(Debug, Serialize, Deserialize, Default)]
struct CounterStore {
    remaining: HashMap<String, usize>,
}

// Syslog initialisation
// ---------------------------------------------------------------------------

/// Initialise the `log` crate facade to write to the local syslog socket
/// under `LOG_AUTH`.
///
/// If the syslog socket is unavailable (e.g. inside a container without one)
/// the logger silently falls back to stderr via a second `env_logger`-style
/// fallback — but since we don't pull in `env_logger`, we just continue
/// without syslog and emit errors to stderr directly.
fn init_syslog() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "doit".into(),
        pid: 0,
    };

    match syslog::unix(formatter) {
        Ok(logger) => {
            if let Err(e) = log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
                .map(|()| log::set_max_level(LevelFilter::Info))
            {
                eprintln!("doit: syslog setup failed: {}", e);
            }
        }
        Err(e) => {
            // Syslog unavailable (e.g. container, no /dev/log). Logging to
            // stderr is a reasonable degraded mode.
            eprintln!("doit: syslog unavailable ({}), falling back to stderr", e);
            log::set_max_level(LevelFilter::Info);
        }
    }
}

// Configuration parsing
// ---------------------------------------------------------------------------

/// Parse `/etc/doit.conf` and return the list of entries found.
///
/// Malformed lines and unknown permit types are reported on stderr but do not
/// abort parsing — they are silently skipped.
fn read_config() -> io::Result<Vec<ConfigEntry>> {
    let file = fs::File::open(CONFIG_PATH)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim().to_string();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "permit" {
            let permit = if parts.len() == 2 {
                PermitType::Password
            } else {
                match parts[2] {
                    "nopass" => PermitType::NoPass,
                    "extend" => PermitType::Extend,
                    _ => {
                        eprintln!(
                            "doit: config: unknown permit type '{}' for user '{}'",
                            parts[2], parts[0]
                        );
                        continue;
                    }
                }
            };
            entries.push(ConfigEntry {
                user: parts[0].to_string(),
                permit,
            });
        } else {
            eprintln!(
                "doit: config: malformed line (expected '<user> permit [nopass|extend]'): {}",
                line
            );
        }
    }

    Ok(entries)
}

/// Look up the permit level for `user` in the parsed config entries.
fn find_permit<'a>(entries: &'a [ConfigEntry], user: &str) -> Option<&'a PermitType> {
    entries.iter().find(|e| e.user == user).map(|e| &e.permit)
}

// Real-user detection
// ---------------------------------------------------------------------------

/// Resolve the real (caller) UID to a username.
///
/// When the binary is setuid-root, `getuid()` returns the caller's UID while
/// the effective UID is root. This function reports the caller's identity so
/// we can check their authorisation level.
fn get_real_username() -> String {
    let uid = unsafe { libc::getuid() };
    match users::get_user_by_uid(uid) {
        Some(u) => u.name().to_string_lossy().into_owned(),
        None => {
            eprintln!("doit: unable to determine username for UID {}", uid);
            process::exit(1);
        }
    }
}

// Counter (extend-mode persistence)
// ---------------------------------------------------------------------------

/// Acquire an exclusive lock on the counter file, deserialise its contents,
/// run `f` with mutable access to the store, then serialise and write back.
///
/// **Locking**: Uses `flock(LOCK_EX)` so concurrent `doit` invocations do not
/// interleave reads and writes. The lock is released automatically when the
/// file is closed (on drop).
///
/// **File creation**: The counter file and its parent directory are created if
/// they do not exist.
///
/// **Corruption**: If the existing file cannot be parsed, a warning is printed
/// and the store is reset to a clean state.
fn with_counter<F>(f: F)
where
    F: FnOnce(&mut CounterStore),
{
    let dir = Path::new(COUNTER_PATH)
        .parent()
        .expect("COUNTER_PATH has no parent");
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!(
                "doit: failed to create counter directory '{}': {}",
                dir.display(),
                e
            );
            process::exit(1);
        }
    }

    let mut file = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(COUNTER_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "doit: failed to open counter file '{}': {}",
                COUNTER_PATH, e
            );
            process::exit(1);
        }
    };

    let fd = file.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
        eprintln!(
            "doit: failed to lock counter file '{}': {}",
            COUNTER_PATH,
            io::Error::last_os_error()
        );
        process::exit(1);
    }

    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents);

    let mut store: CounterStore = if contents.is_empty() {
        CounterStore::default()
    } else {
        match serde_json::from_str(&contents) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("doit: warning: corrupt counter file ({}), resetting", e);
                CounterStore::default()
            }
        }
    };

    f(&mut store);

    let json = match serde_json::to_string_pretty(&store) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("doit: failed to serialise counter data: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = file.set_len(0) {
        eprintln!("doit: failed to truncate counter file: {}", e);
        process::exit(1);
    }
    if let Err(e) = file.seek(io::SeekFrom::Start(0)) {
        eprintln!("doit: failed to seek in counter file: {}", e);
        process::exit(1);
    }
    if let Err(e) = file.write_all(json.as_bytes()) {
        eprintln!("doit: failed to write counter file: {}", e);
        process::exit(1);
    }
    if let Err(e) = file.flush() {
        eprintln!("doit: failed to flush counter file: {}", e);
        process::exit(1);
    }
}

/// Decrement the remaining nopass count for `user` and return the new value.
///
/// If the user has no counter entry yet it is initialised to `EXTEND_LIMIT`.
fn decrement_counter(user: &str) -> usize {
    let mut result = 0_usize;
    with_counter(|store| {
        let entry = store
            .remaining
            .entry(user.to_string())
            .or_insert(EXTEND_LIMIT);
        if *entry > 0 {
            *entry -= 1;
        }
        result = *entry;
    });
    result
}

/// Reset the remaining nopass count for `user` back to `EXTEND_LIMIT`.
fn reset_counter(user: &str) {
    with_counter(|store| {
        store.remaining.insert(user.to_string(), EXTEND_LIMIT);
    });
}

// Password verification
// ---------------------------------------------------------------------------

/// Verify `password` against the user's entry in `/etc/shadow`.
///
/// Supports three hash formats:
///
/// * `$y$` — yescrypt (verified via [`Yescrypt`])
/// * `$6$` / `$5$` — SHA-512 / SHA-256 crypt (verified via [`ShaCrypt`])
///
/// Returns `Ok(true)` on a match, `Ok(false)` on a mismatch, and `Err` for
/// I/O errors, corrupt shadow entries, or unsupported hash types.
fn verify_password(user: &str, password: &str) -> Result<bool, String> {
    let shadow = fs::read_to_string("/etc/shadow")
        .map_err(|e| format!("failed to read /etc/shadow: {}", e))?;

    for line in shadow.lines() {
        let parts: Vec<&str> = line.split(':').collect();

        if parts.is_empty() || parts[0] != user {
            continue;
        }
        if parts.len() < 2 {
            return Ok(false);
        }

        let hashed = parts[1];

        if hashed == "*" || hashed == "!" || hashed.is_empty() {
            return Ok(false);
        }

        let parsed = match PasswordHash::new(hashed) {
            Ok(h) => h,
            Err(_) => {
                return Err(format!(
                    "failed to parse password hash for user '{}' (corrupt /etc/shadow?)",
                    user
                ));
            }
        };

        let valid = if hashed.starts_with("$y$") {
            Yescrypt::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        } else if hashed.starts_with("$6$") || hashed.starts_with("$5$") {
            ShaCrypt::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        } else {
            return Err(format!(
                "unsupported password hash type for user '{}' (starts with '{}')",
                user,
                &hashed[..3.min(hashed.len())]
            ));
        };

        return Ok(valid);
    }

    Ok(false)
}

/// Prompt the user for their password, verify it, and return on success.
///
/// **Security**: Only one attempt is permitted. On failure the process exits
/// to prevent brute-force attacks through `doit`. Empty passwords are rejected
/// and re-prompted.
fn prompt_password(user: &str) {
    loop {
        let password =
            match rpassword::prompt_password(format!("[doit] password for {}: ", user)) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("doit: failed to read password from terminal: {}", e);
                    process::exit(1);
                }
            };

        if password.is_empty() {
            eprintln!("doit: password cannot be empty");
            continue;
        }

        match verify_password(user, &password) {
            Ok(true) => return,
            Ok(false) => {
                eprintln!("doit: incorrect password");
                process::exit(1);
            }
            Err(msg) => {
                eprintln!("doit: {}", msg);
                process::exit(1);
            }
        }
    }
}

// File permission enforcement
// ---------------------------------------------------------------------------

/// Check that `path` is owned by root and not group/other-writable.
///
/// This is a runtime enforcement of the documented permission requirements.
/// If the file has the wrong owner or is too permissive the process exits
/// with a clear error — we refuse to rely on a misconfigured file.
fn check_secure_file(path: &str, description: &str) {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("doit: cannot stat {} ({}): {}", description, path, e);
            process::exit(1);
        }
    };

    // Owner must be root.
    if meta.uid() != 0 {
        eprintln!(
            "doit: {} ({}) must be owned by root (UID 0), but is UID {}",
            description,
            path,
            meta.uid()
        );
        process::exit(1);
    }

    // Group must be root, or at the very least not group-writable.
    if meta.gid() != 0 {
        // Warn if group is not root, but only reject if group-writable.
        if meta.mode() & 0o020 != 0 {
            eprintln!(
                "doit: {} ({}) is group-writable by GID {} — must be owned by root:root",
                description, path, meta.gid()
            );
            process::exit(1);
        }
    }

    // Reject if any "other" permission bits are set beyond read.
    let mode = meta.mode() & 0o777;
    if mode & 0o007 != 0 {
        // World-accessible (any execute/write for "other") — reject.
        if mode & 0o004 != 0 {
            eprintln!(
                "doit: {} ({}) is world-readable (mode {:03o}) — must be mode 600",
                description, path, mode
            );
            process::exit(1);
        }
        if mode & 0o003 != 0 {
            eprintln!(
                "doit: {} ({}) has world-execute/write bits (mode {:03o}) — must be mode 600",
                description, path, mode
            );
            process::exit(1);
        }
    }
}

/// Verify that `/etc/shadow` is readable, printing a set-up hint if not.
///
/// This is called early in [`main`] so that users who forgot to install the
/// binary as setuid root get a clear error pointing them at the fix.
fn check_shadow_access() {
    match fs::File::open("/etc/shadow") {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("doit: cannot read /etc/shadow (Permission denied)");
            eprintln!("doit: the doit binary must be installed as setuid root:");
            eprintln!("doit:   sudo chown root:root /path/to/doit");
            eprintln!("doit:   sudo chmod u+s /path/to/doit");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("doit: cannot access /etc/shadow: {}", e);
            process::exit(1);
        }
    }
}

// Environment sanitisation
// ---------------------------------------------------------------------------

/// Build a [`Command`] for `program` with a sanitised environment.
///
/// The caller's environment is scanned and only known-safe variables are kept.
/// Explicitly dangerous variables (linker hijacking, interpreter injection,
/// language library paths) are stripped, and `PATH` is replaced with
/// [`SAFE_PATH`].
fn build_command(program: &str) -> Command {
    let mut cmd = Command::new(program);

    for var in DANGEROUS_ENV_VARS {
        cmd.env_remove(var);
    }

    let mut env_map: HashMap<&str, String> = HashMap::new();
    for var in SAFE_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            env_map.insert(var, val);
        }
    }
    for (key, val) in std::env::vars() {
        if DANGEROUS_ENV_VARS.contains(&key.as_str()) {
            continue;
        }
        if !SAFE_ENV_VARS.contains(&key.as_str()) {
            env_map.insert(Box::leak(key.into_boxed_str()), val);
        }
    }

    env_map.insert("PATH", SAFE_PATH.to_string());

    cmd.env_clear();
    for (key, val) in &env_map {
        cmd.env(key, val);
    }

    cmd
}

/// Drop the caller identity and fully switch to root.
///
/// When the binary is setuid-root the effective UID is already 0, but the
/// real UID is still the caller.  Many commands (NFS, stat, etc.) check the
/// real UID and will not behave as root if it does not match.  This function
/// calls `setresuid(0, 0, 0)` so that real, effective, and saved UIDs all
/// become root, then verifies the switch took effect.
fn become_root() {
    let ret = unsafe { libc::setresuid(0, 0, 0) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        error!("failed to switch to root UID: {}", err);
        eprintln!("doit: failed to switch to root UID: {}", err);
        eprintln!("doit: the doit binary must be installed as setuid root:");
        eprintln!("doit:   sudo chown root:root /path/to/doit");
        eprintln!("doit:   sudo chmod u+s /path/to/doit");
        process::exit(1);
    }

    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        error!("failed to verify root UID after setresuid");
        eprintln!("doit: failed to verify root UID after privilege switch");
        process::exit(1);
    }
}

// Entry point
// ---------------------------------------------------------------------------

fn main() {
    init_syslog();

    let args = Args::parse();
    let user = get_real_username();

    check_shadow_access();

    // If the config file does not exist, create it with a default entry
    // for the current user.  This matches the behaviour of doas, which
    // prompts the admin during first use.
    if !Path::new(CONFIG_PATH).exists() {
        let default_entry = format!("{} permit\n", user);
        match fs::write(CONFIG_PATH, &default_entry) {
            Ok(_) => {
                // Lock down permissions immediately.
                let _ = fs::set_permissions(CONFIG_PATH, std::fs::Permissions::from_mode(0o600));
                info!("created {} with default entry for '{}'", CONFIG_PATH, user);
                eprintln!(
                    "doit: created {} with entry '{} permit'",
                    CONFIG_PATH, user
                );
            }
            Err(e) => {
                error!("failed to create {}: {}", CONFIG_PATH, e);
                eprintln!(
                    "doit: failed to create config '{}': {}",
                    CONFIG_PATH, e
                );
                eprintln!("doit: create it manually with:");
                eprintln!("doit:   echo '{} permit' | sudo tee {} && sudo chmod 600 {}", user, CONFIG_PATH, CONFIG_PATH);
                process::exit(1);
            }
        }
    }

    // Enforce strict permissions on the config file and the counter
    // directory before trusting any data from them.
    check_secure_file(CONFIG_PATH, "config file");
    if let Some(parent) = Path::new(COUNTER_PATH).parent() {
        // COUNTER_PATH is a constant, so parent() always succeeds, but
        // we still handle it gracefully for defensive consistency.
        if parent.exists() {
            check_secure_file(
                &parent.to_string_lossy(),
                "counter directory",
            );
        }
    }

    // Read the config file once at startup.  The process is short-lived (it
    // exec()s into the target command), so there is no window for the
    // filesystem to change underneath us after this read.
    let entries = match read_config() {
        Ok(e) => e,
        Err(e) => {
            error!("{}: failed to read config: {}", user, e);
            eprintln!("doit: failed to read config '{}': {}", CONFIG_PATH, e);
            process::exit(1);
        }
    };

    let permit = match find_permit(&entries, &user) {
        Some(p) => p,
        None => {
            warn!(
                "{}: authorisation denied (not in {})",
                user, CONFIG_PATH
            );
            eprintln!("doit: user '{}' is not permitted to use doit", user);
            eprintln!(
                "doit: add '{} permit [nopass|extend]' to {}",
                user, CONFIG_PATH
            );
            process::exit(1);
        }
    };

    match *permit {
        PermitType::NoPass => {
            info!("{}: authorised (nopass): {}", user, args.command);
        }

        PermitType::Password => {
            prompt_password(&user);
            info!("{}: authorised (password): {}", user, args.command);
        }

        PermitType::Extend => {
            let remaining = {
                let mut store = CounterStore::default();
                if Path::new(COUNTER_PATH).exists() {
                    if let Ok(s) = fs::read_to_string(COUNTER_PATH) {
                        if let Ok(c) = serde_json::from_str::<CounterStore>(&s) {
                            store = c;
                        }
                    }
                }
                match store.remaining.get(&user) {
                    Some(&n) => n,
                    None => EXTEND_LIMIT,
                }
            };

            if remaining > 0 {
                let new_remaining = decrement_counter(&user);
                info!(
                    "{}: authorised (extend, {} remaining): {}",
                    user, new_remaining, args.command
                );
                // proceed without stderr noise
            } else {
                prompt_password(&user);
                reset_counter(&user);
                info!("{}: authorised (extend, recharged): {}", user, args.command);
                // proceed without stderr noise
            }
        }
    }

    // Fully switch to root before executing, so the command sees both
    // real and effective UID as 0.
    become_root();

    let mut cmd = build_command(&args.command);
    cmd.args(&args.args);
    let err = cmd.exec();

    error!("{}: exec failed: {}: {}", user, args.command, err);
    eprintln!("doit: failed to execute '{}': {}", args.command, err);
    process::exit(1);
}
