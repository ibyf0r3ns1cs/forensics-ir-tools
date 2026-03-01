#!/usr/bin/env python3
"""
=============================================================================
  Linux Persistence Mechanism Hunter
  Forensic Investigation & Threat Hunting Tool
  
  Author: Persistence Hunter
  Usage:  python3 linux_persistence_hunter.py [--root /mnt/vmdk]
  
  Supports offline forensics via --root flag, which prepends every path
  so /etc/crontab becomes /mnt/vmdk/etc/crontab, enabling analysis of
  mounted disk images, VMDKs, or chroot environments.
=============================================================================
"""

import os
import re
import sys
import glob
import stat
import argparse
import subprocess
import textwrap
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
#  ANSI COLOR HELPERS
# ─────────────────────────────────────────────────────────────

class C:
    """Terminal color codes for risk-tiered output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"   # Info / benign
    YELLOW  = "\033[93m"   # Suspicious
    RED     = "\033[91m"   # High risk
    CYAN    = "\033[96m"   # Section headers
    MAGENTA = "\033[95m"   # File content preview
    DIM     = "\033[2m"

def green(t):   return f"{C.GREEN}{t}{C.RESET}"
def yellow(t):  return f"{C.YELLOW}{t}{C.RESET}"
def red(t):     return f"{C.RED}{C.BOLD}{t}{C.RESET}"
def cyan(t):    return f"{C.CYAN}{C.BOLD}{t}{C.RESET}"
def magenta(t): return f"{C.MAGENTA}{t}{C.RESET}"
def dim(t):     return f"{C.DIM}{t}{C.RESET}"
def bold(t):    return f"{C.BOLD}{t}{C.RESET}"

# ─────────────────────────────────────────────────────────────
#  GLOBAL STATE — summary counters per category
# ─────────────────────────────────────────────────────────────

SUMMARY = defaultdict(lambda: {"info": 0, "suspicious": 0, "high_risk": 0})

def record(category, level):
    """Increment the summary counter for a given category and risk level."""
    SUMMARY[category][level] += 1

# ─────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def banner():
    print(cyan("""
╔══════════════════════════════════════════════════════════════════╗
║          Linux Persistence Mechanism Hunter v1.0                 ║
║          Forensic Investigation & Threat Hunting Tool            ║
╚══════════════════════════════════════════════════════════════════╝
"""))


def section(title):
    """Print a styled section header."""
    width = 68
    print(f"\n{cyan('═' * width)}")
    print(cyan(f"  ▶  {title}"))
    print(cyan('═' * width))


def read_file(path, max_bytes=8192):
    """
    Safely read a file. Returns (content_str, error_str).
    Limits reads to max_bytes to avoid flooding output with huge files.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        try:
            return raw.decode("utf-8", errors="replace"), None
        except Exception:
            return raw.decode("latin-1", errors="replace"), None
    except PermissionError:
        return None, "Permission denied"
    except FileNotFoundError:
        return None, "File not found"
    except Exception as e:
        return None, str(e)


def print_file_preview(path, content, max_lines=40):
    """Display a capped preview of file content with line numbers."""
    lines = content.splitlines()
    truncated = len(lines) > max_lines
    display = lines[:max_lines]
    print(magenta(f"  {'─'*60}"))
    print(magenta(f"  FILE: {path}"))
    print(magenta(f"  {'─'*60}"))
    for i, line in enumerate(display, 1):
        print(f"  {dim(str(i).rjust(4))} {line}")
    if truncated:
        print(dim(f"  ... [{len(lines) - max_lines} more lines truncated] ..."))
    print(magenta(f"  {'─'*60}"))


def resolve_path(root, *parts):
    """
    Join root + path parts, stripping any leading slash from parts
    so /etc/crontab becomes <root>/etc/crontab.
    """
    joined = os.path.join(*parts)
    # Make absolute paths relative so they join under root correctly
    if joined.startswith("/"):
        joined = joined[1:]
    return os.path.join(root, joined)


def glob_resolve(root, pattern):
    """Glob a pattern relative to root, returning resolved absolute paths."""
    if pattern.startswith("/"):
        pattern = pattern[1:]
    return glob.glob(os.path.join(root, pattern))


def get_home_dirs(root):
    """Return a list of home directory paths under root."""
    homes = []
    home_base = resolve_path(root, "home")
    if os.path.isdir(home_base):
        for entry in os.scandir(home_base):
            if entry.is_dir():
                homes.append(entry.path)
    root_home = resolve_path(root, "root")
    if os.path.isdir(root_home):
        homes.append(root_home)
    return homes


# ─────────────────────────────────────────────────────────────
#  PATTERN LIBRARIES  (compiled regexes for performance)
# ─────────────────────────────────────────────────────────────

# Patterns that indicate malicious shell activity
SHELL_MALICIOUS = [
    (re.compile(r'curl\s+.*\|\s*(ba)?sh',        re.I), "curl pipe to shell"),
    (re.compile(r'wget\s+.*\|\s*(ba)?sh',         re.I), "wget pipe to shell"),
    (re.compile(r'base64\s+-d.*\|\s*(ba)?sh',     re.I), "base64 decode pipe to shell"),
    (re.compile(r'nc\s+.*-e\s+/bin/(ba)?sh',      re.I), "netcat reverse shell (-e)"),
    (re.compile(r'ncat\s+.*-e\s+/bin/(ba)?sh',    re.I), "ncat reverse shell (-e)"),
    (re.compile(r'/dev/tcp/\d+\.\d+\.\d+\.\d+',  re.I), "/dev/tcp reverse shell"),
    (re.compile(r'bash\s+-i\s+>&\s*/dev/tcp',     re.I), "bash -i redirect reverse shell"),
    (re.compile(r'python.*socket.*connect',        re.I), "python socket connect"),
    (re.compile(r'python.*pty.*spawn',             re.I), "python PTY spawn"),
    (re.compile(r'mkfifo.*nc\s',                  re.I), "mkfifo + netcat"),
    (re.compile(r'rm\s+-rf\s+/',                  re.I), "destructive rm -rf /"),
    (re.compile(r'chmod\s+777',                   re.I), "chmod 777 (wide-open permissions)"),
    (re.compile(r'useradd|adduser',               re.I), "user creation"),
    (re.compile(r'echo\s+.*>>\s*/etc/passwd',     re.I), "passwd file modification"),
]

# Patterns that indicate suspicious (but not definitive) behaviour
SHELL_SUSPICIOUS = [
    (re.compile(r'base64',            re.I), "base64 encoding/decoding"),
    (re.compile(r'curl\s',            re.I), "curl outbound request"),
    (re.compile(r'wget\s',            re.I), "wget outbound request"),
    (re.compile(r'\bnc\b|\bncat\b',   re.I), "netcat usage"),
    (re.compile(r'PROMPT_COMMAND',    re.I), "PROMPT_COMMAND override"),
    (re.compile(r'LD_PRELOAD',        re.I), "LD_PRELOAD injection"),
    (re.compile(r'crontab\s+-e',      re.I), "inline crontab edit"),
    (re.compile(r'nohup\s',           re.I), "nohup (daemonization)"),
    (re.compile(r'disown\s',          re.I), "disown (daemonization)"),
]

# Patterns specific to Python malware
PYTHON_MALICIOUS = [
    (re.compile(r'\bexec\s*\(',       re.I), "exec() call"),
    (re.compile(r'\beval\s*\(',       re.I), "eval() call"),
    (re.compile(r'base64\.b64decode', re.I), "base64 decode"),
    (re.compile(r'__import__\s*\(',   re.I), "__import__ dynamic import"),
    (re.compile(r'socket\.connect\s*\('), "socket.connect"),
    (re.compile(r'subprocess\.(Popen|call|run)', re.I), "subprocess execution"),
    (re.compile(r'os\.system\s*\(',   re.I), "os.system call"),
    (re.compile(r'pty\.spawn',        re.I), "pty.spawn shell"),
    (re.compile(r'/dev/tcp',          re.I), "/dev/tcp in python"),
    (re.compile(r'connect_ex|connect\(.*\d+\.\d+\.\d+\.\d+'), "outbound connection IP"),
]

# PHP web shell indicators
PHP_MALICIOUS = [
    (re.compile(r'\beval\s*\(',                   re.I), "eval()"),
    (re.compile(r'base64_decode\s*\(',            re.I), "base64_decode()"),
    (re.compile(r'\bsystem\s*\(',                 re.I), "system()"),
    (re.compile(r'\bpassthru\s*\(',               re.I), "passthru()"),
    (re.compile(r'\bshell_exec\s*\(',             re.I), "shell_exec()"),
    (re.compile(r'\bpopen\s*\(',                  re.I), "popen()"),
    (re.compile(r'\bproc_open\s*\(',              re.I), "proc_open()"),
    (re.compile(r'\$_(REQUEST|POST|GET|COOKIE)',  re.I), "$_REQUEST/$_POST/$_GET in exec context"),
    (re.compile(r'assert\s*\(\s*\$_(REQUEST|POST|GET)', re.I), "assert with user input"),
    (re.compile(r'preg_replace.*\/e',             re.I), "preg_replace /e modifier (code exec)"),
]

# Environment variable abuse patterns
ENV_PATTERNS = [
    (re.compile(r'^LD_PRELOAD\s*=',   re.M), "LD_PRELOAD set"),
    (re.compile(r'^LD_LIBRARY_PATH\s*=', re.M), "LD_LIBRARY_PATH set"),
    (re.compile(r'PROMPT_COMMAND\s*=', re.M), "PROMPT_COMMAND override"),
    (re.compile(r'^PATH\s*=.*(?<!/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)', re.M), "non-standard PATH"),
]


def scan_content_for_patterns(content, pattern_list):
    """
    Scan content string against a list of (compiled_regex, description) tuples.
    Returns a list of matched descriptions.
    """
    hits = []
    for pattern, desc in pattern_list:
        if pattern.search(content):
            hits.append(desc)
    return hits


def risk_label(hits_malicious, hits_suspicious):
    """Determine risk level string and color function."""
    if hits_malicious:
        return "HIGH RISK", red
    if hits_suspicious:
        return "SUSPICIOUS", yellow
    return "INFO", green


# ─────────────────────────────────────────────────────────────
#  MODULE 1 — CRON JOBS
# ─────────────────────────────────────────────────────────────

def check_cron(root):
    """
    Parse crontab files and directories. For each scheduled command,
    resolve the binary/script path and read its content to detect
    malicious payloads being run on a schedule.
    """
    section("MODULE 1 — Cron Jobs")
    category = "Cron Jobs"

    cron_files = []

    # System-wide crontab
    etc_crontab = resolve_path(root, "/etc/crontab")
    if os.path.isfile(etc_crontab):
        cron_files.append(etc_crontab)

    # Drop-in cron.d snippets (e.g., installed by packages)
    cron_files += glob_resolve(root, "/etc/cron.d/*")

    # Per-user crontabs stored by crond
    cron_files += glob_resolve(root, "/var/spool/cron/crontabs/*")
    cron_files += glob_resolve(root, "/var/spool/cron/*")

    if not cron_files:
        print(dim("  No crontab files found."))
        return

    # Regex to extract the command field from a cron line (skip comments/env)
    cron_line_re = re.compile(
        r'^\s*(?:[*\d,\-/]+\s+){5}(?:\S+\s+)?(.+)$'
    )

    for cfile in cron_files:
        content, err = read_file(cfile)
        if err:
            print(yellow(f"  [WARN] Cannot read {cfile}: {err}"))
            continue

        print(f"\n{bold('  ► Crontab:')} {cfile}")
        record(category, "info")

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Skip variable assignments like MAILTO=root
            if re.match(r'^\s*\w+=', line):
                continue

            m = cron_line_re.match(line)
            if not m:
                continue

            cmd = m.group(1).strip()
            print(f"\n    {green('SCHEDULE:')} {line}")

            # Attempt to extract the first token as the executed binary/script
            # Strip sudo, env, sh -c, bash -c wrappers to get real path
            cmd_clean = re.sub(r'^(sudo|env|/usr/bin/env)\s+', '', cmd)
            # Handle sh -c "..." or bash -c "..."
            sh_c = re.match(r'(?:ba)?sh\s+-c\s+["\']?(.+)["\']?', cmd_clean)
            if sh_c:
                inner = sh_c.group(1)
                # Check the inner command for inline malicious patterns
                hits_m = scan_content_for_patterns(inner, SHELL_MALICIOUS)
                hits_s = scan_content_for_patterns(inner, SHELL_SUSPICIOUS)
                level, color = risk_label(hits_m, hits_s)
                indicators = hits_m + hits_s
                if indicators:
                    print(color(f"    [{level}] Inline shell command indicators: {', '.join(indicators)}"))
                    print(f"    CMD: {inner}")
                    record(category, "high_risk" if hits_m else "suspicious")
                continue

            # Extract first word as potential script path
            tokens = cmd_clean.split()
            script_path_raw = tokens[0] if tokens else ""

            # Resolve against root filesystem
            if script_path_raw.startswith("/"):
                script_full = resolve_path(root, script_path_raw)
            else:
                # Relative path — not resolvable in offline mode, note it
                print(dim(f"    [INFO] Relative command, cannot resolve offline: {cmd}"))
                continue

            if os.path.isfile(script_full):
                script_content, serr = read_file(script_full)
                if serr:
                    print(yellow(f"    [WARN] Cannot read script {script_full}: {serr}"))
                    continue

                hits_m = scan_content_for_patterns(script_content, SHELL_MALICIOUS)
                hits_s = scan_content_for_patterns(script_content, SHELL_SUSPICIOUS)
                hits_p = scan_content_for_patterns(script_content, PYTHON_MALICIOUS) \
                         if script_full.endswith(".py") else []
                all_hits = hits_m + hits_p
                level, color = risk_label(all_hits, hits_s)
                indicators = all_hits + hits_s

                if indicators:
                    print(color(f"    [{level}] Script: {script_path_raw}"))
                    print(color(f"    Indicators: {', '.join(indicators)}"))
                    print_file_preview(script_full, script_content)
                    record(category, "high_risk" if all_hits else "suspicious")
                else:
                    print(green(f"    [OK] Script appears clean: {script_path_raw}"))
                    record(category, "info")
            else:
                print(dim(f"    [INFO] Binary/script not found at: {script_full} (may be system binary)"))


# ─────────────────────────────────────────────────────────────
#  MODULE 2 — SYSTEMD SERVICES & TIMERS
# ─────────────────────────────────────────────────────────────

def check_systemd(root):
    """
    Enumerate all .service and .timer unit files. Extract ExecStart directives
    (the actual binary or script being launched) and analyze their content.
    Attackers often drop malicious systemd units for persistent execution.
    """
    section("MODULE 2 — Systemd Services & Timers")
    category = "Systemd"

    unit_dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]
    # Also check per-user units in home directories
    for home in get_home_dirs(root):
        unit_dirs.append(os.path.join(home.replace(root, ""), ".config/systemd/user"))

    exec_re = re.compile(r'^\s*ExecStart\s*=\s*(.+)', re.M)
    unit_files = []

    for udir in unit_dirs:
        unit_files += glob_resolve(root, f"{udir}/*.service")
        unit_files += glob_resolve(root, f"{udir}/*.timer")

    if not unit_files:
        print(dim("  No systemd unit files found."))
        return

    for ufile in unit_files:
        content, err = read_file(ufile)
        if err:
            continue

        matches = exec_re.findall(content)
        if not matches:
            continue

        print(f"\n{bold('  ► Unit:')} {ufile}")
        record(category, "info")

        for exec_val in matches:
            exec_val = exec_val.strip()
            print(f"    {green('ExecStart:')} {exec_val}")

            # Strip systemd specifiers like @, -, : prefixes
            exec_clean = re.sub(r'^[-@+!:]+', '', exec_val).strip()
            # Get just the binary (before any args)
            bin_path = exec_clean.split()[0] if exec_clean else ""

            if not bin_path.startswith("/"):
                print(dim(f"    [INFO] Relative/env path, skipping: {bin_path}"))
                continue

            full_path = resolve_path(root, bin_path)
            if not os.path.isfile(full_path):
                print(dim(f"    [INFO] Binary not found in image: {bin_path}"))
                continue

            script_content, serr = read_file(full_path)
            if serr:
                print(yellow(f"    [WARN] {serr}: {full_path}"))
                continue

            hits_m = scan_content_for_patterns(script_content, SHELL_MALICIOUS)
            hits_s = scan_content_for_patterns(script_content, SHELL_SUSPICIOUS)
            hits_p = scan_content_for_patterns(script_content, PYTHON_MALICIOUS)
            all_hits = hits_m + hits_p
            level, color = risk_label(all_hits, hits_s)
            indicators = all_hits + hits_s

            if indicators:
                print(color(f"    [{level}] {bin_path}"))
                print(color(f"    Indicators: {', '.join(indicators)}"))
                print_file_preview(full_path, script_content)
                record(category, "high_risk" if all_hits else "suspicious")
            else:
                print(green(f"    [OK] ExecStart binary appears clean: {bin_path}"))


# ─────────────────────────────────────────────────────────────
#  MODULE 3 — SHELL STARTUP FILES
# ─────────────────────────────────────────────────────────────

def check_shell_startup(root):
    """
    Shell startup files execute automatically on login or shell launch.
    Attackers abuse them to establish persistence for specific users or system-wide.
    We scan for outbound connections, encoded payloads, and reverse shell patterns.
    """
    section("MODULE 3 — Shell Startup Files")
    category = "Shell Startup"

    startup_files = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zshrc",
        "/etc/environment",
    ]
    startup_files += glob_resolve(root, "/etc/profile.d/*.sh")

    for home in get_home_dirs(root):
        for rc in [".bashrc", ".bash_profile", ".bash_login", ".profile",
                   ".zshrc", ".zprofile", ".zshenv", ".xprofile"]:
            startup_files.append(os.path.join(home, rc))

    for fpath in startup_files:
        # fpath may be full (already rooted) or a system path to resolve
        if fpath.startswith(root):
            full = fpath
        else:
            full = resolve_path(root, fpath)

        if not os.path.isfile(full):
            continue

        content, err = read_file(full)
        if err:
            print(yellow(f"  [WARN] {full}: {err}"))
            continue

        hits_m = scan_content_for_patterns(content, SHELL_MALICIOUS)
        hits_s = scan_content_for_patterns(content, SHELL_SUSPICIOUS)
        hits_env = scan_content_for_patterns(content, ENV_PATTERNS)
        all_hits = hits_m
        level, color = risk_label(all_hits, hits_s + hits_env)
        indicators = hits_m + hits_s + hits_env

        if indicators:
            print(color(f"\n  [{level}] {full}"))
            print(color(f"  Indicators: {', '.join(indicators)}"))
            print_file_preview(full, content)
            record(category, "high_risk" if hits_m else "suspicious")
        else:
            print(green(f"  [OK] {full}"))
            record(category, "info")


# ─────────────────────────────────────────────────────────────
#  MODULE 4 — ENVIRONMENT VARIABLE ABUSE
# ─────────────────────────────────────────────────────────────

def check_env_abuse(root):
    """
    Environment variables like LD_PRELOAD can force-load attacker libraries
    into every process. PROMPT_COMMAND runs arbitrary code before each prompt.
    PATH hijacking causes legitimate binary names to execute malicious copies.
    """
    section("MODULE 4 — Environment Variable Abuse")
    category = "Env Var Abuse"

    env_files = [
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/security/pam_env.conf",
    ]
    env_files += glob_resolve(root, "/etc/profile.d/*.sh")
    for home in get_home_dirs(root):
        for f in [".bashrc", ".bash_profile", ".profile", ".zshrc", ".pam_environment"]:
            env_files.append(os.path.join(home, f))

    checked = set()
    for fpath in env_files:
        full = fpath if fpath.startswith(root) else resolve_path(root, fpath)
        if full in checked or not os.path.isfile(full):
            continue
        checked.add(full)

        content, err = read_file(full)
        if err:
            continue

        found = []

        # Check LD_PRELOAD
        for m in re.finditer(r'LD_PRELOAD\s*=\s*(\S+)', content):
            lib = m.group(1)
            found.append(("HIGH RISK", red, f"LD_PRELOAD={lib}"))
            record(category, "high_risk")

        # Check LD_LIBRARY_PATH
        for m in re.finditer(r'LD_LIBRARY_PATH\s*=\s*(\S+)', content):
            val = m.group(1)
            # Flag if it includes /tmp or unusual dirs
            if any(x in val for x in ["/tmp", "/dev", "/var/tmp"]):
                found.append(("HIGH RISK", red, f"LD_LIBRARY_PATH includes suspicious dir: {val}"))
                record(category, "high_risk")
            else:
                found.append(("SUSPICIOUS", yellow, f"LD_LIBRARY_PATH={val}"))
                record(category, "suspicious")

        # Check PROMPT_COMMAND
        for m in re.finditer(r'PROMPT_COMMAND\s*=\s*(.+)', content):
            val = m.group(1).strip()
            found.append(("SUSPICIOUS", yellow, f"PROMPT_COMMAND={val}"))
            record(category, "suspicious")

        # Check PATH for prepended unusual directories
        for m in re.finditer(r'(?:export\s+)?PATH\s*=\s*(.+)', content):
            val = m.group(1).strip().strip('"\'')
            parts = val.replace('$PATH', '').split(':')
            for p in parts:
                p = p.strip()
                if p and any(p.startswith(x) for x in ['/tmp', '/dev/shm', '/var/tmp', '/home']):
                    found.append(("HIGH RISK", red, f"PATH hijack — unusual dir prepended: {p}"))
                    record(category, "high_risk")

        if found:
            print(f"\n  {bold('File:')} {full}")
            for level, color, msg in found:
                print(color(f"  [{level}] {msg}"))
        else:
            print(green(f"  [OK] {full}"))
            record(category, "info")

    # Also check /etc/ld.so.preload directly (covered more in module 13 but worth flagging here)
    ld_preload = resolve_path(root, "/etc/ld.so.preload")
    if os.path.isfile(ld_preload):
        content, _ = read_file(ld_preload)
        if content and content.strip():
            print(red(f"\n  [HIGH RISK] /etc/ld.so.preload exists and is non-empty!"))
            print(red(f"  Content: {content.strip()}"))
            record(category, "high_risk")


# ─────────────────────────────────────────────────────────────
#  MODULE 5 — SUID/SGID BINARIES
# ─────────────────────────────────────────────────────────────

def check_suid_sgid(root):
    """
    SUID/SGID binaries run with elevated privileges. Attackers plant custom
    SUID binaries (often disguised as legitimate tools) to escalate privileges
    or maintain root-level persistence after exploitation.
    We walk the filesystem and cross-reference findings with dpkg/rpm databases.
    """
    section("MODULE 5 — SUID/SGID Binaries")
    category = "SUID/SGID"

    # Known-good SUID binaries commonly found on Debian/Ubuntu/RHEL systems
    KNOWN_SUID = {
        "/usr/bin/sudo", "/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/chfn", "/usr/bin/chsh",
        "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
        "/usr/sbin/pppd", "/usr/bin/mount", "/bin/mount", "/bin/umount",
        "/usr/bin/umount", "/usr/bin/at", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/bin/crontab", "/sbin/unix_chkpwd",
        "/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/bin/write",
        "/usr/bin/wall", "/usr/bin/screen",
    }

    print(dim("  Walking filesystem for SUID/SGID bits (this may take a moment)..."))

    skip_dirs = {"proc", "sys", "dev", "run"}
    suid_found = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune virtual/pseudo filesystems to avoid hangs
        dirnames[:] = [d for d in dirnames
                       if not any(dirpath.endswith(f"/{s}") or d == s
                                  for s in skip_dirs)]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                st = os.lstat(fpath)
                mode = st.st_mode
                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)
                if is_suid or is_sgid:
                    # Get the path relative to root for comparison with known list
                    rel_path = "/" + os.path.relpath(fpath, root)
                    suid_found.append((fpath, rel_path, is_suid, is_sgid, mode))
            except (PermissionError, OSError):
                continue

    if not suid_found:
        print(green("  No SUID/SGID binaries found."))
        return

    # Build set of dpkg-tracked files if dpkg database exists in image
    dpkg_files = set()
    dpkg_info = resolve_path(root, "/var/lib/dpkg/info")
    if os.path.isdir(dpkg_info):
        for lst in glob.glob(os.path.join(dpkg_info, "*.list")):
            try:
                with open(lst) as f:
                    for line in f:
                        dpkg_files.add(line.strip())
            except Exception:
                pass

    # Build set from RPM if available
    rpm_files = set()
    rpm_db = resolve_path(root, "/var/lib/rpm")
    # RPM parsing requires external tools; note it can't be done offline easily

    for fpath, rel_path, is_suid, is_sgid, mode in suid_found:
        kind = []
        if is_suid: kind.append("SUID")
        if is_sgid: kind.append("SGID")
        kind_str = "+".join(kind)
        oct_mode = oct(mode)[-4:]

        # Determine if this binary is known/expected
        is_known = rel_path in KNOWN_SUID
        is_dpkg_tracked = rel_path in dpkg_files if dpkg_files else None

        if not is_known and (is_dpkg_tracked is False or is_dpkg_tracked is None):
            print(red(f"  [HIGH RISK] {kind_str} — UNKNOWN/UNTRACKED: {fpath} (mode {oct_mode})"))
            record(category, "high_risk")
        elif not is_known:
            print(yellow(f"  [SUSPICIOUS] {kind_str} — Not in known list: {fpath} (mode {oct_mode})"))
            record(category, "suspicious")
        else:
            print(green(f"  [OK] {kind_str} — {fpath} (mode {oct_mode})"))
            record(category, "info")


# ─────────────────────────────────────────────────────────────
#  MODULE 6 — SUSPICIOUS PYTHON FILES
# ─────────────────────────────────────────────────────────────

def check_suspicious_python(root):
    """
    Malicious Python scripts are commonly dropped in world-writable directories
    (/tmp, /dev/shm) or disguised in web roots. We scan for dangerous function
    calls, socket connections, and encoded payloads that indicate a backdoor
    or post-exploitation tool.
    """
    section("MODULE 6 — Suspicious Python Files")
    category = "Python Malware"

    search_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    for home in get_home_dirs(root):
        search_dirs.append(home.replace(root, "/").replace("//", "/"))
    # Web roots
    search_dirs += ["/var/www", "/srv", "/usr/share/nginx/html",
                    "/usr/share/apache2", "/opt"]

    py_files = []
    for d in search_dirs:
        py_files += glob_resolve(root, f"{d}/**/*.py")
        # Also catch files without .py extension that start with a python shebang
        for dirpath, _, filenames in os.walk(resolve_path(root, d) if not resolve_path(root, d).startswith(root) else resolve_path(root, d)):
            for fname in filenames:
                if not fname.endswith(".py"):
                    fp = os.path.join(dirpath, fname)
                    try:
                        with open(fp, "rb") as fh:
                            first = fh.read(30)
                        if b"python" in first:
                            py_files.append(fp)
                    except Exception:
                        pass

    py_files = list(set(py_files))

    if not py_files:
        print(dim("  No Python files found in monitored directories."))
        return

    for pyf in py_files:
        content, err = read_file(pyf)
        if err:
            continue

        hits_m = scan_content_for_patterns(content, PYTHON_MALICIOUS)
        hits_s = scan_content_for_patterns(content, SHELL_SUSPICIOUS)

        if hits_m:
            level, color = "HIGH RISK", red
            record(category, "high_risk")
        elif hits_s:
            level, color = "SUSPICIOUS", yellow
            record(category, "suspicious")
        else:
            continue  # Skip clean files to reduce noise

        indicators = hits_m + hits_s
        print(color(f"\n  [{level}] {pyf}"))
        print(color(f"  Indicators: {', '.join(indicators)}"))
        print_file_preview(pyf, content)


# ─────────────────────────────────────────────────────────────
#  MODULE 7 — MALICIOUS BASH SCRIPTS
# ─────────────────────────────────────────────────────────────

def check_malicious_bash(root):
    """
    Malicious shell scripts are often planted in world-writable directories,
    disguised with innocuous names, or executed by cron/systemd.
    Classic indicators: piping curl/wget into bash, netcat with -e flag,
    /dev/tcp redirects for in-band reverse shells, base64-decoded execution.
    """
    section("MODULE 7 — Malicious Bash Scripts")
    category = "Bash Malware"

    # Directories outside typical package manager control
    unusual_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/var/www"]
    for home in get_home_dirs(root):
        unusual_dirs.append(home.replace(root, "").lstrip("/"))

    sh_files = []
    for d in unusual_dirs:
        sh_files += glob_resolve(root, f"{d}/**/*.sh")

    # Also find files with bash/sh shebangs that don't have .sh extension
    for d in unusual_dirs:
        full_d = resolve_path(root, d)
        if not os.path.isdir(full_d):
            continue
        for dirpath, _, filenames in os.walk(full_d):
            for fname in filenames:
                if fname.endswith(".sh"):
                    continue
                fp = os.path.join(dirpath, fname)
                try:
                    with open(fp, "rb") as fh:
                        first = fh.read(50)
                    if b"#!/bin/bash" in first or b"#!/bin/sh" in first or b"#!/usr/bin/env bash" in first:
                        sh_files.append(fp)
                except Exception:
                    pass

    sh_files = list(set(sh_files))

    if not sh_files:
        print(dim("  No shell scripts found in monitored directories."))
        return

    for shf in sh_files:
        content, err = read_file(shf)
        if err:
            continue

        hits_m = scan_content_for_patterns(content, SHELL_MALICIOUS)
        hits_s = scan_content_for_patterns(content, SHELL_SUSPICIOUS)

        if hits_m:
            level, color = "HIGH RISK", red
            record(category, "high_risk")
        elif hits_s:
            level, color = "SUSPICIOUS", yellow
            record(category, "suspicious")
        else:
            continue

        indicators = hits_m + hits_s
        print(color(f"\n  [{level}] {shf}"))
        print(color(f"  Indicators: {', '.join(indicators)}"))
        print_file_preview(shf, content)


# ─────────────────────────────────────────────────────────────
#  MODULE 8 — WEB SHELLS (PHP)
# ─────────────────────────────────────────────────────────────

def check_web_shells(root):
    """
    Web shells allow remote code execution via HTTP, giving attackers a
    persistent foothold through the web server. PHP web shells typically
    pass user-supplied input (via $_GET, $_POST, $_REQUEST) directly to
    execution functions like eval(), system(), or shell_exec().
    """
    section("MODULE 8 — Web Shells (PHP)")
    category = "Web Shells"

    web_roots = [
        "/var/www",
        "/srv/http",
        "/srv/www",
        "/usr/share/nginx/html",
        "/usr/share/apache2",
        "/var/apache2",
        "/opt/lampp/htdocs",
        "/home/*/public_html",
        "/home/*/www",
    ]

    php_files = []
    for wr in web_roots:
        php_files += glob_resolve(root, f"{wr}/**/*.php")
        php_files += glob_resolve(root, f"{wr}/**/*.php5")
        php_files += glob_resolve(root, f"{wr}/**/*.phtml")

    php_files = list(set(php_files))

    if not php_files:
        print(dim("  No PHP files found in web roots."))
        return

    for phpf in php_files:
        content, err = read_file(phpf)
        if err:
            continue

        hits_m = scan_content_for_patterns(content, PHP_MALICIOUS)
        if not hits_m:
            continue  # Only report suspicious/malicious PHP

        # Additional check: user input feeding into exec functions
        # Look for $_GET/$_POST/$_REQUEST near system/eval/shell_exec
        user_input_exec = re.search(
            r'(system|exec|eval|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
            content, re.I
        )

        if user_input_exec or len(hits_m) >= 2:
            level, color = "HIGH RISK", red
            record(category, "high_risk")
        else:
            level, color = "SUSPICIOUS", yellow
            record(category, "suspicious")

        print(color(f"\n  [{level}] {phpf}"))
        print(color(f"  Indicators: {', '.join(hits_m)}"))
        if user_input_exec:
            print(red(f"  ⚠ User input directly passed to exec function!"))
        print_file_preview(phpf, content)


# ─────────────────────────────────────────────────────────────
#  MODULE 9 — SSH PERSISTENCE
# ─────────────────────────────────────────────────────────────

def check_ssh_persistence(root):
    """
    SSH is a primary attack vector for persistent access.
    Attackers add unauthorized keys to authorized_keys, modify sshd_config to
    enable root login, or redirect AuthorizedKeysFile to attacker-controlled paths.
    We flag unexpected configuration and enumerate all authorized public keys.
    """
    section("MODULE 9 — SSH Persistence")
    category = "SSH Persistence"

    # Check sshd_config for dangerous settings
    sshd_conf = resolve_path(root, "/etc/ssh/sshd_config")
    if os.path.isfile(sshd_conf):
        content, err = read_file(sshd_conf)
        if content:
            print(f"\n  {bold('sshd_config analysis:')} {sshd_conf}")

            # PermitRootLogin
            m = re.search(r'^\s*PermitRootLogin\s+(\S+)', content, re.M | re.I)
            if m:
                val = m.group(1).lower()
                if val in ("yes", "without-password", "prohibit-password"):
                    print(yellow(f"  [SUSPICIOUS] PermitRootLogin={val} — root SSH login enabled"))
                    record(category, "suspicious")
                else:
                    print(green(f"  [OK] PermitRootLogin={val}"))
                    record(category, "info")

            # AuthorizedKeysFile pointing to unusual location
            m = re.search(r'^\s*AuthorizedKeysFile\s+(.+)', content, re.M | re.I)
            if m:
                val = m.group(1).strip()
                standard = [".ssh/authorized_keys", "%h/.ssh/authorized_keys",
                            "/etc/ssh/authorized_keys/%u"]
                if not any(s in val for s in standard):
                    print(red(f"  [HIGH RISK] AuthorizedKeysFile={val} — unusual path!"))
                    record(category, "high_risk")
                else:
                    print(green(f"  [OK] AuthorizedKeysFile={val}"))

            # PasswordAuthentication (should be no in hardened configs)
            m = re.search(r'^\s*PasswordAuthentication\s+(\S+)', content, re.M | re.I)
            if m and m.group(1).lower() == "yes":
                print(yellow(f"  [SUSPICIOUS] PasswordAuthentication=yes — brute-force risk"))
                record(category, "suspicious")

    # Enumerate authorized_keys across all users
    auth_key_paths = []
    for home in get_home_dirs(root):
        auth_key_paths.append(os.path.join(home, ".ssh", "authorized_keys"))
    auth_key_paths.append(resolve_path(root, "/etc/ssh/authorized_keys"))

    for akp in auth_key_paths:
        if not os.path.isfile(akp):
            continue
        content, err = read_file(akp)
        if err or not content:
            continue

        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        if not lines:
            continue

        print(f"\n  {bold('authorized_keys:')} {akp}")
        for key_line in lines:
            # Parse key type and comment
            parts = key_line.split()
            key_type = parts[0] if parts else "?"
            comment = parts[2] if len(parts) > 2 else "(no comment)"

            # Flag unusual key types or suspicious comments
            if key_type not in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256",
                                 "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-dss"):
                print(red(f"  [HIGH RISK] Unusual key type: {key_type} — {comment}"))
                record(category, "high_risk")
            elif any(c in comment.lower() for c in ["backdoor", "attacker", "hack", "pwned"]):
                print(red(f"  [HIGH RISK] Suspicious key comment: {comment}"))
                record(category, "high_risk")
            else:
                print(yellow(f"  [REVIEW] Key found: type={key_type}, comment={comment}"))
                record(category, "suspicious")

            # Check for command= restrictions (could be used to lock down or hide)
            if key_line.startswith("command="):
                cmd = re.match(r'command="([^"]+)"', key_line)
                if cmd:
                    print(yellow(f"  [SUSPICIOUS] Forced command in key: {cmd.group(1)}"))


# ─────────────────────────────────────────────────────────────
#  MODULE 10 — RC SCRIPTS & INIT FILES
# ─────────────────────────────────────────────────────────────

def check_rc_init(root):
    """
    Legacy SysV init scripts and rc.local are still used on many systems.
    rc.local runs as root at boot — a common target for persistence.
    init.d scripts that don't match standard package naming deserve scrutiny.
    """
    section("MODULE 10 — RC Scripts & Init Files")
    category = "RC/Init"

    rc_files = ["/etc/rc.local", "/etc/inittab", "/etc/rc.d/rc.local"]
    rc_files += glob_resolve(root, "/etc/init.d/*")
    rc_files += glob_resolve(root, "/etc/rc.d/*")

    for fpath in rc_files:
        full = fpath if fpath.startswith(root) else resolve_path(root, fpath)
        if not os.path.isfile(full):
            continue

        content, err = read_file(full)
        if err:
            print(yellow(f"  [WARN] {full}: {err}"))
            continue

        hits_m = scan_content_for_patterns(content, SHELL_MALICIOUS)
        hits_s = scan_content_for_patterns(content, SHELL_SUSPICIOUS)
        indicators = hits_m + hits_s

        if hits_m:
            print(red(f"\n  [HIGH RISK] {full}"))
            print(red(f"  Indicators: {', '.join(hits_m)}"))
            print_file_preview(full, content)
            record(category, "high_risk")
        elif hits_s:
            print(yellow(f"\n  [SUSPICIOUS] {full}"))
            print(yellow(f"  Indicators: {', '.join(hits_s)}"))
            print_file_preview(full, content)
            record(category, "suspicious")
        else:
            print(green(f"  [OK] {full}"))
            record(category, "info")


# ─────────────────────────────────────────────────────────────
#  MODULE 11 — AT JOBS
# ─────────────────────────────────────────────────────────────

def check_at_jobs(root):
    """
    The 'at' daemon schedules one-time jobs. Attackers use 'at' to schedule
    deferred execution of payloads, sometimes to survive a reboot or execute
    after a delay to complicate incident timelines.
    """
    section("MODULE 11 — At Jobs")
    category = "At Jobs"

    at_spools = ["/var/spool/at", "/var/spool/atjobs"]
    at_files = []

    for spool in at_spools:
        full_spool = resolve_path(root, spool)
        if os.path.isdir(full_spool):
            for entry in os.scandir(full_spool):
                if entry.is_file() and not entry.name.startswith("."):
                    at_files.append(entry.path)

    if not at_files:
        print(dim("  No at jobs found."))
        return

    for atf in at_files:
        content, err = read_file(atf)
        if err:
            print(yellow(f"  [WARN] {atf}: {err}"))
            continue

        hits_m = scan_content_for_patterns(content, SHELL_MALICIOUS)
        hits_s = scan_content_for_patterns(content, SHELL_SUSPICIOUS)
        indicators = hits_m + hits_s

        print(f"\n  {bold('At job:')} {atf}")
        if hits_m:
            print(red(f"  [HIGH RISK] Indicators: {', '.join(hits_m)}"))
            print_file_preview(atf, content)
            record(category, "high_risk")
        elif hits_s:
            print(yellow(f"  [SUSPICIOUS] Indicators: {', '.join(hits_s)}"))
            print_file_preview(atf, content)
            record(category, "suspicious")
        else:
            # Still show content of at jobs — any at job is worth reviewing
            print(yellow(f"  [REVIEW] At job scheduled (review manually)"))
            print_file_preview(atf, content)
            record(category, "suspicious")


# ─────────────────────────────────────────────────────────────
#  MODULE 12 — KERNEL MODULES
# ─────────────────────────────────────────────────────────────

def check_kernel_modules(root):
    """
    Rootkits often operate as loadable kernel modules (LKMs) to hide processes,
    files, and network connections. We list modules present in the image and
    cross-reference with those installed via the official kernel packages.
    Modules in non-standard locations or with suspicious names warrant investigation.
    """
    section("MODULE 12 — Kernel Modules")
    category = "Kernel Modules"

    # In offline mode, we can't run lsmod. Instead, scan the module directories.
    # Look for .ko files in non-standard locations.
    official_mod_dirs = glob_resolve(root, "/lib/modules/*/kernel/**/*.ko")
    official_mods = set(os.path.basename(f) for f in official_mod_dirs)

    print(f"  {green(str(len(official_mods)))} official kernel module files found in /lib/modules/")

    # Scan for .ko files outside of /lib/modules/ — these are suspicious
    suspicious_ko = []
    skip_dirs = {"proc", "sys", "lib/modules"}
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip official module directories
        rel = os.path.relpath(dirpath, root)
        if any(rel.startswith(s) for s in skip_dirs):
            dirnames.clear()
            continue
        dirnames[:] = [d for d in dirnames if d not in {"proc", "sys", "dev", "run"}]

        for fname in filenames:
            if fname.endswith(".ko"):
                suspicious_ko.append(os.path.join(dirpath, fname))

    if suspicious_ko:
        for kof in suspicious_ko:
            print(red(f"\n  [HIGH RISK] Kernel module outside /lib/modules/: {kof}"))
            record(category, "high_risk")
    else:
        print(green("  [OK] No kernel modules found outside standard directories."))
        record(category, "info")

    # Also check /etc/modules and /etc/modules-load.d/ for auto-loaded modules
    mod_load_files = ["/etc/modules"]
    mod_load_files += glob_resolve(root, "/etc/modules-load.d/*.conf")
    mod_load_files += glob_resolve(root, "/usr/lib/modules-load.d/*.conf")

    for mlf in mod_load_files:
        full = mlf if mlf.startswith(root) else resolve_path(root, mlf)
        if not os.path.isfile(full):
            continue
        content, _ = read_file(full)
        if content and content.strip():
            print(f"\n  {bold('Module auto-load config:')} {full}")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    mod_name = line + ".ko"
                    if mod_name not in official_mods:
                        print(yellow(f"  [SUSPICIOUS] Auto-loaded module not in official list: {line}"))
                        record(category, "suspicious")
                    else:
                        print(green(f"  [OK] {line}"))


# ─────────────────────────────────────────────────────────────
#  MODULE 13 — DYNAMIC LINKER HIJACKING
# ─────────────────────────────────────────────────────────────

def check_ld_hijacking(root):
    """
    /etc/ld.so.preload forces all processes to load specified shared libraries
    before any other library. A non-empty ld.so.preload on a system that hasn't
    explicitly configured it is a strong rootkit indicator.
    We also scan for .so files in world-writable or temporary directories.
    """
    section("MODULE 13 — Dynamic Linker Hijacking")
    category = "Linker Hijack"

    # Primary check: /etc/ld.so.preload
    ld_preload_path = resolve_path(root, "/etc/ld.so.preload")
    if os.path.isfile(ld_preload_path):
        content, err = read_file(ld_preload_path)
        if content and content.strip():
            print(red(f"\n  [HIGH RISK] /etc/ld.so.preload is non-empty!"))
            print(red(f"  This is a classic rootkit indicator."))
            for line in content.splitlines():
                if line.strip():
                    lib_path = resolve_path(root, line.strip())
                    exists = os.path.isfile(lib_path)
                    status = "EXISTS" if exists else "MISSING (may be in-memory)"
                    print(red(f"  Library: {line.strip()} [{status}]"))
            record(category, "high_risk")
        else:
            print(green("  [OK] /etc/ld.so.preload is empty."))
            record(category, "info")
    else:
        print(green("  [OK] /etc/ld.so.preload does not exist."))
        record(category, "info")

    # Check for .so files in suspicious directories (tmp, shm, home)
    suspicious_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    for home in get_home_dirs(root):
        suspicious_dirs.append(home.replace(root, "").lstrip("/"))

    so_files = []
    for d in suspicious_dirs:
        so_files += glob_resolve(root, f"{d}/**/*.so")
        so_files += glob_resolve(root, f"{d}/**/*.so.*")

    if so_files:
        print(f"\n  {yellow('Shared libraries found in suspicious directories:')}")
        for sof in so_files:
            print(red(f"  [HIGH RISK] Rogue .so file: {sof}"))
            record(category, "high_risk")
    else:
        print(green("  [OK] No rogue .so files found in world-writable directories."))

    # Check ld.so.conf and ld.so.conf.d for unusual library paths
    ld_conf = resolve_path(root, "/etc/ld.so.conf")
    if os.path.isfile(ld_conf):
        content, _ = read_file(ld_conf)
        if content:
            print(f"\n  {bold('ld.so.conf contents:')} {ld_conf}")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if any(line.startswith(x) for x in ["/tmp", "/dev/shm", "/var/tmp"]):
                    print(red(f"  [HIGH RISK] Suspicious library path in ld.so.conf: {line}"))
                    record(category, "high_risk")
                else:
                    print(green(f"  [OK] {line}"))


# ─────────────────────────────────────────────────────────────
#  SUMMARY TABLE
# ─────────────────────────────────────────────────────────────

def print_summary():
    """Print a color-coded summary table of all findings by category."""
    print(f"\n\n{cyan('═' * 68)}")
    print(cyan("  DETECTION SUMMARY"))
    print(cyan('═' * 68))

    header = f"  {'Category':<30} {'Info':>6} {'Suspicious':>12} {'High Risk':>10}"
    print(bold(header))
    print(dim("  " + "─" * 62))

    total_info = total_sus = total_hr = 0

    for cat, counts in sorted(SUMMARY.items()):
        info = counts["info"]
        sus  = counts["suspicious"]
        hr   = counts["high_risk"]
        total_info += info
        total_sus  += sus
        total_hr   += hr

        hr_col  = red(f"{hr:>10}")   if hr  else f"{hr:>10}"
        sus_col = yellow(f"{sus:>12}") if sus else f"{sus:>12}"
        print(f"  {cat:<30} {info:>6} {sus_col} {hr_col}")

    print(dim("  " + "─" * 62))
    hr_tot  = red(f"{total_hr:>10}")    if total_hr  else f"{total_hr:>10}"
    sus_tot = yellow(f"{total_sus:>12}") if total_sus else f"{total_sus:>12}"
    print(bold(f"  {'TOTAL':<30} {total_info:>6} {sus_tot} {hr_tot}"))
    print(cyan('═' * 68))

    if total_hr > 0:
        print(red(f"\n  ⚠  {total_hr} HIGH RISK indicators found — immediate investigation recommended!"))
    if total_sus > 0:
        print(yellow(f"  ⚠  {total_sus} SUSPICIOUS indicators found — manual review required."))
    if total_hr == 0 and total_sus == 0:
        print(green("  ✓  No persistence mechanisms detected."))
    print()


# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSING & ENTRY POINT
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Linux Persistence Mechanism Hunter — Forensic & Threat Hunting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Live system scan (requires root)
          sudo python3 linux_persistence_hunter.py

          # Offline scan of a mounted VMDK / disk image
          sudo python3 linux_persistence_hunter.py --root /mnt/vmdk

          # Run only specific modules
          sudo python3 linux_persistence_hunter.py --root /mnt/evidence --modules cron,ssh,webshell
        """)
    )
    parser.add_argument(
        "--root", "-r",
        default="/",
        help="Root path to scan (default: /). Use /mnt/vmdk for offline images."
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        help=("Comma-separated list of modules to run. "
              "Options: cron, systemd, startup, env, suid, python, bash, webshell, ssh, rc, at, kmod, ld. "
              "Default: all")
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output (for log files)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.no_color:
        # Monkey-patch color functions to no-ops
        global red, yellow, green, cyan, magenta, bold, dim
        red = yellow = green = cyan = magenta = bold = dim = lambda t: t

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"ERROR: Root path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    banner()
    print(f"  {bold('Scan Target:')} {root}")
    print(f"  {bold('Timestamp:')}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {bold('User:')}       {os.environ.get('USER', 'unknown')} (UID {os.getuid()})")

    if os.getuid() != 0 and root == "/":
        print(yellow("\n  [WARN] Not running as root — some checks may be incomplete due to permission restrictions.\n"))

    # Module dispatch table
    all_modules = {
        "cron":     check_cron,
        "systemd":  check_systemd,
        "startup":  check_shell_startup,
        "env":      check_env_abuse,
        "suid":     check_suid_sgid,
        "python":   check_suspicious_python,
        "bash":     check_malicious_bash,
        "webshell": check_web_shells,
        "ssh":      check_ssh_persistence,
        "rc":       check_rc_init,
        "at":       check_at_jobs,
        "kmod":     check_kernel_modules,
        "ld":       check_ld_hijacking,
    }

    if args.modules.lower() == "all":
        selected = list(all_modules.keys())
    else:
        selected = [m.strip().lower() for m in args.modules.split(",")]
        invalid = [m for m in selected if m not in all_modules]
        if invalid:
            print(f"ERROR: Unknown modules: {', '.join(invalid)}", file=sys.stderr)
            print(f"Valid options: {', '.join(all_modules.keys())}", file=sys.stderr)
            sys.exit(1)

    for mod_name in selected:
        try:
            all_modules[mod_name](root)
        except KeyboardInterrupt:
            print(yellow("\n  [!] Interrupted by user."))
            break
        except Exception as e:
            print(red(f"\n  [ERROR] Module '{mod_name}' crashed: {e}"))
            import traceback
            traceback.print_exc()

    print_summary()


if __name__ == "__main__":
    main()
