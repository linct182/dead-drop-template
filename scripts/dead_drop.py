#!/usr/bin/env python3
"""Local, deliberately narrow approved-text transfer tool. Python 3.9+, POSIX."""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings


class Refusal(Exception):
    pass


MAX_BYTES = 25 * 1024 * 1024  # both total plaintext and archive, below GitHub limits
MAX_FILES = 100
TEXT_TYPES = {".txt", ".md", ".csv", ".tsv", ".json"}
EXCLUDED = {".git", ".svn", ".hg", "node_modules", "vendor", ".venv", "venv",
            "__pycache__", ".pytest_cache", ".cache", "build", "dist", "target",
            ".ds_store", "thumbs.db", "desktop.ini", "__macosx"}
APPROVED = {"AGENTS.md", "SPEC.md", "CODEX_HANDOFF.md", "README.md", "SECURITY.md", "LICENSE",
            ".gitignore", "drops/.gitkeep", "scripts/dead-drop", "scripts/dead_drop.py",
            "tests/test_dead_drop.py", ".githooks/pre-commit", ".githooks/pre-push"}
DROP_RE = re.compile(r"drops/drop-\d{4}-\d{2}-\d{2}-[0-9a-f]{16}\.7z\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,99}\Z")
SENSITIVE_PATH = re.compile(
    r"(?:secret|credential|password|confidential|proprietary|internal|customer|employee|"
    r"payroll|passport|private|id_rsa|id_ed25519|\.env|\.aws|\.ssh)", re.I)
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret)"
               r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_+/=.-]{8,}"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
]
LITERAL_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|password|passwd|client[_-]?secret)"
    r"[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_+/=.-]{8,}[\"']")
FLAGS = ["-t7z", "-m0=lzma2", "-mx=3", "-mmt=2", "-mhe=on", "-p"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, cwd, *, data=None, ok=True):
    try:
        proc = subprocess.run(argv, cwd=cwd, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal("A subprocess failed or timed out; no subprocess output is logged.") from None
    if ok and proc.returncode:
        raise Refusal("Command failed: " + argv[0] + " " + argv[1] + "; output suppressed.")
    return proc


def git(repo, *args, ok=True):
    return run(["git", "--no-pager", *args], repo, ok=ok)


def repository():
    output = git(Path.cwd(), "rev-parse", "--show-toplevel").stdout
    return Path(os.fsdecode(output.rstrip(b"\n"))).resolve()


def inside(path, root):
    return path == root or root in path.parents


def no_symlinks(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise Refusal("Symlink paths are not accepted.")


def read_file(path):
    """Bound reads and reject file symlinks, special files, and hardlinks."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
            raise Refusal("Expected a regular, single-link file no larger than 25 MiB.")
        data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise Refusal("File exceeds the 25 MiB MVP limit.")
        return data


def read_source(path):
    """Open each directory without following links, including under concurrent renames."""
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Refusal("Hardlinks and special files are blocked.")
            data = handle.read(MAX_BYTES + 1)
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise Refusal("Source changed during inspection; retry with stable files.")
            return data
    finally:
        os.close(parent_fd)


def temporary(repo):
    base = Path(tempfile.gettempdir()).resolve()
    if inside(base, repo):
        raise Refusal("Temporary storage must be outside the repository; fix TMPDIR.")
    return tempfile.TemporaryDirectory(prefix="dead-drop-", dir=base)


def sevenzip():
    if os.name != "posix":
        raise Refusal("Preparation is supported on POSIX (primarily macOS), not Windows.")
    binary = shutil.which("7zz")
    if not binary:
        raise Refusal("Official 7zz is missing. On macOS install: brew install sevenzip")
    return binary


def archive_command(binary, args, cwd, password=None, *, ok=True):
    # POSIX 7zz reads password lines from stdin. Never interpolate into argv/env.
    data = b"" if password is None else password.encode("ascii") + b"\n"
    proc = run([binary, *args], cwd, data=data, ok=False)
    if password is not None:
        if password.encode("ascii") in proc.stdout:
            raise Refusal("7zz echoed private input; this implementation is unsupported.")
        if b"Enter password" not in proc.stdout:
            raise Refusal("7zz password prompt was not recognized; refusing this implementation.")
    if ok and proc.returncode:
        raise Refusal("7zz failed (wrong password, invalid archive, or unsupported prompt); output suppressed.")
    return proc


def strong_password(password):
    if not 20 <= len(password) <= 128 or any(not 32 <= ord(c) <= 126 for c in password):
        raise Refusal("Use 20–128 printable ASCII characters from a unique random password/passphrase.")
    if password != password.strip() or len(set(password)) < 10:
        raise Refusal("Password is too repetitive or has leading/trailing whitespace.")
    if re.search(r"(?i)(password|qwerty|123456|letmein)", password):
        raise Refusal("Common password patterns are not accepted.")


def read_password(confirm=False):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise Refusal("A local interactive terminal is required; piped password input is disabled.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Archive password (unique, randomly generated, 20+ characters): ")
            strong_password(password)
            if confirm and password != getpass.getpass("Confirm archive password: "):
                raise Refusal("Passwords do not match.")
        except getpass.GetPassWarning:
            raise Refusal("Cannot obtain password without terminal echo.") from None
    return password


def consent(phrase, message):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise Refusal("Interactive human approval is required.")
    print(message)
    if input("Type " + phrase + " to continue: ") != phrase:
        raise Refusal("Approval not given; stopped.")


def safe_name(name):
    stem = name.split(".")[0].upper()
    if (not SAFE_NAME.fullmatch(name) or name.endswith((".", " ")) or
            stem in {"CON", "PRN", "AUX", "NUL", *["COM" + str(i) for i in range(10)],
                     *["LPT" + str(i) for i in range(10)]}):
        raise Refusal("Use a simple Windows-compatible filename (no paths or special characters).")


def inspect_text(name, data, *, payload=True):
    if payload:
        safe_name(name)
        if SENSITIVE_PATH.search(name):
            raise Refusal("Sensitive-looking filename blocked; original file was not changed.")
        if Path(name).suffix.lower() not in TEXT_TYPES:
            raise Refusal("Unknown format blocked. MVP accepts UTF-8 .txt/.md/.csv/.tsv/.json only.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("Non-UTF-8 or binary content blocked.") from None
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise Refusal("Binary/control characters blocked.")
    # Source code legitimately assigns variables named password/token. Use only
    # high-confidence literal signatures for approved implementation files.
    # The fixed GitHub SSH service username is not a personal email address.
    text = text.replace("git@github.com:", "github.com:")
    patterns = SECRET_PATTERNS if payload else [p for i, p in enumerate(SECRET_PATTERNS) if i != 4] + [LITERAL_SECRET]
    if any(pattern.search(text) for pattern in patterns):
        raise Refusal("Secret-like or personal-data pattern found; values are never displayed. Review the original locally.")


def snapshot(repo, root, selections, target):
    root = Path(os.path.abspath(root))
    no_symlinks(root)
    if not root.is_dir() or inside(root, repo):
        raise Refusal("Source root must be an existing directory outside this repository.")
    if not selections or len(selections) > MAX_FILES:
        raise Refusal("Select between 1 and 100 individual files.")
    manifest, seen, total = [], set(), 0
    for selection in selections:
        relative = Path(selection)
        if relative.is_absolute() or ".." in relative.parts:
            raise Refusal("Selections must be relative to --source-root without '..'.")
        source = root / relative
        no_symlinks(source)
        # Reject special files before exclusions and never follow nested repositories.
        if not source.is_file() or not stat.S_ISREG(source.stat().st_mode):
            raise Refusal("Only explicitly selected regular files are accepted (no directories/devices).")
        if any((parent / marker).exists() or (parent / marker).is_symlink() for parent in source.parents
               for marker in (".git", ".hg", ".svn")):
            raise Refusal("Source is inside a repository; nested/source repositories are blocked.")
        if any(part.lower() in EXCLUDED or part.startswith("._") for part in relative.parts):
            print("Excluded by default:", ascii(selection))
            continue
        if SENSITIVE_PATH.search(str(relative)):
            raise Refusal("Sensitive-looking source path blocked.")
        name = source.name
        safe_name(name)
        if name.casefold() in seen:
            raise Refusal("Duplicate/case-colliding basenames; rename selections outside the repository.")
        seen.add(name.casefold())
        data = read_source(source)
        total += len(data)
        if total > MAX_BYTES:
            raise Refusal("Selected plaintext exceeds the 25 MiB MVP limit.")
        inspect_text(name, data)
        if not data:
            raise Refusal("Empty files have no encrypted data stream; select nonempty text files.")
        (target / name).write_bytes(data)
        os.chmod(target / name, 0o600)
        manifest.append({"name": name, "size": len(data), "sha256": digest(data)})
    if not manifest:
        raise Refusal("No files remain after exclusions.")
    return sorted(manifest, key=lambda entry: entry["name"])


def show_manifest(manifest, archive):
    print("Local-only manifest (basenames are used inside the archive):")
    for entry in manifest:
        print(" ", ascii(entry["name"]), entry["size"], "bytes SHA256", entry["sha256"])
    print("Intended archive:", archive)
    print("Flags:", " ".join(FLAGS), "(password via private stdin pipe)")
    print("Scanner: no heuristic findings. This does not establish authorization or confidentiality.")


def validate_manifest(manifest):
    if not isinstance(manifest, list) or not 1 <= len(manifest) <= MAX_FILES:
        raise Refusal("Invalid local verification receipt.")
    seen, total = set(), 0
    for entry in manifest:
        if not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}:
            raise Refusal("Invalid receipt entry.")
        name, size, sha = entry["name"], entry["size"], entry["sha256"]
        if not isinstance(name, str):
            raise Refusal("Invalid receipt filename.")
        safe_name(name)
        if name.casefold() in seen or type(size) is not int or not 0 <= size <= MAX_BYTES:
            raise Refusal("Invalid receipt size or duplicate name.")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise Refusal("Invalid receipt hash.")
        seen.add(name.casefold())
        total += size
    if total > MAX_BYTES:
        raise Refusal("Receipt exceeds plaintext size limit.")


def hidden_headers(binary, archive):
    data = read_file(archive)
    if not 32 <= len(data) <= MAX_BYTES or not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        raise Refusal("Invalid or oversized 7z artifact.")
    probe = archive_command(binary, ["l", "-slt", "--", str(archive)], archive.parent, ok=False)
    if probe.returncode == 0 or b"Enter password" not in probe.stdout:
        raise Refusal("Archive does not demonstrate password-protected headers.")
    return probe.stdout


def verify(binary, archive, password, manifest, scratch):
    validate_manifest(manifest)
    public_listing = hidden_headers(binary, archive)
    if any(entry["name"].encode("ascii") in public_listing for entry in manifest):
        raise Refusal("Archive exposed a member name without a password.")
    wrong = secrets.token_hex(32)
    # On official POSIX 7zz, bare -p during reading means an empty password,
    # whereas omitting -p requests stdin input for encrypted archives.
    rejected = archive_command(binary, ["t", "--", str(archive)], scratch, wrong, ok=False)
    if rejected.returncode == 0:
        raise Refusal("Archive accepted a wrong password.")
    archive_command(binary, ["t", "--", str(archive)], scratch, password)
    listing = archive_command(binary, ["l", "-slt", "--", str(archive)], scratch, password).stdout
    try:
        body = listing.decode("utf-8").split("----------\n", 1)[1]
        records = []
        for block in body.strip().split("\n\n"):
            if block.strip():
                record = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
                records.append(record)
        expected = {entry["name"]: entry["size"] for entry in manifest}
        if len(records) != len(expected):
            raise ValueError()
        for record in records:
            name = record["Path"]
            safe_name(name)
            if (name not in expected or int(record["Size"]) != expected.pop(name) or
                    record.get("Encrypted") != "+" or "7zAES" not in record.get("Method", "") or
                    record.get("Folder", "-") != "-" or
                    any("link" in key.lower() for key in record) or
                    "l" in record.get("Attributes", "").split(" ")[-1]):
                raise ValueError()
        if expected:
            raise ValueError()
    except (ValueError, IndexError, KeyError, UnicodeDecodeError):
        raise Refusal("Archive member list, encryption, or sizes differ from the receipt.") from None
    extracted = scratch / "extracted"
    extracted.mkdir(mode=0o700)
    archive_command(binary, ["x", "-y", "-o" + str(extracted), "--", str(archive)], scratch, password)
    if {p.name for p in extracted.iterdir()} != {e["name"] for e in manifest}:
        raise Refusal("Extraction manifest mismatch.")
    for entry in manifest:
        path = extracted / entry["name"]
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise Refusal("Extracted member is not a regular private file.")
        data = read_file(path)
        if len(data) != entry["size"] or digest(data) != entry["sha256"]:
            raise Refusal("Extracted content hash mismatch.")
        inspect_text(entry["name"], data)


def receipt_directory(repo):
    raw = os.fsdecode(git(repo, "rev-parse", "--git-path", "dead-drop-receipts").stdout).strip()
    path = Path(raw)
    return path if path.is_absolute() else repo / path


def save_receipt(repo, archive, manifest):
    folder = receipt_directory(repo)
    no_symlinks(folder)
    folder.mkdir(mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    sha = digest(read_file(archive))
    path = folder / (sha + ".json")
    with path.open("x", encoding="utf-8") as handle:
        os.chmod(path, 0o600)
        json.dump({"sha256": sha, "manifest": manifest}, handle)


def load_receipt(repo, data):
    sha = digest(data)
    path = receipt_directory(repo) / (sha + ".json")
    no_symlinks(path)
    try:
        if path.stat().st_size > 50000:
            raise ValueError()
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["sha256"] != sha:
            raise ValueError()
        validate_manifest(record["manifest"])
        return record["manifest"]
    except (OSError, ValueError, KeyError, TypeError):
        raise Refusal("Missing/invalid local receipt. Only locally prepared, unchanged artifacts can be staged/published.") from None


def index_entries(repo, tree=None):
    if tree:
        raw = git(repo, "ls-tree", "-rz", tree).stdout
        entries = []
        for line in raw.split(b"\0"):
            if line:
                meta, name = line.split(b"\t", 1)
                mode, kind, oid = meta.split()
                entries.append((os.fsdecode(name), mode, oid))
        return entries
    raw = git(repo, "ls-files", "--stage", "-z").stdout
    entries = []
    for line in raw.split(b"\0"):
        if line:
            meta, name = line.split(b"\t", 1)
            mode, oid, stage = meta.split()
            if stage != b"0":
                raise Refusal("Resolve Git index conflicts first.")
            entries.append((os.fsdecode(name), mode, oid))
    return entries


def audit_entries(repo, entries, binary, require_receipts=()):
    with temporary(repo) as temp:
        scratch = Path(temp)
        for name, mode, oid in entries:
            if mode not in (b"100644", b"100755"):
                raise Refusal("Symlink/submodule/special Git entry blocked: " + ascii(name))
            if name not in APPROVED and not DROP_RE.fullmatch(name):
                raise Refusal("Non-allowlisted Git path (possible plaintext): " + ascii(name))
            size = int(git(repo, "cat-file", "-s", oid.decode()).stdout)
            if size > MAX_BYTES:
                raise Refusal("Oversized Git blob blocked.")
            data = git(repo, "cat-file", "blob", oid.decode()).stdout
            if DROP_RE.fullmatch(name):
                archive = scratch / "candidate.7z"
                archive.write_bytes(data)
                hidden_headers(binary, archive)
                if name in require_receipts:
                    load_receipt(repo, data)
            else:
                if name == "drops/.gitkeep" and data:
                    raise Refusal("drops/.gitkeep must be empty.")
                inspect_text(name, data, payload=False)


def changed_index(repo):
    return {os.fsdecode(p) for p in git(repo, "diff", "--cached", "--name-only", "-z").stdout.split(b"\0") if p}


def audit_index(repo, binary):
    audit_entries(repo, index_entries(repo), binary, changed_index(repo))


def worktree_check(repo, binary):
    audit_index(repo, binary)
    # Untracked and ignored raw payloads must not hide behind .gitignore.
    for options in (("--others", "--exclude-standard"), ("--others", "--ignored", "--exclude-standard")):
        for raw in git(repo, "ls-files", "-z", *options).stdout.split(b"\0"):
            if not raw:
                continue
            name = os.fsdecode(raw)
            path = repo / name
            no_symlinks(path)
            if "__pycache__" in path.parts and path.suffix == ".pyc" and not path.is_symlink():
                continue
            if name in APPROVED or DROP_RE.fullmatch(name):
                continue
            if path.name in {".DS_Store", "Thumbs.db"} and not path.is_symlink():
                continue
            raise Refusal("Unexpected local file (including ignored files): " + ascii(name))
    for name in APPROVED:
        path = repo / name
        if path.exists() or path.is_symlink():
            no_symlinks(path)
            inspect_text(name, read_file(path), payload=False)
    drops = repo / "drops"
    no_symlinks(drops)
    if drops.exists():
        for path in drops.iterdir():
            no_symlinks(path)
            if path.name == ".gitkeep" and path.is_file() and not path.read_bytes():
                continue
            if not path.is_file() or not DROP_RE.fullmatch("drops/" + path.name):
                raise Refusal("Unexpected file/directory in drops/.")
            hidden_headers(binary, path)
            # All new/modified artifacts must have local provenance.
            head = git(repo, "show", "HEAD:drops/" + path.name, ok=False)
            if head.returncode or head.stdout != read_file(path):
                load_receipt(repo, read_file(path))


def prepare(repo, args):
    binary = sevenzip()
    worktree_check(repo, binary)
    with temporary(repo) as temp:
        scratch = Path(temp)
        source = scratch / "snapshot"
        source.mkdir(mode=0o700)
        manifest = snapshot(repo, args.source_root, args.paths, source)
        name = "drop-" + datetime.date.today().isoformat() + "-" + secrets.token_hex(8) + ".7z"
        relative = "drops/" + name
        show_manifest(manifest, relative)
        consent("AUTHORIZED", "Confirm both public distribution and home-to-office download through public GitHub are approved.\n"
                "Encryption is defense in depth. Never use this for restricted material or to bypass office controls.")
        password = read_password(confirm=True)
        archive = scratch / name
        archive_command(binary, ["a", *FLAGS, "--", str(archive), *[e["name"] for e in manifest]], source, password)
        verify(binary, archive, password, manifest, scratch)
        del password
        worktree_check(repo, binary)
        drops = repo / "drops"
        drops.mkdir(exist_ok=True)
        no_symlinks(drops)
        destination = drops / name
        created = False
        try:
            with destination.open("xb") as output:
                created = True
                os.chmod(destination, 0o600)
                output.write(read_file(archive))
            save_receipt(repo, destination, manifest)
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise
        print("Verified archive created:", relative)
        print("Nothing staged, committed, or pushed. Local receipt is under .git/dead-drop-receipts/.")


def hook_check(repo, binary):
    configured = git(repo, "config", "--get", "core.hooksPath", ok=False).stdout.strip()
    if configured != b".githooks":
        raise Refusal("Enable the repository hooks first: git config core.hooksPath .githooks")
    for name in ("pre-commit", "pre-push"):
        path = repo / ".githooks" / name
        no_symlinks(path)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise Refusal("Repository hooks must exist and be executable.")


def publish(repo, args):
    binary = sevenzip()
    worktree_check(repo, binary)
    hook_check(repo, binary)
    if changed_index(repo) or git(repo, "diff", "--name-only").stdout:
        raise Refusal("Publish requires an empty index and no tracked changes. Review/commit code separately.")
    relative = args.archive
    if not DROP_RE.fullmatch(relative):
        raise Refusal("Specify a locally prepared drops/drop-DATE-RANDOM.7z path.")
    archive = repo / relative
    no_symlinks(archive)
    data = read_file(archive)
    manifest = load_receipt(repo, data)
    original_hash = digest(data)
    if git(repo, "ls-files", "--error-unmatch", "--", relative, ok=False).returncode == 0:
        raise Refusal("Archive is already tracked; publish accepts only a new local drop.")
    branch = git(repo, "symbolic-ref", "--short", "HEAD").stdout.decode().strip()
    if git(repo, "check-ref-format", "--branch", branch, ok=False).returncode:
        raise Refusal("Invalid branch.")
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    fetch_urls = git(repo, "remote", "get-url", "--all", "origin").stdout.decode().splitlines()
    push_urls = git(repo, "remote", "get-url", "--push", "--all", "origin").stdout.decode().splitlines()
    if len(fetch_urls) != 1 or fetch_urls != push_urls or not re.fullmatch(
            r"(?:git@github\.com:|https://github\.com/|ssh://git@github\.com/)"
            r"[A-Za-z0-9_-]+/dead-drop(?:\.git)?", fetch_urls[0]):
        raise Refusal("Origin must have one matching fetch/push GitHub dead-drop URL, without embedded credentials.")
    remote = git(repo, "ls-remote", "--exit-code", "origin", "refs/heads/" + branch).stdout.split()
    if not remote or remote[0] != head:
        raise Refusal("Local HEAD must equal the existing origin branch; synchronize/review unpublished commits separately.")
    with temporary(repo) as temp:
        scratch = Path(temp)
        pinned = scratch / "candidate.7z"
        pinned.write_bytes(data)
        password = read_password()
        verify(binary, pinned, password, manifest, scratch)
        del password
    show_manifest(manifest, relative)
    print("Origin:", ascii(push_urls[0]))
    print("Branch:", ascii(branch))
    staged = False
    committed = False
    try:
        git(repo, "add", "--", relative)
        staged = True
        audit_index(repo, binary)
        if changed_index(repo) != {relative}:
            raise Refusal("Index changed unexpectedly.")
        # Only a single known encrypted binary is staged, so this diff contains no member names.
        print(git(repo, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--stat", "--", relative).stdout.decode())
        print(git(repo, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--", relative).stdout.decode())
        consent("PUBLISH", "Commit and push this archive to PUBLIC GitHub? It may remain public permanently.")
        worktree_check(repo, binary)
        if (digest(read_file(archive)) != original_hash or changed_index(repo) != {relative} or
                git(repo, "rev-parse", "HEAD").stdout.strip() != head or
                git(repo, "show", ":" + relative).stdout != data or
                git(repo, "remote", "get-url", "--push", "--all", "origin").stdout.decode().splitlines() != push_urls):
            raise Refusal("Archive, HEAD, or index changed during approval.")
        git(repo, "commit", "-m", "Add encrypted drop " + archive.name)
        committed = True
        # Normal non-force push of exactly this branch; pre-push also audits all outgoing trees.
        try:
            git(repo, "push", "--no-follow-tags", "--no-mirror", push_urls[0], "HEAD:refs/heads/" + branch)
        except Refusal:
            raise Refusal("Commit was created; push failed or its result is uncertain. Inspect GitHub and Git status before taking further action.") from None
        print("Published encrypted archive:", relative)
    finally:
        if staged and not committed:
            git(repo, "reset", "-q", "HEAD", "--", relative, ok=False)


def pre_push(repo, binary):
    # Hook protocol is ref lines on stdin, never passwords. Audit every outgoing commit,
    # including historical versions deleted from the final tree.
    for line in sys.stdin:
        fields = line.split()
        if len(fields) != 4:
            raise Refusal("Invalid pre-push protocol.")
        _, local, destination, remote = fields
        if not re.fullmatch(r"[0-9a-f]{40,64}", local + "") or not re.fullmatch(r"[0-9a-f]{40,64}", remote):
            raise Refusal("Invalid push object IDs.")
        if set(local) == {"0"}:
            continue
        # Tags and arbitrary refs can publish annotations or raw blobs that
        # rev-list/tree inspection does not cover. This workflow publishes branches only.
        if not destination.startswith("refs/heads/"):
            raise Refusal("Only branch updates are supported; tags and other refs are blocked.")
        if git(repo, "cat-file", "-t", local).stdout.strip() != b"commit":
            raise Refusal("Outgoing branch must point directly to a commit, not a tag/tree/blob.")
        if set(remote) == {"0"}:
            revisions = git(repo, "rev-list", local).stdout.split()
        else:
            revisions = git(repo, "rev-list", local, "^" + remote).stdout.split()
        for oid in revisions:
            message = git(repo, "cat-file", "commit", oid.decode()).stdout.partition(b"\n\n")[2]
            inspect_text("commit message", message, payload=False)
            entries = index_entries(repo, oid.decode())
            # Local receipts required for every outgoing archive, not just the tip.
            audit_entries(repo, entries, binary, {name for name, _, _ in entries if DROP_RE.fullmatch(name)})
    print("Outgoing history passed the local path/content guard.")


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Dead Drop: approved non-confidential text only. No unattended publication.")
    sub = parser.add_subparsers(dest="command")
    prep = sub.add_parser("prepare", help="Review explicit external files, encrypt and verify; no staging/push")
    prep.add_argument("--source-root", required=True, type=Path)
    prep.add_argument("paths", nargs="+")
    pub = sub.add_parser("publish", help="Reverify, review diff, explicitly approve commit and push")
    pub.add_argument("archive")
    check = sub.add_parser("check", help="Check prerequisites, index, working tree and plaintext prevention")
    check.add_argument("--index", action="store_true", help="Audit exact staged blobs (pre-commit hook)")
    check.add_argument("--pre-push", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("help", help="Show usage")
    args = parser.parse_args(argv)
    if args.command in (None, "help"):
        parser.print_help()
        return 0
    try:
        repo = repository()
        if args.command == "prepare":
            prepare(repo, args)
        elif args.command == "publish":
            publish(repo, args)
        else:
            binary = sevenzip()
            if args.pre_push:
                pre_push(repo, binary)
            elif args.index:
                audit_index(repo, binary)
            else:
                worktree_check(repo, binary)
                hook_check(repo, binary)
                print("Repository/index checks passed; 7zz available. No authorization is implied.")
        return 0
    except (Refusal, OSError, EOFError, KeyboardInterrupt) as error:
        # Never include OS filenames/contents or raw subprocess output in errors.
        message = str(error) if isinstance(error, Refusal) else "Interrupted or local I/O failed; no publication completed by this step."
        print("STOP:", message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
