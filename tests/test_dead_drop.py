"""Synthetic fixtures only; real archives stay in auto-cleaned external tempdirs."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dead_drop", PROJECT / "scripts/dead_drop.py")
dd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dd)


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dead-drop-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.source = self.base / "source"
        self.source.mkdir()
        self.scratch = self.base / "scratch"
        self.scratch.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "synthetic.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.repo / "README.md").write_text("Approved synthetic repository.\n")
        (self.repo / "drops").mkdir()
        (self.repo / "drops/.gitkeep").touch()
        self.git("add", "--", "README.md", "drops/.gitkeep")
        self.git("commit", "-qm", "Synthetic base")
        self.sample = self.source / "sample.txt"
        self.sample.write_text("Approved synthetic public sample.\n")
        self.password = secrets.token_hex(24)
        self.name = "drops/drop-2026-11-08-0123456789abcdef.7z"

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True).stdout

    def snapshot(self, selections=None):
        return dd.snapshot(self.repo, self.source, selections or ["sample.txt"], self.scratch)

    def artifact(self):
        manifest = self.snapshot()
        archive = self.repo / self.name
        dd.archive_command(dd.sevenzip(), ["a", *dd.FLAGS, "--", str(archive), "sample.txt"],
                           self.scratch, self.password)
        dd.save_receipt(self.repo, archive, manifest)
        return archive, manifest


class SelectionTests(Sandbox):
    def test_launcher_runs_directly_without_shell_fallback(self):
        result = subprocess.run([str(PROJECT / "scripts/dead-drop"), "help"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"prepare", result.stdout)

    def test_positive_snapshot_leaves_original_untouched(self):
        before = self.sample.read_bytes()
        manifest = self.snapshot()
        self.assertEqual(manifest[0]["sha256"], dd.digest(before))
        self.assertEqual((self.scratch / "sample.txt").read_bytes(), before)
        self.assertEqual(self.sample.read_bytes(), before)

    def test_secret_personal_unknown_and_binary_content(self):
        cases = [("sample.txt", "api_" + "key = '" + secrets.token_hex(24) + "'"),
                 ("sample.txt", "person" + "@example.invalid"),
                 ("sample.txt", "-----BEGIN " + "PRIVATE KEY-----"),
                 ("sample.txt", "a\x00b"), ("sample.pdf", "unknown")]
        for name, content in cases:
            with self.subTest(name=name, category=cases.index((name, content))):
                (self.source / name).write_text(content)
                with self.assertRaises(dd.Refusal):
                    self.snapshot([name])
        self.assertFalse(list(self.scratch.iterdir()))

    def test_sensitive_names_and_paths(self):
        for name in (".env", "credentials.txt", "internal.csv"):
            (self.source / name).write_text("synthetic")
            with self.subTest(name=name), self.assertRaises(dd.Refusal):
                self.snapshot([name])

    def test_symlink_file_and_parent(self):
        (self.source / "link.txt").symlink_to(self.sample)
        (self.source / "folder").symlink_to(self.source, target_is_directory=True)
        for name in ("link.txt", "folder/sample.txt"):
            with self.subTest(name=name), self.assertRaises(dd.Refusal):
                self.snapshot([name])

    def test_hardlink_device_directory_and_escape(self):
        os.link(self.sample, self.source / "hard.txt")
        os.mkfifo(self.source / "fifo.txt")
        for name in ("hard.txt", "fifo.txt", ".", "../outside.txt", str(self.sample)):
            with self.subTest(name=name), self.assertRaises(dd.Refusal):
                self.snapshot([name])

    def test_nested_repo(self):
        (self.source / ".git").mkdir()
        with self.assertRaises(dd.Refusal):
            self.snapshot()

    def test_exclusion_is_visible(self):
        (self.source / "node_modules").mkdir()
        (self.source / "node_modules/a.txt").write_text("excluded")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            manifest = self.snapshot(["node_modules/a.txt", "sample.txt"])
        self.assertIn("Excluded by default", output.getvalue())
        self.assertEqual([e["name"] for e in manifest], ["sample.txt"])

    def test_duplicates_empty_and_oversized(self):
        with self.assertRaises(dd.Refusal):
            self.snapshot(["sample.txt", "sample.txt"])
        self.sample.write_bytes(b"")
        with self.assertRaises(dd.Refusal):
            self.snapshot()
        self.sample.write_bytes(b"0123456789")
        with mock.patch.object(dd, "MAX_BYTES", 5), self.assertRaises(dd.Refusal):
            self.snapshot()

    def test_windows_unsafe_and_control_filenames(self):
        for name in ("CON.txt", "a\nb.txt", "-switch.txt", "@list.txt", "a:b.txt", "a.txt."):
            with self.subTest(name=repr(name)), self.assertRaises(dd.Refusal):
                dd.safe_name(name)

    def test_missing_dependency(self):
        with mock.patch.object(dd.shutil, "which", return_value=None), self.assertRaises(dd.Refusal):
            dd.sevenzip()

    def test_weak_empty_and_incompatible_passwords(self):
        for value in ("", "short", "a" * 40, "password" + "abcdefghijklmno", "abcdefghijklmnoé123456789", "abc\ndefghijklmnopqrst"):
            with self.subTest(length=len(value)), self.assertRaises(dd.Refusal):
                dd.strong_password(value)
        dd.strong_password(self.password)

    def test_no_piped_password_or_approval(self):
        with mock.patch.object(dd.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(dd.Refusal):
                dd.read_password()
            with self.assertRaises(dd.Refusal):
                dd.consent("AUTHORIZED", "synthetic")

    def test_no_getpass_echo_fallback_and_mismatch(self):
        import warnings
        def fallback(*args):
            warnings.warn("synthetic", dd.getpass.GetPassWarning)
            return self.password
        with mock.patch.object(dd.sys.stdin, "isatty", return_value=True), mock.patch.object(dd.sys.stdout, "isatty", return_value=True):
            with mock.patch.object(dd.getpass, "getpass", side_effect=fallback), self.assertRaises(dd.Refusal):
                dd.read_password()
            with mock.patch.object(dd.getpass, "getpass", side_effect=[self.password, "different"]), self.assertRaises(dd.Refusal):
                dd.read_password(confirm=True)

    def test_consent_requires_exact_phrase(self):
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(dd.sys.stdin, "isatty", return_value=True), mock.patch.object(dd.sys.stdout, "isatty", return_value=True):
            with mock.patch("builtins.input", return_value="yes"), self.assertRaises(dd.Refusal):
                dd.consent("AUTHORIZED", "synthetic")
            with mock.patch("builtins.input", return_value="AUTHORIZED"):
                dd.consent("AUTHORIZED", "synthetic")

    def test_repository_local_temporary_root_rejected(self):
        with mock.patch.object(dd.tempfile, "gettempdir", return_value=str(self.repo)), self.assertRaises(dd.Refusal):
            dd.temporary(self.repo)


@unittest.skipUnless(shutil.which("7zz"), "Official 7zz required for integration tests")
class ArchiveAndGitTests(Sandbox):
    def test_real_multifile_archive(self):
        (self.source / "table.csv").write_text("item,count\napples,3\n")
        manifest = self.snapshot(["sample.txt", "table.csv"])
        archive = self.base / "multiple.7z"
        dd.archive_command(dd.sevenzip(), ["a", *dd.FLAGS, "--", str(archive),
                                          *[e["name"] for e in manifest]],
                           self.scratch, self.password)
        dd.verify(dd.sevenzip(), archive, self.password, manifest, self.base)

    def test_pre_push_rejects_tag_refs_and_noncommit_objects(self):
        head = self.git("rev-parse", "HEAD").decode().strip()
        self.git("tag", "-a", "synthetic-tag", "-m", "synthetic annotation")
        tag = self.git("rev-parse", "synthetic-tag").decode().strip()
        blob = self.git("rev-parse", "HEAD:README.md").decode().strip()
        for oid, destination in ((head, "refs/tags/lightweight"),
                                 (tag, "refs/tags/annotated"),
                                 (tag, "refs/heads/tag-object"),
                                 (blob, "refs/notes/payload"),
                                 (blob, "refs/heads/blob-object")):
            protocol = "HEAD " + oid + " " + destination + " " + "0" * 40 + "\n"
            with self.subTest(destination=destination):
                with mock.patch.object(dd.sys, "stdin", io.StringIO(protocol)):
                    with self.assertRaises(dd.Refusal):
                        dd.pre_push(self.repo, dd.sevenzip())

    def test_pre_push_reviews_commit_messages_and_allows_safe_branch(self):
        parent = self.git("rev-parse", "HEAD").decode().strip()
        for message, blocked in (("Reviewed public documentation", False),
                                 ("gh" + "p_" + "a" * 36, True)):
            self.git("commit", "--allow-empty", "-qm", message)
            head = self.git("rev-parse", "HEAD").decode().strip()
            protocol = "HEAD " + head + " refs/heads/main " + parent + "\n"
            with self.subTest(blocked=blocked), contextlib.redirect_stdout(io.StringIO()):
                with mock.patch.object(dd.sys, "stdin", io.StringIO(protocol)):
                    if blocked:
                        with self.assertRaises(dd.Refusal):
                            dd.pre_push(self.repo, dd.sevenzip())
                    else:
                        dd.pre_push(self.repo, dd.sevenzip())
            parent = head

    def test_real_encryption_extraction_and_wrong_password(self):
        archive, manifest = self.artifact()
        dd.verify(dd.sevenzip(), archive, self.password, manifest, self.base)
        with tempfile.TemporaryDirectory(dir=self.base) as temp, self.assertRaises(dd.Refusal):
            dd.verify(dd.sevenzip(), archive, secrets.token_hex(24), manifest, Path(temp))
        listing = dd.archive_command(dd.sevenzip(), ["l", "--", str(archive)], self.base, ok=False)
        self.assertNotEqual(listing.returncode, 0)
        self.assertNotIn(b"sample.txt", listing.stdout)
        self.assertNotIn(self.password.encode(), archive.read_bytes())

    def test_password_only_on_stdin_not_argv_env_or_output(self):
        original = dd.subprocess.run
        invocations = []
        def capture(argv, **kwargs):
            self.assertNotIn(self.password, " ".join(argv))
            self.assertNotIn("env", kwargs)
            result = original(argv, **kwargs)
            if argv[0] == dd.sevenzip():
                invocations.append(kwargs["input"])
                self.assertNotIn(self.password.encode(), result.stdout)
            return result
        with mock.patch.object(dd.subprocess, "run", side_effect=capture):
            self.artifact()
        self.assertIn(self.password.encode() + b"\n", invocations)

    def test_bad_prompt_or_echo_fails_closed(self):
        for output in (b"no recognized prompt", b"Enter password:" + self.password.encode()):
            proc = types.SimpleNamespace(returncode=0, stdout=output)
            with mock.patch.object(dd, "run", return_value=proc), self.assertRaises(dd.Refusal):
                dd.archive_command("synthetic", ["a"], self.base, self.password)

    def test_unencrypted_and_content_only_encryption_rejected(self):
        for flags in (["-t7z"], ["-t7z", "-p"]):
            archive = self.base / ("probe" + str(len(flags)) + ".7z")
            password = self.password if "-p" in flags else None
            dd.archive_command(dd.sevenzip(), ["a", *flags, "--", str(archive), "sample.txt"], self.source, password)
            with self.assertRaises(dd.Refusal):
                dd.hidden_headers(dd.sevenzip(), archive)

    def test_failed_verification_does_not_create_drop_or_receipt(self):
        args = types.SimpleNamespace(source_root=self.source, paths=["sample.txt"])
        temporary_paths = []
        original = dd.temporary
        def tracked_temporary(repo):
            handle = original(repo)
            temporary_paths.append(Path(handle.name))
            return handle
        with mock.patch.object(dd, "temporary", side_effect=tracked_temporary), mock.patch.object(dd, "consent"), mock.patch.object(dd, "read_password", return_value=self.password), mock.patch.object(dd, "verify", side_effect=dd.Refusal("synthetic verification failure")), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(dd.Refusal):
                dd.prepare(self.repo, args)
        self.assertEqual([p.name for p in (self.repo / "drops").iterdir()], [".gitkeep"])
        self.assertFalse(dd.receipt_directory(self.repo).exists())
        self.assertEqual(dd.changed_index(self.repo), set())
        self.assertTrue(temporary_paths)
        self.assertTrue(all(not path.exists() for path in temporary_paths))

    def test_prepare_success_no_staging_or_plaintext(self):
        args = types.SimpleNamespace(source_root=self.source, paths=["sample.txt"])
        output = io.StringIO()
        with mock.patch.object(dd, "consent"), mock.patch.object(dd, "read_password", return_value=self.password), contextlib.redirect_stdout(output):
            dd.prepare(self.repo, args)
        artifacts = list((self.repo / "drops").glob("*.7z"))
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(dd.changed_index(self.repo), set())
        self.assertNotIn("sample.txt", self.git("status", "--short").decode())
        self.assertNotIn(self.password, output.getvalue())
        receipt = dd.load_receipt(self.repo, artifacts[0].read_bytes())
        self.assertEqual(receipt[0]["name"], "sample.txt")
        self.assertTrue(self.sample.exists())
        self.assertFalse((self.repo / "sample.txt").exists())

    def test_staged_plaintext_and_deleted_historical_plaintext(self):
        (self.repo / "raw.txt").write_text("synthetic")
        self.git("add", "--", "raw.txt")
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())
        self.git("commit", "-qm", "unsafe synthetic fixture")
        self.git("rm", "-q", "raw.txt")
        self.git("commit", "-qm", "delete fixture")
        oid = self.git("rev-parse", "HEAD").decode().strip()
        protocol = "refs/heads/main " + oid + " refs/heads/main " + "0" * 40 + "\n"
        with mock.patch.object(dd.sys, "stdin", io.StringIO(protocol)), self.assertRaises(dd.Refusal):
            dd.pre_push(self.repo, dd.sevenzip())

    def test_index_blob_not_working_copy_is_scanned(self):
        token = "gh" + "p_" + "a" * 36
        (self.repo / "README.md").write_text(token)
        self.git("add", "--", "README.md")
        (self.repo / "README.md").write_text("clean worktree")
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())

    def test_hardcoded_credential_in_approved_document_is_blocked(self):
        (self.repo / "README.md").write_text("pass" + "word = '" + secrets.token_hex(24) + "'")
        self.git("add", "--", "README.md")
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())

    def test_forged_drop_and_symlink_index_rejected(self):
        (self.repo / self.name).write_text("not encrypted")
        self.git("add", "--", self.name)
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())
        self.git("reset", "-q", "HEAD", "--", self.name)
        (self.repo / "SPEC.md").symlink_to(self.sample)
        self.git("add", "--", "SPEC.md")
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())

    def test_receipt_and_ciphertext_tampering(self):
        archive, manifest = self.artifact()
        self.assertEqual(dd.load_receipt(self.repo, archive.read_bytes()), manifest)
        original = archive.read_bytes()
        archive.write_bytes(original + b"tampered")
        with self.assertRaises(dd.Refusal):
            dd.load_receipt(self.repo, archive.read_bytes())
        archive.write_bytes(original)
        self.git("add", "--", self.name)
        dd.audit_index(self.repo, dd.sevenzip())
        receipt = dd.receipt_directory(self.repo) / (dd.digest(original) + ".json")
        receipt.unlink()
        with self.assertRaises(dd.Refusal):
            dd.audit_index(self.repo, dd.sevenzip())

    def test_extraction_hash_mismatch(self):
        archive, manifest = self.artifact()
        manifest[0]["sha256"] = "0" * 64
        with self.assertRaises(dd.Refusal):
            dd.verify(dd.sevenzip(), archive, self.password, manifest, self.base)

    def test_corrupted_archive_fails_verification(self):
        archive, manifest = self.artifact()
        data = bytearray(archive.read_bytes())
        data[40] ^= 0xFF
        archive.write_bytes(data)
        with self.assertRaises(dd.Refusal):
            dd.verify(dd.sevenzip(), archive, self.password, manifest, self.base)

    def test_real_precommit_hook_allows_code_and_blocks_raw_payload(self):
        (self.repo / "scripts").mkdir()
        (self.repo / ".githooks").mkdir()
        shutil.copyfile(PROJECT / "scripts/dead_drop.py", self.repo / "scripts/dead_drop.py")
        shutil.copyfile(PROJECT / "LICENSE", self.repo / "LICENSE")
        hook = self.repo / ".githooks/pre-commit"
        shutil.copyfile(PROJECT / ".githooks/pre-commit", hook)
        hook.chmod(0o755)
        self.git("config", "core.hooksPath", ".githooks")
        self.git("add", "--", "scripts/dead_drop.py", ".githooks/pre-commit", "LICENSE")
        self.git("commit", "-qm", "approved synthetic implementation")
        (self.repo / "raw.txt").write_text("synthetic plaintext")
        self.git("add", "--", "raw.txt")
        result = subprocess.run(["git", "commit", "-qm", "must be blocked"], cwd=self.repo,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Non-allowlisted Git path", result.stderr)

    def test_ignored_plaintext_and_untracked_symlink_rejected(self):
        (self.repo / ".gitignore").write_text("*.env\n")
        (self.repo / "payload.env").write_text("synthetic")
        with self.assertRaises(dd.Refusal):
            dd.worktree_check(self.repo, dd.sevenzip())
        (self.repo / "payload.env").unlink()
        (self.repo / "SPEC.md").symlink_to(self.sample)
        with self.assertRaises(dd.Refusal):
            dd.worktree_check(self.repo, dd.sevenzip())

    def configure_publish(self):
        self.git("remote", "add", "origin", "git@github.com:synthetic/dead-drop.git")
        (self.repo / ".githooks").mkdir()
        for name in ("pre-commit", "pre-push"):
            shutil.copyfile(PROJECT / ".githooks" / name, self.repo / ".githooks" / name)
            (self.repo / ".githooks" / name).chmod(0o755)
        self.git("add", "--", ".githooks/pre-commit", ".githooks/pre-push")
        self.git("commit", "-qm", "synthetic hooks")
        # Hook invocation is mocked; all other Git operations remain real.
        self.git("config", "core.hooksPath", ".githooks")

    def publish_git(self, calls, *, remote_ahead=False):
        original = dd.git
        def intercept(repo, *args, **kwargs):
            calls.append(args)
            if args[0] == "ls-remote":
                oid = "0" * 40 if remote_ahead else self.git("rev-parse", "HEAD").decode().strip()
                return types.SimpleNamespace(returncode=0, stdout=(oid + "\trefs/heads/main\n").encode())
            if args[0] in ("commit", "push"):
                return types.SimpleNamespace(returncode=0, stdout=b"")
            return original(repo, *args, **kwargs)
        return intercept

    def test_publish_declined_unstages_and_never_commits_or_pushes(self):
        self.configure_publish()
        archive, _ = self.artifact()
        calls = []
        with mock.patch.object(dd, "git", side_effect=self.publish_git(calls)), mock.patch.object(dd, "read_password", return_value=self.password), mock.patch.object(dd, "consent", side_effect=dd.Refusal("declined")), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(dd.Refusal):
                dd.publish(self.repo, types.SimpleNamespace(archive=self.name))
        self.assertFalse(any(call[0] in ("commit", "push") for call in calls))
        self.assertEqual(dd.changed_index(self.repo), set())
        self.assertTrue(archive.exists())

    def test_publish_only_after_exact_confirmation(self):
        self.configure_publish()
        self.artifact()
        calls, confirmations = [], []
        output = io.StringIO()
        def approve(phrase, message):
            self.assertFalse(any(call[0] in ("commit", "push") for call in calls))
            self.assertEqual(dd.changed_index(self.repo), {self.name})
            review = output.getvalue()
            self.assertIn("Local-only manifest", review)
            self.assertIn("sample.txt", review)
            self.assertIn("Intended archive: " + self.name, review)
            self.assertIn("Flags: " + " ".join(dd.FLAGS), review)
            self.assertIn("diff --git", review)
            confirmations.append(phrase)
        with mock.patch.object(dd, "git", side_effect=self.publish_git(calls)), mock.patch.object(dd, "read_password", return_value=self.password), mock.patch.object(dd, "consent", side_effect=approve), contextlib.redirect_stdout(output):
            dd.publish(self.repo, types.SimpleNamespace(archive=self.name))
        self.assertEqual(confirmations, ["PUBLISH"])
        self.assertEqual([call[0] for call in calls if call[0] in ("commit", "push")], ["commit", "push"])
        push = next(call for call in calls if call[0] == "push")
        self.assertIn("--no-follow-tags", push)
        self.assertNotIn("--force", push)

    def test_publish_blocks_extra_staged_file_and_unpublished_head(self):
        self.configure_publish()
        self.artifact()
        (self.repo / "README.md").write_text("changed")
        self.git("add", "--", "README.md")
        with self.assertRaises(dd.Refusal):
            dd.publish(self.repo, types.SimpleNamespace(archive=self.name))
        self.git("reset", "--hard", "-q", "HEAD")
        calls = []
        with mock.patch.object(dd, "git", side_effect=self.publish_git(calls, remote_ahead=True)), self.assertRaises(dd.Refusal):
            dd.publish(self.repo, types.SimpleNamespace(archive=self.name))
        self.assertFalse(any(call[0] in ("commit", "push") for call in calls))

    def test_publish_rechecks_index_after_approval(self):
        self.configure_publish()
        self.artifact()
        calls = []
        def concurrent_change(*args):
            (self.repo / "README.md").write_text("changed during approval")
            self.git("add", "--", "README.md")
        with mock.patch.object(dd, "git", side_effect=self.publish_git(calls)), mock.patch.object(dd, "read_password", return_value=self.password), mock.patch.object(dd, "consent", side_effect=concurrent_change), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(dd.Refusal):
                dd.publish(self.repo, types.SimpleNamespace(archive=self.name))
        self.assertFalse(any(call[0] in ("commit", "push") for call in calls))
        self.assertNotIn(self.name, dd.changed_index(self.repo))


if __name__ == "__main__":
    unittest.main()
