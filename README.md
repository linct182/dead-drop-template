# Dead Drop

**Leave it here. Pick it up elsewhere.**

A small local CLI for packaging selected files into encrypted archives and sharing them through GitHub. Archives use 7z AES-256 encryption, including encrypted filenames, and are verified locally before publication.

Use only non-confidential files approved for public distribution through an authorized sharing channel. Anyone can download a public archive, and Git history can retain it after deletion. Encryption does not grant permission to share restricted material.

## Create your own copy

Open [dead-drop-template](https://github.com/linct182/dead-drop-template), select **Use this template → Create a new repository**, and create a repository named **`dead-drop`** under your own account. The current CLI requires that repository name. The template contains the tool and an empty `drops/` folder, with no transfer archives or local receipts.

Clone your new repository and run setup inside it:

```sh
git clone https://github.com/YOUR-USERNAME/dead-drop.git
cd dead-drop
```

Replace `YOUR-USERNAME` with your GitHub username. Your `origin` should point to your own repository. Use the visibility and sharing channel authorized for your files; anonymous downloads require a public repository.

## Setup

Preparation runs on macOS with Python 3.9+, Git, and official `7zz`. No additional Python packages are required.

```sh
brew install sevenzip
git config core.hooksPath .githooks
./scripts/dead-drop check
```

Repeat hook setup after cloning. The local hooks check staged files and outgoing history; they are safeguards against mistakes, not a server-side security policy.

## Prepare

Keep source files outside the repository and select individual files relative to their source folder:

```sh
./scripts/dead-drop prepare --source-root /absolute/path/to/approved-files sample.md
```

The tool scans a private snapshot and displays a local manifest, archive name, exclusions, and encryption flags. Review the selection and type `AUTHORIZED` to confirm the required permissions. Originals remain untouched.

Enter and confirm a unique, randomly generated password of **20–128 printable ASCII characters**. Keep it in your approved password manager; it cannot be recovered by the tool. Enter it only at the private terminal prompt, never in commands, repository files, or logs. Terminal input is hidden and passwords reach `7zz` through a private stdin pipe.

Preparation verifies encrypted filenames, wrong-password rejection, archive integrity, and extracted content hashes. Only a verified `.7z` file is copied into `drops/`. Nothing is staged, committed, or pushed by `prepare`.

Supported inputs are nonempty UTF-8 `.txt`, `.md`, `.csv`, `.tsv`, and `.json` files: up to 100 files and 25 MiB total. Archives must also fit 25 MiB. Directories, symlinks, hardlinks, source repositories, unknown formats, and suspicious content are rejected. Metadata, caches, dependency folders, and build outputs are excluded by default. Scanning uses limited patterns and cannot establish that a file is safe or authorized to share.

`drops/` accepts verified encrypted archives only. The manifest and verification receipt stay local under `.git/dead-drop-receipts/`; keep that receipt to publish the archive.

## Publish

```sh
./scripts/dead-drop check
./scripts/dead-drop publish drops/drop-DATE-RANDOM.7z
```

Replace the placeholder with the prepared archive's actual name. Enter its saved password to repeat verification, review the manifest, encryption flags, destination, branch, and Git diff, then type **`PUBLISH`** to approve the commit and push.

Publication requires enabled hooks, an empty index, a clean tracked working tree, and local HEAD matching the existing origin branch. Review and synchronize implementation changes separately. Only the selected encrypted archive is staged; avoid `git add .`. Declining before commit unstages it. If a push fails after commit, inspect Git status and the remote before retrying.

## Download

Open `drops/` on GitHub, select the archive, and choose **Download raw file**. Open it with an approved 7-Zip-compatible extractor and enter the saved archive password. Filenames are also password-protected. Follow the access and software policies of the receiving environment.

A public repository normally needs no GitHub sign-in to download. The archive password is separate from GitHub authentication. GitHub's **Download ZIP** is an unencrypted repository snapshot; any `.7z` inside still requires its own password. Keep passwords in a separately approved password manager or sharing channel.

## Details

```sh
./scripts/dead-drop help
python3 -m unittest discover -s tests -v
```

See [SECURITY.md](SECURITY.md) for the security design, password-handling behavior, and platform limitations. Deleting an archive does not recall copies or remove it from public history.

## License

The tool and its documentation are available under the [MIT license](LICENSE). You may use, modify, and redistribute them while retaining the copyright and license notices. Transfer payloads in `drops/` are not covered by this software license; their own permissions and terms apply.
