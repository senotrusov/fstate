## fstate: a lightweight inventory of your files, projects, and folders

`fstate` is a lightweight, deterministic command-line utility for generating a human-readable, hash-based summary of your Git repositories and unversioned data folders. Its goal is simple: to describe your filesystem in a single, deterministic text file, a plain-text inventory that captures the exact state of your projects and data.

If you use multiple computers, like a laptop, desktop, or virtual machine, it can be tricky to keep everything in sync. By comparing (`diff`-ing) fstate summaries between computers, you can instantly see:

*   Which projects or folders exist on one machine but not another
*   Which Git repositories have uncommitted or unpushed changes
*   Which unversioned data folders (for example, photos, research data, archives) have changed, gone out of sync, or even suffered bit rot

With this visibility, you can immediately determine which computer holds the most current files. From there, you can perform standard Git operations to commit and push/pull changes, and for unversioned data, perform a fast, predictable one-way sync (for example, using `rsync`). You can also copy projects across machines if you notice that one computer has them while another does not.

All of this helps you manage your files across multiple machines without relying on automated n-way synchronization tools, which often come with their own set of problems.

### ✨ Example output

A clean repository with a **single commit ready to push**, a dirty repository with **uncommitted changes**, and a directory containing **photos**, all shown together in one output:

```
git + fc11021421e20e19 2025-05-09T11:09:12.000Z project-a
      main +1 https://github.com/user/project-a.git
git ! 0f498c89b27a3c3d 2025-11-05T02:01:00.123Z project-c
      main https://github.com/user/project-c.git
dir   060dd8f97cf4da23 2025-11-09T22:41:31.139Z photos
```

### 🚀 Features

*   **Git Repository Analysis:** Summarizes the state of any Git repository in two concise lines, showing its status (clean, ahead, dirty, or error), commit or content hash, last modification time, and relative path on the first line, followed by branch relationships, ahead/behind counts, and the remote URL on the second.
*   **Directory buckets:** For non-versioned folders, `fstate` uses a simple heuristic to group directories into meaningful “buckets,” working with or without user-provided hints. Each bucket is displayed as a single-line summary. Additionally, `fstate` may maintain a hidden **`.fstate`** file inside the bucket containing a manifest of file paths, hashes, and timestamps.
*   **Nested Entity Exclusion:** Automatically excludes any subdirectory that is itself a Git repository or another `fstate` bucket from its parent's hash calculation, ensuring clean, modular state tracking.
*   **Deterministic Hashing:** Uses `xxh3` for high-speed, non-cryptographic, 16-character hashes for both file contents and overall directory states.
*   **Built-in Bitrot Detection:** Compares the current file mtime and hash against the existing `.fstate` file. If a file's mtime is the *same* but its hash is *different*, it indicates potential bitrot.
*   **Common Root Relativity:** Automatically determines the longest common ancestor path for all input arguments, making output paths universally comparable across machines.

---

### 📦 Installation

Since `fstate` is written in Go, you can easily install it if you have the Go toolchain configured:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/senotrusov/fstate.git
    cd fstate
    ```
2.  **Install the binary:**
    ```bash
    go install
    ```
    *(The `fstate` binary will be placed in your `$GOPATH/bin` or `$GOBIN`)*

### ⚙️ Building for Development

To compile the executable in the current directory for local testing or development:

```bash
go build
```

### 💡 Usage

Running `fstate` without any arguments is equivalent to scanning the current directory (`fstate .`). Paths provided as positional arguments are treated as `--walk` paths.

```bash
# Scan the current directory
fstate

# Scan a specific project and a data folder
fstate ~/code/my-project ~/data/photos

# Scan your home folder while ignoring all dotfiles except .password-store
fstate -e '/.*' -e '!/.password-store' ~
```

#### Options

| Flag | Description |
| :--- | :--- |
| `-a, --add <path>` | Add a path to scan as a bucket or Git repository (can be used multiple times). |
| `-b, --ignorebitrot` | Disable bitrot verification during scans. |
| `-c, --createstate` | Create new `.fstate` files for newly discovered buckets. By default, only existing `.fstate` files are updated. |
| `-d, --aheadbehind` | Show detailed ahead/behind Git status information (e.g., `+1 -2`). By default, only the ahead count is shown. |
| `-e, --exclude <pattern>` | Exclude files matching the given pattern (can be used multiple times). |
| `-o, --output <file>` | Write the output to a file instead of standard output. |
| `-r, --readonly` | Treat `.fstate` files as read-only, preventing any modification or creation. |
| `-s, --statelesswalk <path>` | Create and scan a stateless walk-only bucket (can be used multiple times). |
| `-w, --walk <path>` | Create and scan a walk-only bucket (can be used multiple times). |

#### Examples

**1. Scanning Multiple Project Roots**

When you specify multiple paths, `fstate` automatically calculates the **common root** for all of them and makes all output paths relative to that root. This ensures the output is consistent, regardless of which machine you run it on.

```bash
# On Machine A (where projects are in /home/user/code/)
fstate --add ~/code/app1 --add ~/code/app2 ~/data/archive
# Common root will be '/home/user'.

# On Machine B (where projects are in /mnt/work/code/)
fstate --add /mnt/work/code/app1 --add /mnt/work/code/app2 /mnt/work/archive
# Common root will be '/mnt/work'.
# The relative paths in the output will match Machine A's output.
```

**2. Excluding directories and files**

The `-e` flag lets you exclude files or directories using patterns similar to `.gitignore`. The rules are processed in order, and the **last pattern that matches a path determines its fate**.

Patterns can be specified multiple times. Matching is performed using Go’s `filepath.Match`.

*   **Component Pattern:** If a pattern does not start with `/`, it matches any component (file or directory name) in the path.
    ```bash
    # Exclude all directories named 'node_modules' and all files ending in '.log'
    fstate -e 'node_modules' -e '*.log' .
    ```

*   **Anchored Pattern:** To match only at the root of any of the provided directories, prefix the pattern with `/`.
    ```bash
    # Exclude the 'vendor' directory only at the top level, not 'app/vendor'
    fstate -e /vendor .
    ```

*   **Negative Patterns (Re-inclusion):** You can re-include a file that was excluded by a previous pattern by prefixing the pattern with an exclamation mark (`!`).

    > **Shell/Bash Warning:** The exclamation mark (`!`) is a special character in Bash and other shells that is used for history expansion. To use it as a literal character in a pattern, you **must** enclose the argument in single quotes (`'`) or escape it with a backslash (`\!`).

    ```bash
    # Exclude the entire 'logs' directory...
    # ...but re-include 'important.log' from within it.
    fstate -e '/logs' -e '!/logs/important.log' .

    # Exclude all .tmp files...
    # ...but do not exclude a specific file named 'final.tmp'
    fstate -e '*.tmp' -e '!final.tmp' .
    ```

**3. Generating and Comparing State Files**

The recommended workflow is to output the state to a file on each machine, typically using the machine's hostname for a unique filename:

```bash
# On all machines, run to generate a local state file:
fstate -o "$(uname -n)".fstate ~/projects /data/photos
```

The resulting state files (e.g., `desktop.fstate`, `laptop.fstate`) are small and can be easily shared through various methods, such as network transfer or a Git repository containing your notes.

Once the files are accessible, you can use `diff` to compare the states:

```bash
diff desktop.fstate laptop.fstate
```
The output of the `diff` immediately points to the projects or data buckets that have diverged, and highlights any that only exist on one of the machines.

### 📋 Output Format Specification

The final output is sorted deterministically and printed line-by-line.

#### Git Repository Lines (`git`)

Generated for any directory containing a `.git` folder. The state of a Git repository is always described across two lines.

**First Line: Core State**

| Field | Description | Clean (`<space>` / `+`) | Dirty (`!`) | Error (`X`) |
| :--- | :--- | :--- | :--- | :--- |
| **`git`** | Entity type indicator. | | | |
| **`<STATUS>`** | **Status.** | `<space>`(Up-to-Date with Upstream), `+` (Ahead of Upstream) | `!` (Uncommitted changes) | `X` (Error) |
| **`<HASH>`** | **Summary Hash.** | First 16 chars of the HEAD commit SHA-1. | A 16-character XXH3 hash derived from all changed file contents and paths (staged, unstaged, untracked, and deleted). | A hash of the directory contents. |
| **`<TIMESTAMP>`** | **Modification Time.** | Commit time of HEAD. | The most recent mtime among all changed files. | The most recent mtime of any file. |
| **`<PATH>`** | Path relative to the **Common Root**. | | | |

**Second Line: Branch and Remote Details**

The second line is indented and its components are space-separated.

| Component | Description | Example |
| :--- | :--- | :--- |
| **`<LOCAL_BRANCH>`** | The short name of the current local branch. | `main` |
| `-> <UPSTREAM_BRANCH>` | *(Optional)* Appears if the local branch name is different from its remote tracking branch. `<UPSTREAM_BRANCH>` is the full name of the remote branch. | `dev -> origin/main` |
| **`<AHEAD/BEHIND>`** | By default, only commits ahead (`+A`) are shown. With `--aheadbehind`, both ahead (`+A`) and behind (`-B`) counts are displayed. | `+1` or `+3 -1` |
| **`<UPSTREAM_URL>`** | The URL of the upstream remote. | `https://github.com/user/repo.git` |

**Example Git Outputs:**

A repository that is clean and has one commit to push:
```
git + fc11021421e20e19 2025-05-09T11:09:12.000Z project-a
      main +1 https://github.com/user/project-a.git
```

A repository where the local branch `feature` tracks a different remote branch `origin/main`:
```
git + ab118c89b27a3c3d 2025-11-05T02:01:00.123Z project-b
      feature -> origin/main +3 https://github.com/user/project-b.git
```

A dirty repository with uncommitted changes:
```
git ! 0f498c89b27a3c3d 2025-11-05T02:01:00.123Z project-c
      main https://github.com/user/project-c.git
```

**Special Git statuses and states**

1.  **Repository error (`X` status)**
    The `X` status indicates that a critical Git command has failed, signaling a corrupted or invalid repository. It is reported using the standard two-line format: the first line includes a deterministic bucket-style hash and timestamp, while the second, indented line contains the full error message from the failed command.

    ```
    git X d41d8cd98f00b204 2025-11-06T19:00:00.000Z corrupted-repo
          git status -> exit status 128: fatal: not a git repository (or any of the parent directories): .git
    ```

2.  **Empty repository (`!` status)**
    A newly initialized repository (`git init`) with no commits is considered dirty (`!`). The second line will display the special indicator `[empty]`.

    ```
    git ! f959f63745d10d4b 2025-11-06T11:42:44.837Z new-repo
          [empty]
    ```

#### Directory Bucket Line (`dir`)

A directory is considered a “Bucket” if it contains at least one non-excluded file or if it already has a `.fstate` file (even an empty one).

| Field | Description |
| :--- | :--- |
| **`dir`** | Entity type indicator. |
| **`<STATUS>`** | **Status.** `<space>` (OK), `B` (Bitrot detected). |
| **`<BUCKET_HASH>`** | A 16-char **XXH3 hash** calculated from the *contents* of the in-memory `.fstate` file generated for the current scan. |
| **`<TIMESTAMP>`** | Most recent modification time (`mtime`) of any file within this bucket's scope. |
| **`<PATH>`** | Path relative to the **Common Root**. |

**Example Bucket Output:**

```
dir   1b676f44a30e8c4f 2025-11-05T03:30:00.000Z documents/photos-2024
dir B 8a2d4b9f6c1e0f3a 2025-11-04T11:20:00.000Z research/datasets/set1
```

### 🗃️ Bitrot & State File Management

`fstate` provides granular control over when and how state files (`.fstate`) are written to disk.

| Flag / State | Behavior |
| :--- | :--- |
| **(Default)** | Scans all directories. **Updates** `.fstate` files if they already exist. Does **not create** new ones. |
| **`-c, --createstate`** | **Enables writing for new buckets.** Creates new `.fstate` files for buckets that don't have one, and updates existing ones. |
| **`-r, --readonly`** | **Disables all writing.** Prevents both creation and updates of any `.fstate` or `.fstate-after-bitrot` files. Cannot be used with `-c`. |
| **`-b, --ignorebitrot`** | When writing is enabled, this flag disables the bitrot check and unconditionally overwrites `.fstate` with the new state. |

**Bitrot Detection**

Bitrot is identified when a file’s modification timestamp (mtime) has not changed, but its XXH3 content hash differs from the hash stored in the existing `.fstate` file. When this occurs, the bucket receives a `B` status in the fstate output, a warning is sent to `stderr` with the path of the corrupted file, and the new state is saved to `.fstate-after-bitrot` instead of overwriting `.fstate`. The user must then manually review the issue and resolve the bitrot before replacing `.fstate` with `.fstate-after-bitrot`.
