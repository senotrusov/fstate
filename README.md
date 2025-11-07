## fstate: The simple way to see what’s out of sync between your machines.

A lightweight, deterministic command-line utility for generating a human-readable, **hash-based state summary** of your **Git repositories** and **unversioned data folders** across multiple machines.

---

### 🌟 Why `fstate`? (The Problem & The Solution)

If you work on multiple computers (laptop, desktop, VM) and rely on manual or automatic synchronization, you know the pain:

1.  **Slow, Automated Syncing:** Fully automatic sync services are often resource-intensive, slow, and prone to creating conflicts or disasters, especially with large codebases or vast amounts of data.
2. **Lack of State Visibility:** You often don't know *which* machine has the latest version of a project or dataset, or even whether a specific project or data directory exists on it at all. This is especially true for folders containing things like **photos, video, datasets, or experimental output** that are not tracked by Git.

`fstate` solves this by giving you **state at a glance**:

The tool generates a single, deterministic **state summary** (`fstate` output) for any set of directories. By comparing the tiny `fstate` output files from different computers, you can instantly determine:

*   **Project Inventory and Mapping:** You get a full, quick list of every Git repository and data folder present. Comparing the outputs from two machines immediately shows you **which projects/folders are missing** on one machine entirely, serving as a rapid inventory audit.
*   **Project Status (Git Repos):** Which machine has a dirty Git repository (`!`) or unpushed commits (`=`). This is a quick way to audit the sync status of all your checked-out projects.
*   **Data Integrity (Data Buckets):** Which data folders (e.g., photo archives, unversioned research data) are out of sync (different `BUCKET_HASH`).
*   **The Source of Truth:** The hashes communicate the current state of your files. You immediately know which computer holds the most current files, allowing you to execute a fast, predictable, one-way sync (e.g., using `rsync`) instead of a full, two-way, conflict-prone operation.

### 🚀 Features

*   **Deterministic Hashing:** Uses `xxh3` for high-speed, non-cryptographic, 16-character hashes for both file contents and overall directory states.
*   **Git Repository Analysis:** Differentiates between clean, unpushed, and dirty states, providing the branch, commit hash, and upstream URL.
*   **Directory "Buckets":** For non-versioned folders, `fstate` scans and creates a file manifest with each file’s path, hash, and timestamp, stored in a hidden **`.fstate`** file inside the folder. The `BUCKET_HASH` reflects this manifest’s state. You can easily compare two `.fstate` files (e.g., from desktop and laptop) with `diff` to see added, removed, or changed files.
*   **Built-in Bitrot Detection:** Compares the current file mtime and hash against the existing `.fstate` file. If a file's mtime is the *same* but its hash is *different*, it indicates potential bitrot and writes the new state to a separate `.fstate-after-bitrot` file.
*   **Nested Entity Exclusion:** Automatically excludes any subdirectory that is itself a Git repository or another `fstate` bucket from its parent's hash calculation, ensuring clean, modular state tracking.
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

The simplest way to run `fstate` is to scan the current directory:

```bash
fstate
```

#### Options

| Flag | Description |
| :--- | :--- |
| `-o <file>` | Write output to the specified file path (default: stdout). |
| `-e <pattern>` | Exclude pattern (can be specified multiple times). |
| `-w` | Write `.fstate` files. Creates `.fstate` for new buckets and updates existing ones. |
| `-nostate` | Do not write or modify any `.fstate` files. Overrides default behavior of updating existing files. Cannot be used with `-w`. |
| `-nobitrot` | Disable the bitrot detection logic. |

#### Examples

**1. Scanning Multiple Project Roots**

When you specify multiple paths, `fstate` automatically calculates the **common root** for all of them and makes all output paths relative to that root. This ensures the output is consistent, regardless of which machine you run it on.

```bash
# On Machine A (where projects are in /home/user/code/)
fstate ~/code/app1 ~/code/app2 ~/data/archive
# Common root will be '/home/foo'.

# On Machine B (where projects are in /mnt/work/code/)
fstate /mnt/work/code/app1 /mnt/work/code/app2 /mnt/work/archive
# Common root will be '/mnt/work'.
# The relative paths in the output will match Machine A's output.
```

**2. Excluding directories and files**

The `-e` flag lets you exclude specific files or directories from a scan. Exclusion patterns can either match any path component or be anchored to the **common root** by starting with `/`. The matching behavior is implemented using Go’s `filepath.Match`.

```bash
# Exclude all 'temp' directories and any files containing 'cache'
fstate -e temp -e '*cache*' .

# Exclude only the 'vendor' directory at the root of the scan
fstate -e /vendor .
```

**3. Generating and Comparing State Files**

The recommended workflow is to output the state to a file on each machine, typically using the machine's hostname for a unique filename:

```bash
# On all machines, run to generate a local state file:
fstate -o "$(uname -n)".fstate ~/projects /data/photos
```

The resulting state files (e.g., `desktop.fstate`, `laptop.fstate`) are small and can be easily exchanged via any method:

*   **Network File Share** (NFS, Samba)
*   **Transfer tools** (scp, rsync)
*   **Git-controlled Notes** or a dedicated sync folder

Once the files are accessible, you can use `diff` to compare the states:

```bash
diff desktop.fstate laptop.fstate
```
The output of the `diff` immediately points to the projects or data buckets that have diverged, and highlights any that only exist on one of the machines.

### 📋 Output Format Specification

The final output is sorted deterministically and printed line-by-line.

#### Git Repository Line (`git`)

Generated for any directory containing a `.git` folder.

| Field | Description | Clean (`<space>` / `=`) | Dirty (`!`) |
| :--- | :--- | :--- | :--- |
| **`git`** | Entity type indicator. | | |
| **`<STATUS>`** | **Status.** | `<space>`(Up-to-Date with Upstream), `=` (Ahead of Upstream) | `!` (Uncommitted changes) |
| **`<HASH>`** | **Summary Hash.** | First 16 chars of the HEAD commit SHA-1. | A 16-character XXH3 hash derived from all changed file contents and paths (staged, unstaged, untracked, and deleted). |
| **`<TIMESTAMP>`** | **Modification Time.** | Commit time of HEAD. | The most recent modification time (`mtime`) among all changed files. |
| **`<PATH>`** | Path relative to the **Common Root**. | | |
| **`<BRANCH>`** | Short name of the current branch. | | |
| **`<UPSTREAM_URL>`** | URL of the configured upstream remote. | | |

**Example Git Output:**

```
git ! 0f498c89b27a3c3d 2025-11-05T02:01:00.123Z app1/backend <main https://github.com/user/app1>
dir   1b676f44a30e8c4f 2025-11-05T03:30:00.000Z app1/images
```

**Special Git statuses and states**

`fstate` recognizes two special Git repository cases to provide complete state visibility:

1. **Repository error (`X` status)**
   The `X` status means a critical Git command (like `git status` or `git rev-parse`) failed in this directory. This usually indicates the directory is not a valid Git repository, is corrupted, or has insufficient permissions.

   * **Hash/timestamp:** Set to a deterministic bucket-style hash/timestamp if possible.
   * **Branch field:** Contains the full error message for diagnostics.

2. **Empty repository (`!` status with `<[empty]>` branch)**
   A newly initialized repository (`git init`) with no commits yet shows a dirty status (`!`) because it is in an incomplete state, and **HEAD** does not exist.

   * **Hash/timestamp:** Calculated from any existing unstaged changes, or set to a bucket-style hash/timestamp if no files exist.
   * **Branch field:** Replaced with the special indicator `<[empty]>`.


#### Directory Bucket Line (`dir`)

A directory is considered a “Bucket” if it contains at least one non-excluded file or if it already has a `.fstate` file (even an empty one).

| Field | Description |
| :--- | :--- |
| **`dir`** | Entity type indicator. |
| **`<BUCKET_HASH>`** | A 16-char **XXH3 hash** calculated from the *contents* of the in-memory `.fstate` file generated for the current scan. |
| **`<TIMESTAMP>`** | Most recent modification time (`mtime`) of any file within this bucket's scope. |
| **`<PATH>`** | Path relative to the **Common Root**. |

**Example Bucket Output:**

```
dir   1b676f44a30e8c4f 2025-11-05T03:30:00.000Z documents/photos-2024
```

---

### 🗃️ Bitrot & State File Management

By default, `fstate` runs in a "read-only" mode for new directories. It will scan all directories and report their state, but will only *update* existing `.fstate` files. It will **not** create new `.fstate` files unless explicitly told to.

| Flag / State | Behavior |
| :--- | :--- |
| **(Default)** | Scans all directories. **Updates** `.fstate` files if they already exist. Does **not create** new ones. |
| **`-w`** | **Enables writing.** Creates new `.fstate` files for buckets that don't have one, and updates existing ones. |
| **`-nostate`** | **Disables all writing.** Prevents both creation and updates of any `.fstate` or `.fstate-after-bitrot` files. Cannot be used with `-w`. |
| **`-nobitrot`** | When writing is enabled (either by default or with `-w`), this flag disables the bitrot check and unconditionally overwrites `.fstate` with the new state. |

**Bitrot Detection**

Bitrot is identified when a file’s modification timestamp (mtime) has not changed, but its XXH3 content hash differs from the hash stored in the existing `.fstate` file. When this occurs, a warning is sent to stderr, and the new state is saved to `.fstate-after-bitrot` instead of overwriting `.fstate`. The user must then manually review the issue and resolve the bitrot before replacing `.fstate` with `.fstate-after-bitrot`.
