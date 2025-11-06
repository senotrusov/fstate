## fstate: A Deterministic File State Scanner for Informed Synchronization

A lightweight, deterministic command-line utility for generating a human-readable, **hash-based state summary** of your **Git repositories** and **unversioned data folders** across multiple machines.

---

### 🌟 Why `fstate`? (The Problem & The Solution)

If you work on multiple computers (laptop, desktop, VM) and rely on manual or selective synchronization, you know the pain:

1.  **Slow, Automated Syncing:** Fully automatic sync services are often resource-intensive, slow, and prone to creating conflicts or disasters, especially with large codebases or vast amounts of data.
2.  **Lack of State Visibility:** You often don't know *which* machine has the latest version of a project or dataset without running a full, slow `diff` or a resource-heavy sync service scan. This is especially true for folders containing things like **photos, video, datasets, or experimental output** that are not tracked by Git.

`fstate` solves this by giving you **state at a glance**:

The tool generates a single, deterministic **state summary** (`fstate` output) for any set of directories. By comparing the tiny `fstate` output files from different computers, you can instantly determine:

*   **Project Inventory and Mapping:** You get a full, quick list of every Git repository and data folder present. Comparing the outputs from two machines immediately shows you **which projects/folders are missing** on one machine entirely, serving as a rapid inventory audit.
*   **Project Status (Git Repos):** Which machine has a dirty Git repository (`!`) or unpushed commits (`=`). This is a quick way to audit the sync status of all your checked-out projects.
*   **Data Integrity (Data Buckets):** Which data folders (e.g., photo archives, unversioned research data) are out of sync (different `BUCKET_HASH`).
*   **The Source of Truth:** The hashes communicate the current state of your files. You immediately know which computer holds the most current files, allowing you to execute a fast, predictable, one-way sync (e.g., using `rsync`) instead of a full, two-way, conflict-prone operation.

### 🚀 Features

*   **Deterministic Hashing:** Uses `xxh3` for high-speed, non-cryptographic, 16-character hashes for both file contents and overall directory states.
*   **Git Repository Analysis:** Differentiates between clean, unpushed, and dirty states, providing the branch, commit hash, and upstream URL.
*   **Directory "Buckets":** Handles unversioned data folders by creating a file manifest (`.fstate`) and calculating a hash over that manifest.
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

### 💡 Usage

The simplest way to run `fstate` is to scan the current directory:

```bash
fstate
```

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

**2. Excluding Directories and Files**

Use the `-e` flag to exclude paths. Patterns can be anchored with a leading `/` or match any path component (like `.gitignore`).

```bash
# Exclude all 'temp' directories and files that contain 'cache'
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

| Field | Description | Clean (` ` / `=`) | Dirty (`!`) |
| :--- | :--- | :--- | :--- |
| **`git`** | Entity type indicator. | | |
| **`<S>`** | **Status.** ` ` (Clean, Pushed), `=` (Clean, Unpushed), `!` (Dirty, Uncommitted Changes). | HEAD pushed state. | `!` if any staged, unstaged, or untracked file exists. |
| **`<HASH>`** | **Summary Hash.** | First 16 chars of the HEAD commit SHA-1. | 16-char XXH3 hash of all changed files/content. |
| **`<TIMESTAMP>`** | **Modification Time.** | Commit time of HEAD. | Most recent mtime of any changed file. |
| **`<BRANCH>`** | Short name of the current branch. | | |
| **`<PATH>`** | Path relative to the **Common Root**. | | |
| **`<UPSTREAM_URL>`** | URL of the configured upstream remote. | | |

**Example Git Output:**

```
git ! 0f498c89b27a3c3d 2025-11-05T02:01:00.123Z main app1/backend https://github.com/user/app1
dir 1b676f44a30e8c4f 2025-11-05T03:30:00.000Z app1/images
```

#### Directory Bucket Line (`dir`)

Generated for non-Git directories that contain files or an existing `.fstate` file.

| Field | Description |
| :--- | :--- |
| **`dir`** | Entity type indicator. |
| **`<BUCKET_HASH>`** | 16-char XXH3 hash of the calculated `.fstate` file content. |
| **`<TIMESTAMP>`** | Most recent mtime of any file within this bucket's scope. |
| **`<PATH>`** | Path relative to the **Common Root**. |

**Example Bucket Output:**

```
dir 1b676f44a30e8c4f 2025-11-05T03:30:00.000Z documents/photos-2024
```

---
### ⚙️ Bitrot & State File Management

By default, `fstate` writes the calculated file manifest to a file named **`.fstate`** in the bucket's root directory.

| Flag | Behavior |
| :--- | :--- |
| **(Default)** | If `.fstate` exists, perform bitrot check. If clean, overwrite `.fstate`. |
| **`--nostate`** | **Do not** write or modify `.fstate` or `.fstate-after-bitrot` files. Run purely as a scanner. |
| **`--nobitrot`** | Ignore bitrot check. If `.fstate` exists, unconditionally overwrite it with the new state. |

**Bitrot Detection Logic:**

Bitrot is detected only when a file's **modification timestamp (mtime) remains the same**, but its **XXH3 content hash has changed** compared to the hash recorded in the existing `.fstate`.

*   **If Bitrot Detected:** A warning is printed to `stderr`, and the new state is written to **`.fstate-after-bitrot`** instead of overwriting `.fstate`. The user must manually inspect the situation and resolve the bitrot before promoting `.fstate-after-bitrot` to `.fstate`.
