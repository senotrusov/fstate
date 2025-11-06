// main.go
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/xxh3"
)

const (
	fstateFile       = ".fstate"
	fstateBitrotFile = ".fstate-after-bitrot"
	iso8601Format    = "2006-01-02T15:04:05.000Z"
	gitDir           = ".git"
	hashLength       = 16
)

// debugEnabled is a package-level variable to control debug logging.
var debugEnabled bool

// debugf prints formatted debug messages to stderr if the -debug flag is enabled.
func debugf(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("DEBUG: "+format, v...)
	}
}

// stringSliceFlag is a custom flag type to handle multiple occurrences of a string flag.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Config stores the application's configuration from command-line arguments.
type Config struct {
	InputPaths    []string
	OutputFile    string
	Excludes      []string
	NoFstateWrite bool
	IgnoreBitrot  bool
	CommonRoot    string
}

// Entity represents an item on the filesystem to be processed (either a Git repo or a Bucket).
type Entity interface {
	Process(cfg *Config) error
	Print(writer io.Writer, commonRoot string)
	GetPath() string
	GetChildren() []Entity
	AddChild(child Entity)
}

// FileState holds the calculated state of a single file for a bucket.
type FileState struct {
	Path      string // Relative to bucket root
	Hash      string
	Timestamp time.Time
}

// Bucket represents a standard directory with files.
type Bucket struct {
	Path       string
	BucketHash string
	Timestamp  time.Time
	Children   []Entity
	files      []FileState
}

// GitRepo represents a Git repository.
type GitRepo struct {
	Path        string
	Status      string
	Hash        string
	Timestamp   time.Time
	Branch      string
	UpstreamURL string
	Children    []Entity
	Error       error // Field to store processing errors
}

// --- Entity Interface Implementations ---

func (b *Bucket) GetPath() string       { return b.Path }
func (b *Bucket) GetChildren() []Entity { return b.Children }
func (b *Bucket) AddChild(child Entity) { b.Children = append(b.Children, child) }

func (g *GitRepo) GetPath() string       { return g.Path }
func (g *GitRepo) GetChildren() []Entity { return g.Children }
func (g *GitRepo) AddChild(child Entity) { g.Children = append(g.Children, child) }

// --- Main Program Logic ---

func main() {
	// 1. Configure and parse flags
	cfg := &Config{}
	var excludes stringSliceFlag
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file path (default: stdout)")
	flag.Var(&excludes, "e", "Exclude pattern (can be specified multiple times)")
	flag.BoolVar(&cfg.NoFstateWrite, "nostate", false, "Prevent writing/modifying .fstate files")
	flag.BoolVar(&cfg.IgnoreBitrot, "nobitrot", false, "Disable bitrot detection logic")
	flag.BoolVar(&debugEnabled, "debug", false, "Enable debug logging output to stderr")

	flag.Parse()
	cfg.Excludes = excludes

	// Initialize the logger to not show date/time prefixes for debug output
	log.SetFlags(0)

	// 2. Determine input paths
	cfg.InputPaths = flag.Args()
	if len(cfg.InputPaths) == 0 {
		cfg.InputPaths = []string{"."}
	}

	// 3. Calculate common root
	var err error
	cfg.CommonRoot, err = getCommonRoot(cfg.InputPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating common root: %v\n", err)
		os.Exit(1)
	}

	// Log the final configuration if debug is enabled
	debugf("Configuration complete: %+v", *cfg)

	// 4. Discover all entities (explicit and implicit)
	entities, err := findEntities(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning directories: %v\n", err)
		os.Exit(1)
	}

	// 5. Process each entity in the tree
	for _, entity := range entities {
		if err := processEntityRecursive(entity, cfg); err != nil {
			// This block should now only be hit by critical, non-recoverable errors
			// since GitRepo.Process() will no longer return errors for git failures.
			fmt.Fprintf(os.Stderr, "Error processing path %s: %v\n", entity.GetPath(), err)
			os.Exit(1)
		}
	}

	// 6. Print the results
	if err := printResults(entities, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}
}

// getCommonRoot calculates the longest common ancestor path from a list of paths.
func getCommonRoot(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("cannot find common root of empty path list")
	}

	absPaths := make([]string, len(paths))
	for i, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("could not get absolute path for %s: %w", p, err)
		}
		absPaths[i] = abs
	}

	if len(absPaths) == 1 {
		// For a single path, the root is the path itself.
		info, err := os.Stat(absPaths[0])
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return filepath.Dir(absPaths[0]), nil
		}
		return absPaths[0], nil
	}

	// Algorithm: Start with the first path and chop off parts until it's a prefix of all other paths.
	commonRoot := absPaths[0]
	for _, p := range absPaths[1:] {
		for !strings.HasPrefix(p, commonRoot+string(os.PathSeparator)) && commonRoot != "/" && commonRoot != "" {
			parent := filepath.Dir(commonRoot)
			if parent == commonRoot { // Reached the top (e.g., "/" or "C:\")
				break
			}
			commonRoot = parent
		}
	}

	return commonRoot, nil
}

// findEntities walks the input paths to discover all explicit and implicit entities in a single pass.
func findEntities(cfg *Config) ([]Entity, error) {
	var gitRepos []string
	var explicitBuckets []string
	dirsWithFiles := make(map[string]bool)

	// Step 1: Walk the entire file tree once to gather all facts.
	for _, path := range cfg.InputPaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		err = filepath.WalkDir(absPath, func(currentPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if isExcluded(currentPath, cfg.CommonRoot, cfg.Excludes) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				if hasDirEntry(currentPath, gitDir) {
					gitRepos = append(gitRepos, currentPath)
					return filepath.SkipDir // Git repos are terminal; don't look inside.
				}
				if hasDirEntry(currentPath, fstateFile) {
					explicitBuckets = append(explicitBuckets, currentPath)
				}
			} else {
				// It's a file, so its parent is a candidate for an implicit bucket.
				dirsWithFiles[filepath.Dir(currentPath)] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking %s: %w", path, err)
		}
	}

	// Step 2: Build the initial entity list and a map of "claimed" space.
	var finalEntities []Entity
	claimedPaths := make(map[string]bool)

	for _, path := range gitRepos {
		finalEntities = append(finalEntities, &GitRepo{Path: path})
		claimedPaths[path] = true
	}
	for _, path := range explicitBuckets {
		finalEntities = append(finalEntities, &Bucket{Path: path})
		claimedPaths[path] = true
	}

	// Step 3: Find the highest-level implicit buckets.
	// Sort candidate paths to process parents before children.
	var candidatePaths []string
	for path := range dirsWithFiles {
		candidatePaths = append(candidatePaths, path)
	}
	sort.Strings(candidatePaths)

	for _, path := range candidatePaths {
		isClaimed := false
		// Check if this path or any of its parents are already claimed.
		tempPath := path
		for {
			if claimedPaths[tempPath] {
				isClaimed = true
				break
			}
			parent := filepath.Dir(tempPath)
			if parent == tempPath {
				break
			}
			tempPath = parent
		}

		if !isClaimed {
			finalEntities = append(finalEntities, &Bucket{Path: path})
			claimedPaths[path] = true // This new bucket now claims its space.
		}
	}

	// Step 4: Build the parent-child relationships for the final list.
	sort.Slice(finalEntities, func(i, j int) bool {
		return len(finalEntities[i].GetPath()) < len(finalEntities[j].GetPath())
	})

	var rootEntities []Entity
	for _, entity := range finalEntities {
		parent := findParentEntity(rootEntities, entity.GetPath())
		if parent != nil {
			parent.AddChild(entity)
		} else {
			rootEntities = append(rootEntities, entity)
		}
	}

	return rootEntities, nil
}

// processEntityRecursive processes the given entity and all its children.
func processEntityRecursive(entity Entity, cfg *Config) error {
	if err := entity.Process(cfg); err != nil {
		return err
	}
	// Sort children by path for deterministic processing and output
	sort.Slice(entity.GetChildren(), func(i, j int) bool {
		return entity.GetChildren()[i].GetPath() < entity.GetChildren()[j].GetPath()
	})
	for _, child := range entity.GetChildren() {
		if err := processEntityRecursive(child, cfg); err != nil {
			return err
		}
	}
	return nil
}

// printResults writes the final output to the configured destination.
func printResults(entities []Entity, cfg *Config) error {
	var writer io.Writer = os.Stdout
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		writer = f
	}

	// Sort root entities for deterministic output
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].GetPath() < entities[j].GetPath()
	})

	for _, entity := range entities {
		printEntityRecursive(writer, entity, cfg.CommonRoot)
	}
	return nil
}

func printEntityRecursive(writer io.Writer, entity Entity, commonRoot string) {
	entity.Print(writer, commonRoot)
	for _, child := range entity.GetChildren() {
		printEntityRecursive(writer, child, commonRoot)
	}
}

// --- Bucket Processing ---

func (b *Bucket) Process(cfg *Config) error {
	var files []FileState
	var latestModTime time.Time
	nestedEntityPaths := make(map[string]bool)
	for _, child := range b.Children {
		nestedEntityPaths[child.GetPath()] = true
	}

	err := filepath.WalkDir(b.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == b.Path {
			return nil // Skip the root directory itself
		}

		// Check for nested entities to exclude their contents
		if nestedEntityPaths[path] {
			return filepath.SkipDir
		}

		if isExcluded(path, cfg.CommonRoot, cfg.Excludes) {
			// Log ignored paths within a bucket
			debugf("Excluding path within bucket '%s': %s", b.Path, path)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil // Continue walking
		}

		// Don't include the state file itself in its own state
		if filepath.Base(path) == fstateFile || filepath.Base(path) == fstateBitrotFile {
			return nil
		}

		relPath, err := filepath.Rel(b.Path, path)
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		modTime := info.ModTime()

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hash := fmt.Sprintf("%016x", xxh3.Hash(content))

		files = append(files, FileState{
			Path:      relPath,
			Hash:      hash,
			Timestamp: modTime,
		})

		if modTime.After(latestModTime) {
			latestModTime = modTime
		}
		return nil
	})

	if err != nil {
		return err
	}

	hasFstate := hasDirEntry(b.Path, fstateFile)

	// A directory is only a bucket if it contains actual files or an explicit .fstate file.
	if len(files) == 0 && !hasFstate {
		b.BucketHash = "" // Mark as non-bucket to be skipped during printing
		return nil
	}

	// Sort files by path for deterministic .fstate content
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	b.files = files
	b.Timestamp = latestModTime

	// Generate the content for the .fstate file
	var fstateContent strings.Builder
	for _, f := range b.files {
		fmt.Fprintf(&fstateContent, "%s %s %s\n", f.Hash, formatTimestamp(f.Timestamp), f.Path)
	}
	fstateString := fstateContent.String()
	b.BucketHash = fmt.Sprintf("%016x", xxh3.HashString(fstateString))

	if cfg.NoFstateWrite {
		return nil
	}

	// Bitrot detection logic
	existingFstatePath := filepath.Join(b.Path, fstateFile)
	if _, err := os.Stat(existingFstatePath); err == nil && !cfg.IgnoreBitrot {
		bitrotDetected, err := checkBitrot(existingFstatePath, b.files)
		if err != nil {
			return fmt.Errorf("failed to check for bitrot in %s: %w", existingFstatePath, err)
		}
		if bitrotDetected {
			fmt.Fprintf(os.Stderr, "warning: bitrot detected in bucket %s. Writing new state to %s\n", b.Path, fstateBitrotFile)
			bitrotFilePath := filepath.Join(b.Path, fstateBitrotFile)
			return atomicWrite(bitrotFilePath, []byte(fstateString))
		}
	}

	// Default action: write to .fstate
	return atomicWrite(existingFstatePath, []byte(fstateString))
}

func (b *Bucket) Print(writer io.Writer, commonRoot string) {
	// Don't print if it resolved to not being a bucket (e.g., empty dir)
	if b.BucketHash == "" {
		return
	}
	relPath, err := filepath.Rel(commonRoot, b.Path)
	if err != nil {
		relPath = b.Path // Fallback
	}
	if relPath == "." && commonRoot == b.Path {
		// Special case for when the single input is the current directory
		relPath = ""
	}

	fmt.Fprintf(writer, "dir   %s %s %s\n", b.BucketHash, formatTimestamp(b.Timestamp), relPath)
}

func checkBitrot(fstatePath string, currentFiles []FileState) (bool, error) {
	existingContent, err := os.ReadFile(fstatePath)
	if err != nil {
		return false, err
	}

	existingState := make(map[string]FileState)
	scanner := bufio.NewScanner(bytes.NewReader(existingContent))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " ", 3)
		if len(parts) != 3 {
			continue
		}
		ts, err := time.Parse(iso8601Format, parts[1])
		if err != nil {
			continue // Malformed line
		}
		existingState[parts[2]] = FileState{Hash: parts[0], Timestamp: ts, Path: parts[2]}
	}

	for _, currentFile := range currentFiles {
		if oldFile, ok := existingState[currentFile.Path]; ok {
			// Bitrot condition: same mtime, different hash
			if oldFile.Timestamp.Equal(currentFile.Timestamp) && oldFile.Hash != currentFile.Hash {
				return true, nil
			}
		}
	}
	return false, nil
}

// --- Git Repo Processing ---

// Process gathers all state for a GitRepo. If any git command fails, it sets
// the status to 'X', stores the error, and returns nil to allow the program to
// continue processing other entities.
func (g *GitRepo) Process(cfg *Config) error {
	// Centralized error handler for this function
	handleGitError := func(err error) error {
		g.Status = "X"
		g.Hash = "0000000000000000"
		g.Timestamp = time.Time{}
		g.Error = err
		return nil // Return nil to signal that the error has been handled locally
	}

	// IsDirty, StatusChanges, LatestModTime
	dirty, changes, modTime, err := gitGetStatus(g.Path)
	if err != nil {
		return handleGitError(fmt.Errorf("git status failed: %w", err))
	}

	var isEmptyRepo bool
	g.Branch, err = gitExec(g.Path, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		// A common reason for failure is an empty repository (no commits yet).
		// In this case, 'HEAD' does not exist. We check the error message to confirm.
		if strings.Contains(err.Error(), "unknown revision or path not in the working tree") ||
			strings.Contains(err.Error(), "ambiguous argument 'HEAD'") {
			isEmptyRepo = true
			g.Branch = "[empty]"
		} else {
			return handleGitError(fmt.Errorf("could not get branch: %w", err))
		}
	}

	// This is a best-effort call; failure to get the upstream URL is not a critical error
	// that should mark the repository as errored ('X').
	g.UpstreamURL, _ = gitGetUpstreamURL(g.Path, g.Branch)

	// A repo is "clean" only if it's not dirty and not empty.
	if !dirty && !isEmptyRepo {
		g.Hash, err = gitExec(g.Path, "rev-parse", "HEAD")
		if err != nil {
			return handleGitError(fmt.Errorf("could not get HEAD commit hash: %w", err))
		}
		g.Hash = g.Hash[:hashLength]

		commitTimeUnix, err := gitExec(g.Path, "log", "-1", "--format=%ct")
		if err != nil {
			return handleGitError(fmt.Errorf("could not get commit timestamp: %w", err))
		}
		var commitTimeSec int64
		fmt.Sscanf(commitTimeUnix, "%d", &commitTimeSec)
		g.Timestamp = time.Unix(commitTimeSec, 0)

		unpushed, err := gitIsUnpushed(g.Path)
		if err != nil {
			// If checking the push status fails, we can't be sure, but it's safer
			// to not mark the whole repo as errored. We will just proceed as if it's pushed.
			debugf("Could not check unpushed status for %s: %v", g.Path, err)
			unpushed = false
		}
		if unpushed {
			g.Status = "="
		} else {
			g.Status = " "
		}

	} else {
		g.Status = "!"
		g.Timestamp = modTime

		// Sort changes by path for deterministic hashing
		sort.Slice(changes, func(i, j int) bool {
			return changes[i].path < changes[j].path
		})

		var dirtyContent strings.Builder
		for _, change := range changes {
			fullPath := filepath.Join(g.Path, change.path)

			// A status containing 'D' indicates a deletion.
			if strings.Contains(change.status, "D") {
				// For deleted items, we only hash the fact of their deletion.
				fmt.Fprintf(&dirtyContent, "%s %s\n", change.status, change.path)
				continue
			}

			// For any other change, check if it's a file or a directory.
			info, err := os.Stat(fullPath)
			if err != nil {
				// If path doesn't exist (e.g., deleted after status) or is inaccessible,
				// we must still record this state for a deterministic hash.
				fmt.Fprintf(&dirtyContent, "%s %s ERROR:%s\n", change.status, change.path, err.Error())
				continue
			}

			if info.IsDir() {
				// Hash the entire directory's contents deterministically.
				dirHash, err := hashDirectory(fullPath)
				if err != nil {
					// If hashing fails, record the error for a deterministic hash.
					fmt.Fprintf(&dirtyContent, "%s %s TYPE:DIR ERROR:%s\n", change.status, change.path, err.Error())
				} else {
					fmt.Fprintf(&dirtyContent, "%s %s %s\n", change.status, change.path, dirHash)
				}
			} else {
				// It's a file. Now we read its content to include in the hash.
				// This restores the essential content-hashing logic.
				content, err := os.ReadFile(fullPath)
				if err != nil {
					// Handle cases where the file is unreadable.
					fmt.Fprintf(&dirtyContent, "%s %s ERROR:%s\n", change.status, change.path, err.Error())
					continue
				}
				fmt.Fprintf(&dirtyContent, "%s %s\n", change.status, change.path)
				dirtyContent.Write(content)
			}
		}
		g.Hash = fmt.Sprintf("%016x", xxh3.HashString(dirtyContent.String()))
	}
	return nil
}

func (g *GitRepo) Print(writer io.Writer, commonRoot string) {
	relPath, err := filepath.Rel(commonRoot, g.Path)
	if err != nil {
		relPath = g.Path // Fallback
	}
	if relPath == "." && commonRoot == g.Path {
		relPath = ""
	}

	// Handle the error state print format
	if g.Status == "X" {
		// Sanitize the error message for single-line output
		errorMsg := "unknown error"
		if g.Error != nil {
			errorMsg = strings.ReplaceAll(g.Error.Error(), "\n", " ")
		}
		fmt.Fprintf(writer, "git %s %s %s %s <%s>\n", g.Status, g.Hash, formatTimestamp(g.Timestamp), relPath, errorMsg)
		return
	}

	branchInfo := g.Branch

	if g.UpstreamURL != "" {
		branchInfo = fmt.Sprintf("%s %s", g.Branch, g.UpstreamURL)
	}

	fmt.Fprintf(writer, "git %s %s %s %s <%s>\n", g.Status, g.Hash, formatTimestamp(g.Timestamp), relPath, branchInfo)
}

type gitChange struct {
	status string
	path   string
}

func gitGetStatus(repoPath string) (isDirty bool, changes []gitChange, latestModTime time.Time, err error) {
	output, err := gitExec(repoPath, "status", "--porcelain")
	if err != nil {
		return false, nil, time.Time{}, err
	}
	if len(output) == 0 {
		return false, nil, time.Time{}, nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		// Keep the original 2-character status for a more accurate hash.
		status := line[:2]
		path := line[3:]

		changes = append(changes, gitChange{status: status, path: path})

		// For deleted files, we don't have an mtime.
		// The status for a file deleted from the index is " D".
		if !strings.Contains(status, "D") {
			fullPath := filepath.Join(repoPath, path)
			info, err := os.Stat(fullPath)
			if err != nil {
				// Ignore errors, file might be gone after status check.
				continue
			}

			var currentModTime time.Time
			if info.IsDir() {
				// Walk the directory to find the latest mtime of any file inside.
				currentModTime, err = getLatestModTimeInDir(fullPath)
				if err != nil {
					// If we can't walk the dir, fall back to the dir's own mtime.
					currentModTime = info.ModTime()
				}
			} else {
				// It's a file.
				currentModTime = info.ModTime()
			}

			if currentModTime.After(latestModTime) {
				latestModTime = currentModTime
			}
		}
	}
	return true, changes, latestModTime, nil
}

func gitGetUpstreamURL(repoPath, branchName string) (string, error) {
	remoteName, err := gitExec(repoPath, "config", "--get", fmt.Sprintf("branch.%s.remote", branchName))
	if err != nil || remoteName == "" {
		return "", errors.New("no remote configured for branch")
	}

	remoteURL, err := gitExec(repoPath, "config", "--get", fmt.Sprintf("remote.%s.url", remoteName))
	if err != nil {
		return "", fmt.Errorf("could not get URL for remote '%s'", remoteName)
	}
	return remoteURL, nil
}

func gitIsUnpushed(repoPath string) (bool, error) {
	// Check if an upstream branch is configured
	_, err := gitExec(repoPath, "rev-parse", "@{u}")
	if err != nil {
		// Fails if no upstream is configured, which is not a critical error.
		return false, nil
	}

	// Get local and remote HEADs
	localHead, err := gitExec(repoPath, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}
	remoteHead, err := gitExec(repoPath, "rev-parse", "@{u}")
	if err != nil {
		return false, err
	}

	// If they are different, there are unpushed/unpulled changes.
	// We only care about unpushed, so we check if the upstream is an ancestor of local.
	if localHead == remoteHead {
		return false, nil
	}

	mergeBase, err := gitExec(repoPath, "merge-base", "HEAD", "@{u}")
	if err != nil {
		return false, err
	}

	// If the merge base is the remote head, then local is ahead.
	return mergeBase == remoteHead, nil
}

func gitExec(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Create a concise, single-line error message
		errMsg := fmt.Sprintf("git %s -> %s: %s", strings.Join(args, " "), err, stderr.String())
		return "", errors.New(strings.TrimSpace(errMsg))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// --- Utility Functions ---

// hashDirectory calculates a single hash for an entire directory structure.
// It walks the directory, hashing file contents and relative paths in a deterministic order.
func hashDirectory(rootPath string) (string, error) {
	fileHashes := make(map[string]string)
	var paths []string // To sort the keys of the map

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			relPath, err := filepath.Rel(rootPath, path)
			if err != nil {
				return err
			}

			content, err := os.ReadFile(path)
			if err != nil {
				// Hash the error message to make it deterministic if a file becomes unreadable.
				fileHashes[relPath] = fmt.Sprintf("ERROR:%s", err.Error())
			} else {
				fileHashes[relPath] = fmt.Sprintf("%016x", xxh3.Hash(content))
			}
			paths = append(paths, relPath)
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	// Sort paths for deterministic order
	sort.Strings(paths)

	// Create a single string buffer to hash
	var contentToHash strings.Builder
	for _, path := range paths {
		fmt.Fprintf(&contentToHash, "%s %s\n", fileHashes[path], path)
	}

	finalHash := fmt.Sprintf("%016x", xxh3.HashString(contentToHash.String()))
	return finalHash, nil
}

// getLatestModTimeInDir walks a directory and returns the most recent modification time
// of any file or subdirectory within it.
func getLatestModTimeInDir(rootPath string) (time.Time, error) {
	var latestTime time.Time
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			// Can happen if file is deleted during the walk, just skip it.
			return nil
		}
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
		}
		return nil
	})
	return latestTime, err
}

// formatTimestamp converts a time.Time to the required ISO 8601 format.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(iso8601Format)
}

// isExcluded checks if a path matches any of the exclusion patterns.
func isExcluded(path, commonRoot string, patterns []string) bool {
	relPath, err := filepath.Rel(commonRoot, path)
	if err != nil {
		relPath = path // Fallback
	}

	components := strings.Split(relPath, string(os.PathSeparator))

	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "/") {
			// Anchored pattern
			match, _ := filepath.Match(strings.TrimPrefix(pattern, "/"), relPath)
			if match {
				return true
			}
		} else {
			// Component pattern
			for _, component := range components {
				match, _ := filepath.Match(pattern, component)
				if match {
					return true
				}
			}
		}
	}
	return false
}

// hasDirEntry checks for the existence of a file or directory in a given path without walking.
func hasDirEntry(path, name string) bool {
	entryPath := filepath.Join(path, name)
	if _, err := os.Stat(entryPath); err == nil {
		return true
	}
	return false
}

// atomicWrite writes data to a file atomically by using a temporary file and renaming.
func atomicWrite(filename string, data []byte) error {
	tempFile, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name()) // Clean up temp file on error

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempFile.Name(), filename)
}

// findParentEntity traverses the entity tree to find the direct parent of a given path.
func findParentEntity(roots []Entity, path string) Entity {
	var bestMatch Entity
	for _, root := range roots {
		p := findParentRecursive(root, path)
		if p != nil {
			if bestMatch == nil || len(p.GetPath()) > len(bestMatch.GetPath()) {
				bestMatch = p
			}
		}
	}
	return bestMatch
}

func findParentRecursive(current Entity, path string) Entity {
	// Check if 'current' is a direct or indirect parent of 'path'
	if strings.HasPrefix(path, current.GetPath()+string(os.PathSeparator)) {
		// It's a potential parent. Check if any of its children are a better (more specific) parent.
		var bestChildMatch Entity
		for _, child := range current.GetChildren() {
			p := findParentRecursive(child, path)
			if p != nil {
				// This should always be a more specific path if it's a match
				bestChildMatch = p
				break
			}
		}
		if bestChildMatch != nil {
			return bestChildMatch
		}
		// No child is a more specific parent, so 'current' is the direct parent.
		return current
	}
	return nil
}
