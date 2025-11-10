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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
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
	hashBufferSize   = 128 * 1024 // 128 KiB buffer for hashing files
)

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
	InputPaths         []string
	WalkPaths          []string
	WalkStatelessPaths []string
	OutputFile         string
	Excludes           []string
	Readonly           bool
	CreateState        bool
	IgnoreBitrot       bool
	CommonRoot         string
	AllScanRoots       []string
	AheadBehind        bool
}

// Entity represents an item on the filesystem to be processed (either a Git repo or a Bucket).
type Entity interface {
	Process(cfg *Config) error
	Print(writer io.Writer, commonRoot string, cfg *Config)
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
	Path        string
	BucketHash  string
	Timestamp   time.Time
	Children    []Entity
	files       []FileState
	Status      string
	IsWalkOnly  bool
	IsStateless bool
	IsExplicit  bool
}

// GitRepo represents a Git repository.
type GitRepo struct {
	Path           string
	Status         string
	Hash           string
	Timestamp      time.Time
	Branch         string
	UpstreamURL    string
	UpstreamBranch string
	AheadBehind    string
	Children       []Entity
	Error          error // Field to store processing errors
}

// --- Entity Interface Implementations ---

func (b *Bucket) GetPath() string       { return b.Path }
func (b *Bucket) GetChildren() []Entity { return b.Children }
func (b *Bucket) AddChild(child Entity) { b.Children = append(b.Children, child) }

func (g *GitRepo) GetPath() string       { return g.Path }
func (g *GitRepo) GetChildren() []Entity { return g.Children }
func (g *GitRepo) AddChild(child Entity) { g.Children = append(g.Children, child) }

// --- Main Program Logic ---

// flagDefinition centralizes the definition of a command-line flag.
type flagDefinition struct {
	name      string      // long name, e.g., "add"
	shortName string      // short name, e.g., "a"
	argName   string      // name for the flag's argument in the usage output, e.g., "<path>"
	usage     string      // help text
	valuePtr  interface{} // pointer to the variable that holds the flag's value
}

// setupAndParseFlags configures the command-line flags, sets a custom usage message,
// and parses the flags. It centralizes flag definition to avoid repetition.
func setupAndParseFlags(cfg *Config) {
	var addPaths, excludes, walkPaths, walkStatelessPaths stringSliceFlag

	// Centralized flag definitions provide a single source of truth.
	flagDefs := []flagDefinition{
		{"add", "a", "path", "Add a path to scan as a bucket or Git repository (can be used multiple times).", &addPaths},
		{"aheadbehind", "d", "", "Show detailed ahead/behind Git status information.", &cfg.AheadBehind},
		{"createstate", "c", "", "Create new .fstate files for newly discovered buckets; otherwise update only the existing ones.", &cfg.CreateState},
		{"exclude", "e", "pattern", "Exclude files matching the given pattern (can be used multiple times).", &excludes},
		{"ignorebitrot", "b", "", "Disable bitrot verification during scans.", &cfg.IgnoreBitrot},
		{"output", "o", "file", "Write the output to a file instead of standard output.", &cfg.OutputFile},
		{"readonly", "r", "", "Treat .fstate files as read-only, preventing modification or creation.", &cfg.Readonly},
		{"statelesswalk", "s", "path", "Create and scan a stateless walk-only bucket (can be used multiple times).", &walkStatelessPaths},
		{"walk", "w", "path", "Create and scan a walk-only bucket (can be used multiple times).", &walkPaths},
	}

	// Sort definitions by short name for a consistent, predictable help message.
	sort.Slice(flagDefs, func(i, j int) bool {
		return flagDefs[i].shortName < flagDefs[j].shortName
	})

	// Register all flags from the centralized definitions.
	for _, def := range flagDefs {
		// The flag package requires passing the usage string for each alias.
		definitiveUsage := def.usage
		switch v := def.valuePtr.(type) {
		case *string:
			flag.StringVar(v, def.name, "", definitiveUsage)
			flag.StringVar(v, def.shortName, "", definitiveUsage)
		case *bool:
			flag.BoolVar(v, def.name, false, definitiveUsage)
			flag.BoolVar(v, def.shortName, false, definitiveUsage)
		case flag.Value: // Handles our custom stringSliceFlag
			flag.Var(v, def.name, definitiveUsage)
			flag.Var(v, def.shortName, definitiveUsage)
		default:
			// This indicates a programming error.
			panic(fmt.Sprintf("unsupported flag type for %s", def.name))
		}
	}

	// Define a much simpler, data-driven custom usage message.
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: fstate [flags] [paths...]")
		fmt.Fprintln(flag.CommandLine.Output(), "If paths are provided without a flag, they are treated as --walk arguments.")
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")

		for _, def := range flagDefs {
			// Format names like "-a, --add <path>"
			names := fmt.Sprintf("-%s, --%s", def.shortName, def.name)
			if def.argName != "" {
				names = fmt.Sprintf("%s <%s>", names, def.argName)
			}
			// Adjust padding to accommodate the longest flag string with its argument name
			fmt.Fprintf(flag.CommandLine.Output(), "  %-27s %s\n", names, def.usage)
		}
	}

	flag.Parse()

	// Post-parsing assignments from the temporary slice flags to the config struct.
	cfg.InputPaths = addPaths
	cfg.Excludes = excludes
	cfg.WalkPaths = append(walkPaths, flag.Args()...) // Append positional args
	cfg.WalkStatelessPaths = walkStatelessPaths
}

func main() {
	// 1. Configure and parse flags using the new refactored function.
	cfg := &Config{}
	setupAndParseFlags(cfg)

	if cfg.Readonly && cfg.CreateState {
		fmt.Fprintln(os.Stderr, "Error: cannot use -nostate and -w flags at the same time.")
		os.Exit(1)
	}

	// 2. Determine input paths
	isBareFstate := len(cfg.InputPaths) == 0 && len(cfg.WalkPaths) == 0 && len(cfg.WalkStatelessPaths) == 0
	if isBareFstate {
		// A bare 'fstate' call implies a walk of the current directory.
		cfg.WalkPaths = []string{"."}
	}

	allPathsForRoot := []string{}
	allPathsForRoot = append(allPathsForRoot, cfg.InputPaths...)
	allPathsForRoot = append(allPathsForRoot, cfg.WalkPaths...)
	allPathsForRoot = append(allPathsForRoot, cfg.WalkStatelessPaths...)

	// If after all logic there are still no paths, default to current directory.
	if len(allPathsForRoot) == 0 {
		allPathsForRoot = []string{"."}
	}

	// Store absolute paths of all scan roots for the exclude logic.
	absRoots := make([]string, len(allPathsForRoot))
	for i, p := range allPathsForRoot {
		abs, err := filepath.Abs(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting absolute path for %s: %v\n", p, err)
			os.Exit(1)
		}
		absRoots[i] = abs
	}
	cfg.AllScanRoots = absRoots

	// 3. Calculate common root
	var err error
	cfg.CommonRoot, err = getCommonRoot(allPathsForRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating common root: %v\n", err)
		os.Exit(1)
	}

	// 4. Discover all entities (explicit and implicit)
	entities, err := findEntities(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning directories: %v\n", err)
		os.Exit(1)
	}

	// 5. Setup output writer
	var writer io.Writer = os.Stdout
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	// 6. Process and Print entities recursively
	// Sort root entities for deterministic processing and output
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].GetPath() < entities[j].GetPath()
	})

	for _, entity := range entities {
		if err := processAndPrintRecursive(writer, entity, cfg); err != nil {
			// This will now catch critical, non-recoverable errors.
			// GitRepo processing errors are handled internally and won't be returned here.
			fmt.Fprintf(os.Stderr, "Error processing path %s: %v\n", entity.GetPath(), err)
			os.Exit(1)
		}
	}
}

// processAndPrintRecursive combines the processing and printing steps into a single
// recursive walk. It processes an entity, prints its result immediately, and then
// recursively calls itself for all children.
func processAndPrintRecursive(writer io.Writer, entity Entity, cfg *Config) error {
	// Step 1: Process the current entity (heavy work)
	if err := entity.Process(cfg); err != nil {
		// This error should only be returned for critical failures (e.g., file system errors).
		// Git command failures are handled within GitRepo.Process itself.
		return err
	}

	// Step 2: Print the result of the processed entity immediately
	entity.Print(writer, cfg.CommonRoot, cfg)

	// Step 3: Sort children by path for deterministic processing and output
	sort.Slice(entity.GetChildren(), func(i, j int) bool {
		return entity.GetChildren()[i].GetPath() < entity.GetChildren()[j].GetPath()
	})

	// Step 4: Recurse for each child
	for _, child := range entity.GetChildren() {
		if err := processAndPrintRecursive(writer, child, cfg); err != nil {
			return err
		}
	}
	return nil
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
	var fstateBuckets []string
	dirsWithFiles := make(map[string]bool)

	// Step 1: Walk all argument paths to gather facts about the filesystem.
	allScanRoots := []string{}
	allScanRoots = append(allScanRoots, cfg.InputPaths...)
	allScanRoots = append(allScanRoots, cfg.WalkPaths...)
	allScanRoots = append(allScanRoots, cfg.WalkStatelessPaths...)

	walkSet := make(map[string]struct{})
	for _, p := range allScanRoots {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		walkSet[abs] = struct{}{}
	}

	for path := range walkSet {
		// Only walk directories that exist
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(path, func(currentPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if isExcluded(currentPath, cfg.CommonRoot, cfg.AllScanRoots, cfg.Excludes) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				if hasDirEntry(currentPath, gitDir) {
					gitRepos = append(gitRepos, currentPath)
					return filepath.SkipDir // Git repos are terminal.
				}
				if hasDirEntry(currentPath, fstateFile) {
					fstateBuckets = append(fstateBuckets, currentPath)
				}
			} else {
				dirsWithFiles[filepath.Dir(currentPath)] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking %s: %w", path, err)
		}
	}

	// Step 2: Build the entity list.
	var finalEntities []Entity
	// claimedPaths tracks space consumed by "hard" buckets.
	claimedPaths := make(map[string]bool)
	// entityExists prevents creating two entities for the same path.
	entityExists := make(map[string]bool)

	// Git repos always claim their space.
	for _, path := range gitRepos {
		if entityExists[path] {
			continue
		}
		finalEntities = append(finalEntities, &GitRepo{Path: path})
		claimedPaths[path] = true
		entityExists[path] = true
	}

	// "Hard" buckets from -add flag claim their space.
	for _, path := range cfg.InputPaths {
		absPath, _ := filepath.Abs(path)
		if entityExists[absPath] {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			finalEntities = append(finalEntities, &Bucket{Path: absPath, IsExplicit: true})
			claimedPaths[absPath] = true
			entityExists[absPath] = true
		}
	}

	// Walk-only buckets are added as entities but DO NOT claim space.
	for _, path := range cfg.WalkPaths {
		absPath, _ := filepath.Abs(path)
		if entityExists[absPath] {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			finalEntities = append(finalEntities, &Bucket{Path: absPath, IsWalkOnly: true, IsExplicit: true})
			entityExists[absPath] = true
		}
	}
	for _, path := range cfg.WalkStatelessPaths {
		absPath, _ := filepath.Abs(path)
		if entityExists[absPath] {
			continue
		}
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			finalEntities = append(finalEntities, &Bucket{Path: absPath, IsWalkOnly: true, IsStateless: true, IsExplicit: true})
			entityExists[absPath] = true
		}
	}

	// Buckets with .fstate files claim space, if not already claimed or defined.
	for _, path := range fstateBuckets {
		if entityExists[path] {
			continue
		}
		isClaimed := false
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
			claimedPaths[path] = true
			entityExists[path] = true
		}
	}

	// Implicit buckets from dirs with files can only form in unclaimed space.
	var candidatePaths []string
	for path := range dirsWithFiles {
		candidatePaths = append(candidatePaths, path)
	}
	sort.Strings(candidatePaths)

	for _, path := range candidatePaths {
		if entityExists[path] {
			continue
		}
		isClaimed := false
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
			claimedPaths[path] = true
			entityExists[path] = true
		}
	}

	// Step 3: Build the parent-child relationships for the final list.
	sort.Slice(finalEntities, func(i, j int) bool {
		return len(finalEntities[i].GetPath()) < len(finalEntities[j].GetPath())
	})

	var rootEntities []Entity
	for i, entity := range finalEntities {
		var parent Entity
		// Look for a parent in the entities processed so far.
		for j := 0; j < i; j++ {
			potentialParent := finalEntities[j]
			if strings.HasPrefix(entity.GetPath(), potentialParent.GetPath()+string(os.PathSeparator)) {
				// The best parent is the longest one found so far.
				if parent == nil || len(potentialParent.GetPath()) > len(parent.GetPath()) {
					parent = potentialParent
				}
			}
		}

		if parent != nil {
			parent.AddChild(entity)
		} else {
			rootEntities = append(rootEntities, entity)
		}
	}

	return rootEntities, nil
}

// --- Bucket Processing ---

func (b *Bucket) Process(cfg *Config) error {
	b.Status = " "
	var files []FileState
	var latestModTime time.Time
	var fileFound bool // To track if we found any regular files

	nestedEntityPaths := make(map[string]bool)
	for _, child := range b.Children {
		nestedEntityPaths[child.GetPath()] = true
	}

	// Single walk to gather file info, calculate hashes, and find the latest mtime.
	// Any error returned from this walk is considered fatal and will terminate the program.
	walkErr := filepath.WalkDir(b.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Error from WalkDir itself, e.g., permission error on a directory.
			return err
		}
		if path == b.Path {
			return nil // Skip the root directory itself.
		}

		// Skip nested entities (Git repos or other buckets).
		if nestedEntityPaths[path] {
			return filepath.SkipDir
		}

		if isExcluded(path, cfg.CommonRoot, cfg.AllScanRoots, cfg.Excludes) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// For walk-only buckets, don't descend into subdirectories for file gathering.
		// Any subdirectory that is not a known child entity will be skipped.
		if d.IsDir() {
			if b.IsWalkOnly {
				return filepath.SkipDir
			}
			return nil // For normal buckets, continue walk.
		}

		// We only care about normal files. Ignore symlinks, dirs, pipes, etc.
		if !d.Type().IsRegular() {
			return nil
		}

		// Ignore .fstate files from hash and mtime calculation.
		baseName := filepath.Base(path)
		if baseName == fstateFile || baseName == fstateBitrotFile {
			return nil
		}

		// From here, we have a regular file to process.
		fileFound = true

		// Get FileInfo.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("could not get file info for %s: %w", path, err)
		}

		// Hash the file content.
		hash, err := hashFileChunked(path)
		if err != nil {
			// This covers read errors.
			return fmt.Errorf("could not hash file %s: %w", path, err)
		}

		relPath, err := filepath.Rel(b.Path, path)
		if err != nil {
			// This should not happen if path is inside b.Path.
			return fmt.Errorf("could not get relative path for %s: %w", path, err)
		}

		modTime := info.ModTime()
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

	if walkErr != nil {
		return walkErr // Propagate fatal error to terminate the program.
	}

	hasFstate := hasDirEntry(b.Path, fstateFile)

	// --- Suppression Logic ---
	// Decide upfront if this bucket should be materialized in the output.

	// Rule 1: A stateless walk-only bucket is ONLY materialized if it already has state.
	// The presence of top-level files is irrelevant for this decision.
	if b.IsStateless && !hasFstate {
		b.BucketHash = "" // Suppress printing.
		return nil        // Skip all hash, bitrot, and write logic.
	}

	// Rule 2: An empty walk-only bucket (that is not stateless) is not materialized.
	if b.IsWalkOnly && !fileFound && !hasFstate {
		b.BucketHash = "" // Suppress printing.
		return nil
	}

	// Rule 3: An implicit bucket is only materialized if it has files or state.
	if !b.IsExplicit && !fileFound && !hasFstate {
		b.BucketHash = ""
		return nil
	}

	// --- Materialization Logic ---
	// If we passed the suppression checks, proceed to calculate hash and handle state.
	var fstateString string
	if !fileFound {
		// Case: No regular files, but .fstate exists or it's an explicit empty bucket.
		info, err := os.Stat(b.Path)
		if err != nil {
			return fmt.Errorf("could not stat bucket directory %s for mtime: %w", b.Path, err)
		}
		b.Timestamp = info.ModTime()
		b.BucketHash = fmt.Sprintf("%016x", xxh3.HashString(""))
		fstateString = ""
	} else {
		// Case: Regular files were found.
		b.Timestamp = latestModTime
		sort.Slice(files, func(i, j int) bool {
			return files[i].Path < files[j].Path
		})
		var fstateContent strings.Builder
		for _, f := range files {
			fmt.Fprintf(&fstateContent, "%s %s %s\n", f.Hash, formatTimestamp(f.Timestamp), f.Path)
		}
		fstateString = fstateContent.String()
		b.BucketHash = fmt.Sprintf("%016x", xxh3.HashString(fstateString))
	}
	b.files = files

	// --- Bitrot detection and .fstate writing logic ---
	existingFstatePath := filepath.Join(b.Path, fstateFile)

	if hasFstate && !cfg.IgnoreBitrot {
		bitrottenFiles, err := checkBitrot(existingFstatePath, b.files)
		if err != nil {
			return fmt.Errorf("failed to check for bitrot in %s: %w", existingFstatePath, err)
		}

		if len(bitrottenFiles) > 0 {
			b.Status = "B"
			for _, fileRelPath := range bitrottenFiles {
				fmt.Fprintf(os.Stderr, "bitrot warning: %s\n", filepath.Join(b.Path, fileRelPath))
			}
			if !cfg.Readonly {
				bitrotFilePath := filepath.Join(b.Path, fstateBitrotFile)
				if err := atomicWrite(bitrotFilePath, []byte(fstateString)); err != nil {
					return fmt.Errorf("failed to write bitrot state file for %s: %w", b.Path, err)
				}
			}
			return nil
		}
	}

	if cfg.Readonly {
		return nil
	}

	if cfg.CreateState || hasFstate {
		if err := atomicWrite(existingFstatePath, []byte(fstateString)); err != nil {
			return fmt.Errorf("failed to write state file for %s: %w", b.Path, err)
		}
	}

	return nil
}

func (b *Bucket) Print(writer io.Writer, commonRoot string, cfg *Config) {
	// Don't print if it resolved to not being a bucket (e.g., empty implicit dir)
	if b.BucketHash == "" {
		return
	}
	relPath, err := filepath.Rel(commonRoot, b.Path)
	if err != nil {
		relPath = b.Path // Fallback
	}

	fmt.Fprintf(writer, "dir %s %s %s %s\n", b.Status, b.BucketHash, formatTimestamp(b.Timestamp), relPath)
}

func checkBitrot(fstatePath string, currentFiles []FileState) ([]string, error) {
	existingContent, err := os.ReadFile(fstatePath)
	if err != nil {
		return nil, err
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

	var bitrottenFiles []string
	for _, currentFile := range currentFiles {
		if oldFile, ok := existingState[currentFile.Path]; ok {
			// Truncate both timestamps to millisecond precision for a reliable comparison.
			oldTs := oldFile.Timestamp.Truncate(time.Millisecond)
			newTs := currentFile.Timestamp.Truncate(time.Millisecond)

			// Bitrot condition: same mtime (at millisecond precision), different hash
			if oldTs.Equal(newTs) && oldFile.Hash != currentFile.Hash {
				bitrottenFiles = append(bitrottenFiles, currentFile.Path)
			}
		}
	}

	return bitrottenFiles, nil
}

// --- Git Repo Processing ---

type gitChange struct {
	status string
	path   string
}

type gitStatusInfo struct {
	Branch         string
	UpstreamBranch string
	AheadBehind    string
	IsUnpushed     bool
	IsDirty        bool
	IsEmpty        bool
	Changes        []gitChange
	UpstreamURL    string
}

// Process gathers all state for a GitRepo. If any git command fails, it sets
// the status to 'X', stores the error, and falls back to calculating directory state.
// If the fallback filesystem calculation fails, a critical error is returned to terminate the program.
func (g *GitRepo) Process(cfg *Config) error {
	// Centralized error handler for git commands.
	handleGitError := func(gitErr error) error {
		g.Status = "X"
		g.Error = gitErr // Store the original Git error

		// Fallback to calculating state directly from the filesystem.
		// An error here is fatal for the whole program.
		dirHash, modTime, fsErr := calculateDirectoryState(g.Path)
		if fsErr != nil {
			return fmt.Errorf("filesystem error during git fallback for %s: %w", g.Path, fsErr)
		}

		g.Hash = dirHash
		g.Timestamp = modTime

		return nil // Return nil to signal the git error was handled, allowing program to continue.
	}

	statusInfo, err := gitGetStatus(g.Path)
	if err != nil {
		return handleGitError(fmt.Errorf("git status failed: %w", err))
	}

	g.Branch = statusInfo.Branch
	// If the repository is empty (no commits), override the branch name to '[empty]'
	// to match the specification, regardless of what the initial branch is called (e.g., 'main').
	if statusInfo.IsEmpty {
		g.Branch = "[empty]"
	}
	g.UpstreamURL = statusInfo.UpstreamURL
	g.UpstreamBranch = statusInfo.UpstreamBranch
	g.AheadBehind = statusInfo.AheadBehind

	if !statusInfo.IsDirty && !statusInfo.IsEmpty {
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

		if statusInfo.IsUnpushed {
			g.Status = "+"
		} else {
			g.Status = " "
		}
	} else {
		g.Status = "!"

		if statusInfo.IsEmpty {
			dirHash, latestTime, err := calculateDirectoryState(g.Path)
			if err != nil {
				return fmt.Errorf("could not calculate directory state for empty repo %s: %w", g.Path, err)
			}
			g.Hash = dirHash
			g.Timestamp = latestTime
		} else { // Is dirty
			dirtyHash, modTime, err := calculateDirtyState(g.Path, statusInfo.Changes)
			if err != nil {
				g.Status = "X"
				g.Error = err
				// Fallback to calculating state directly from the filesystem.
				dirHash, modTime, fsErr := calculateDirectoryState(g.Path)
				if fsErr != nil {
					return fmt.Errorf("filesystem error during git fallback for %s: %w", g.Path, fsErr)
				}
				g.Hash = dirHash
				g.Timestamp = modTime
				return nil
			}
			g.Hash = dirtyHash
			g.Timestamp = modTime
		}
	}

	return nil
}

func (g *GitRepo) Print(writer io.Writer, commonRoot string, cfg *Config) {
	relPath, err := filepath.Rel(commonRoot, g.Path)
	if err != nil {
		relPath = g.Path // Fallback
	}

	// Handle the error state print format
	if g.Status == "X" {
		errorMsg := "unknown error"
		if g.Error != nil {
			errorMsg = strings.ReplaceAll(g.Error.Error(), "\n", " ")
		}
		fmt.Fprintf(writer, "git %s %s %s %s\n      %s\n", g.Status, g.Hash, formatTimestamp(g.Timestamp), relPath, errorMsg)
		return
	}

	var branchInfoParts []string
	if g.Branch != "" {
		branchInfoParts = append(branchInfoParts, g.Branch)
	}

	// Handle upstream branch name difference
	if g.UpstreamBranch != "" {
		// e.g., 'origin/main'
		remoteBranchName := g.UpstreamBranch
		if slashIndex := strings.LastIndex(g.UpstreamBranch, "/"); slashIndex != -1 {
			remoteBranchName = g.UpstreamBranch[slashIndex+1:]
		}
		if g.Branch != remoteBranchName && g.Branch != "(detached)" {
			branchInfoParts = append(branchInfoParts, "->", g.UpstreamBranch)
		}
	}

	// Add ahead/behind info
	if g.AheadBehind != "" {
		parts := strings.Fields(g.AheadBehind)
		if len(parts) == 2 {
			if cfg.AheadBehind {
				branchInfoParts = append(branchInfoParts, fmt.Sprintf("%s %s", parts[0], parts[1]))
			} else {
				aheadStr := parts[0]
				ahead, err := strconv.Atoi(strings.TrimPrefix(aheadStr, "+"))
				if err == nil && ahead > 0 {
					branchInfoParts = append(branchInfoParts, aheadStr)
				}
			}
		}
	}

	// Add upstream URL
	if g.UpstreamURL != "" {
		branchInfoParts = append(branchInfoParts, g.UpstreamURL)
	}

	branchInfo := strings.Join(branchInfoParts, " ")
	fmt.Fprintf(writer, "git %s %s %s %s\n      %s\n", g.Status, g.Hash, formatTimestamp(g.Timestamp), relPath, branchInfo)
}

// calculateDirtyState calculates a deterministic hash and finds the latest modification time for the
// set of changes in a dirty Git repository. It only considers regular files for hashing.
// If any file is unreadable or a filesystem error occurs, it returns an error to signal a fallback is needed.
func calculateDirtyState(repoPath string, changes []gitChange) (hash string, latestModTime time.Time, err error) {
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].path < changes[j].path
	})

	hasher := xxh3.New()
	buf := make([]byte, hashBufferSize)
	var hasNonDeletedChange bool

	for _, change := range changes {
		fullPath := filepath.Join(repoPath, change.path)

		if strings.Contains(change.status, "D") {
			fmt.Fprintf(hasher, "%s %s\n", change.status, change.path)
			continue
		}
		hasNonDeletedChange = true

		info, err := os.Stat(fullPath)
		if err != nil {
			// If stat fails, it could be a broken symlink. Use Lstat as a fallback
			// to get info about the symlink itself.
			info, err = os.Lstat(fullPath)
			if err != nil {
				// If Lstat also fails, then we can't get any info, so we error out.
				return "", time.Time{}, fmt.Errorf("could not stat changed path %s: %w", fullPath, err)
			}
		}
		currentModTime := info.ModTime()

		// TODO: Feed hasher with symlink targets?

		if info.Mode().IsRegular() {
			fmt.Fprintf(hasher, "%s %s\n", change.status, change.path)
			file, err := os.Open(fullPath)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("could not open changed file %s: %w", fullPath, err)
			}

			_, copyErr := io.CopyBuffer(hasher, file, buf)
			file.Close()

			if copyErr != nil {
				return "", time.Time{}, fmt.Errorf("could not read changed file %s: %w", fullPath, copyErr)
			}
		}

		if currentModTime.After(latestModTime) {
			latestModTime = currentModTime
		}
	}

	if !hasNonDeletedChange && len(changes) > 0 {
		deletedFileDirs := make(map[string]bool)
		for _, change := range changes {
			dir := filepath.Dir(filepath.Join(repoPath, change.path))
			deletedFileDirs[dir] = true
		}
		for dir := range deletedFileDirs {
			info, err := os.Stat(dir)
			if err == nil && info.ModTime().After(latestModTime) {
				latestModTime = info.ModTime()
			}
		}
	}
	return fmt.Sprintf("%016x", hasher.Sum64()), latestModTime, nil
}

// gitGetStatus uses porcelain v2 to get a comprehensive repo status in one call.
func gitGetStatus(repoPath string) (*gitStatusInfo, error) {
	output, err := gitExec(repoPath, "status", "--porcelain=v2", "--branch", "-z")
	if err != nil {
		return nil, err
	}

	info := &gitStatusInfo{}
	if len(output) == 0 {
		if !hasDirEntry(repoPath, gitDir) {
			return nil, errors.New("not a git repository")
		}
		info.IsEmpty = true
		info.IsDirty = true // An empty, uncommitted repo is considered "dirty"
		return info, nil
	}

	// Records are terminated by a NUL byte.
	// The final record after the split will be empty.
	records := strings.Split(output, "\x00")

	for i := 0; i < len(records)-1; i++ {
		entry := records[i]
		if len(entry) == 0 {
			continue
		}

		switch entry[0] {
		case '#': // Header line
			parts := strings.Fields(entry)
			if len(parts) < 3 {
				continue
			}
			switch parts[1] {
			case "branch.head":
				info.Branch = parts[2] // e.g., "main" or "(detached)"
			case "branch.oid":
				if parts[2] == "(initial)" {
					info.IsEmpty = true
				}
			case "branch.upstream":
				info.UpstreamBranch = parts[2]
			case "branch.ab":
				if len(parts) > 3 {
					info.AheadBehind = fmt.Sprintf("%s %s", parts[2], parts[3])
					ahead, _ := strconv.Atoi(strings.TrimPrefix(parts[2], "+"))
					if ahead > 0 {
						info.IsUnpushed = true
					}
				}
			}
		case '1': // Ordinary changed entry
			info.IsDirty = true
			// 1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
			// Split into 9 parts to isolate the path, which is the 9th part.
			parts := strings.SplitN(entry, " ", 9)
			if len(parts) < 9 {
				continue
			}
			status := parts[1]
			path := parts[8]
			info.Changes = append(info.Changes, gitChange{status: status, path: path})
		case '2': // Renamed or copied entry
			info.IsDirty = true
			// 2 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <X><score> <path>
			// The next record is <origPath>, which we must skip.
			parts := strings.SplitN(entry, " ", 10)
			if len(parts) < 10 {
				continue
			}
			status := parts[1]
			path := parts[9] // This is the new path (<path>)
			info.Changes = append(info.Changes, gitChange{status: status, path: path})
			i++ // IMPORTANT: Advance loop to skip the <origPath> record.
		case 'u': // Unmerged entry
			info.IsDirty = true
			// u <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>
			parts := strings.SplitN(entry, " ", 11)
			if len(parts) < 11 {
				continue
			}
			status := parts[1]
			path := parts[10]
			info.Changes = append(info.Changes, gitChange{status: status, path: path})
		case '?': // Untracked
			info.IsDirty = true
			path := entry[2:]
			info.Changes = append(info.Changes, gitChange{status: "??", path: path})
		}
	}

	if info.Branch != "" && info.Branch != "(detached)" {
		remoteName, err := gitExec(repoPath, "config", "--get", fmt.Sprintf("branch.%s.remote", info.Branch))
		if err == nil && remoteName != "" {
			info.UpstreamURL, _ = gitExec(repoPath, "config", "--get", fmt.Sprintf("remote.%s.url", remoteName))
		}
	}

	return info, nil
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

// calculateDirectoryState walks a directory to calculate a deterministic hash and find the
// most recent modification time in a single pass. It only considers regular files
// and ignores the .git directory. Any filesystem error encountered during this process
// is considered fatal and will be returned, stopping the program.
func calculateDirectoryState(rootPath string) (string, time.Time, error) {
	hasher := xxh3.New()
	var latestModTime time.Time
	var fileCount int
	// Allocate buffer once and reuse it for all file reads in this walk.
	buf := make([]byte, hashBufferSize)

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// This error comes from WalkDir itself (e.g., permissions on a directory).
			return err
		}

		// Skip the .git directory entirely.
		if d.IsDir() && d.Name() == gitDir {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil // Continue walking
		}

		// We only care about normal files. Ignore symlinks, pipes, etc.
		if !d.Type().IsRegular() {
			return nil
		}

		// From here, we have a regular file.
		fileCount++

		info, err := d.Info()
		if err != nil {
			// Failed to get file info (e.g., permissions, race condition)
			return fmt.Errorf("could not get file info for %s: %w", path, err)
		}

		// Update most recent mtime.
		modTime := info.ModTime()
		if modTime.After(latestModTime) {
			latestModTime = modTime
		}

		// Add file path to hash for determinism.
		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return fmt.Errorf("could not get relative path for %s: %w", path, err)
		}
		hasher.WriteString(relPath)

		// Add file content to hash.
		file, err := os.Open(path)
		if err != nil {
			// Failed to open file (e.g., permissions)
			return fmt.Errorf("could not open file %s: %w", path, err)
		}
		defer file.Close()

		if _, err := io.CopyBuffer(hasher, file, buf); err != nil {
			// Failed to read file content.
			return fmt.Errorf("could not read file content from %s: %w", path, err)
		}

		return nil
	})

	if err != nil {
		return "", time.Time{}, err
	}

	// Special case: if there are no files (just a .git dir), get mtime from the root folder itself.
	if fileCount == 0 {
		info, err := os.Stat(rootPath)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("could not stat root directory %s for mtime: %w", rootPath, err)
		}
		latestModTime = info.ModTime()
	}

	hash := fmt.Sprintf("%016x", hasher.Sum64())
	return hash, latestModTime, nil
}

// hashFileChunked calculates the xxh3 hash of a file by reading it in chunks.
// This is memory-efficient for large files.
func hashFileChunked(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := xxh3.New()
	buf := make([]byte, hashBufferSize)
	if _, err := io.CopyBuffer(hasher, file, buf); err != nil {
		return "", err
	}

	hash := fmt.Sprintf("%016x", hasher.Sum64())
	return hash, nil
}

// formatTimestamp converts a time.Time to the required ISO 8601 format.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(iso8601Format)
}

// isExcluded checks if a path should be excluded based on a list of patterns.
// It supports negative patterns (prefixed with '!') to re-include previously
// excluded paths, similar to gitignore rules. The last pattern in the list
// that matches the path determines whether it is excluded or included.
func isExcluded(path string, commonRoot string, allScanRoots []string, patterns []string) bool {
	// A path's exclusion status is determined by the last matching pattern.
	// Default is to be included (not excluded).
	excluded := false

	for _, pattern := range patterns {
		isNegative := strings.HasPrefix(pattern, "!")
		if isNegative {
			pattern = pattern[1:] // Trim '!'
		}

		matchFound := false
		if strings.HasPrefix(pattern, "/") {
			// Anchored pattern: matches against the path relative to one of the scan roots.
			p := strings.TrimPrefix(pattern, "/")
			for _, root := range allScanRoots {
				// Path must be inside or be the same as the current scan root.
				if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
					continue
				}

				relPath, err := filepath.Rel(root, path)
				if err != nil {
					continue // Should not happen if prefix check passed.
				}

				if match, _ := filepath.Match(p, relPath); match {
					// The special path "." should only be matched by an explicit "."
					// pattern, not a wildcard pattern like ".*" that is intended
					// for hidden files.
					if relPath != "." || p == "." {
						matchFound = true
						break // Matched against one root, no need to check others for this pattern.
					}
				}
			}
		} else {
			// Component pattern: matches against any directory/file name component in the path
			// relative to the common root of all scan paths.
			relPath, err := filepath.Rel(commonRoot, path)
			if err != nil {
				relPath = path // Fallback in case of error
			}
			components := strings.Split(relPath, string(os.PathSeparator))
			for _, component := range components {
				// Similarly, the special component "." should only be matched
				// by an explicit "." pattern.
				if component == "." && pattern != "." {
					continue
				}
				if match, _ := filepath.Match(pattern, component); match {
					matchFound = true
					break // A component matched, no need to check others for this pattern
				}
			}
		}

		if matchFound {
			// If it's a negative pattern (!), it's NOT excluded.
			// If it's a positive pattern, it IS excluded.
			// This updates the status based on the latest match.
			excluded = !isNegative
		}
	}

	return excluded
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
