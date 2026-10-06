package version

import (
	"os/exec"
	"strings"
	"sync"
)

var (
	// Version is the semantic release version of DriftWarden.
	Version = "1.0.0"
	// GitCommit is set via ldflags during build or resolved at runtime.
	GitCommit = "dev"
	// BuildDate is the release or build timestamp.
	BuildDate = "2026-10-05"
)

var (
	cachedCommit string
	commitOnce   sync.Once
)

// GetVersion returns the current semantic version.
func GetVersion() string {
	return Version
}

// GetGitCommit returns the git commit hash from build flags or git repo.
func GetGitCommit() string {
	if GitCommit != "" && GitCommit != "dev" && GitCommit != "unknown" {
		return GitCommit
	}
	commitOnce.Do(func() {
		out, err := exec.Command("git", "rev-parse", "HEAD").Output()
		if err == nil {
			cachedCommit = strings.TrimSpace(string(out))
		}
		if cachedCommit == "" {
			cachedCommit = GitCommit
		}
	})
	if cachedCommit != "" {
		return cachedCommit
	}
	return "dev"
}
