package temp

import (
	"os/exec"
)

// CreateTempDir and returns its name
func CreateTempDir() (string, error) {
	cmd := exec.Command("mktemp")
	tmpDirPath, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(tmpDirPath), err
}
