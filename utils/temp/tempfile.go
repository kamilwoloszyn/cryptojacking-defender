package temp

import "os/exec"

// CreateTempFile creates a new plain file and returns its path
func CreateTempFile() (string, error) {
	cmd := exec.Command("tempfile")
	tempPath, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(tempPath), nil
}
