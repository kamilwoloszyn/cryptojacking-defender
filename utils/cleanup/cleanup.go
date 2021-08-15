package cleanup

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// RemoveAsRoot force removes files with sudo command. It uses shell script.
func RemoveAsRoot(pathes ...string) {
	for _, p := range pathes {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sudo rm -f %s", p))
		if err := cmd.Run(); err != nil {
			log.Printf("[WARNING]: Cannot delete %s : %s", p, err)
		}
	}
}

// RemoveAsCurrentUser removes files without extra permissions.
func RemoveAsCurrentUser(pathes ...string) {
	for _, p := range pathes {
		if err := os.Remove(p); err != nil {
			log.Printf("[WARNING]: Cannot delete %s : %s", p, err)
		}
	}
}
