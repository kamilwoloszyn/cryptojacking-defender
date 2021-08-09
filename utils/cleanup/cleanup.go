package cleanup

import (
	"fmt"
	"os/exec"
)

func RemoveAsRoot(path ...string) error {
	for _, p := range path {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sudo rm -f %s", p))
		return cmd.Run()
	}
	return nil
}
