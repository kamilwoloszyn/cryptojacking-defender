package chrome

import (
	"log"
	"os/exec"
)

type Chrome struct {
	SslFile string
}

func New(
	sslFile string,
) *Chrome {
	return &Chrome{
		SslFile: sslFile,
	}
}

func (c *Chrome) RunChrome() error {
	cmd := exec.Command("google-chrome", "--ssl-key-log-file="+c.SslFile)
	if err := cmd.Run(); err != nil {
		log.Fatalf("[FATAL]: Couldn't run browser: %s", err)
	}
	return nil
}
