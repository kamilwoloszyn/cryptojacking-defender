package tshark

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
)

//Client Tshark is used for decrypt captured pcap files.
type Tshark struct {
	sslKeysPath string
}

func New(
	sslKeyPath string,
) *Tshark {
	return &Tshark{
		sslKeysPath: sslKeyPath,
	}
}

func (t *Tshark) Decrypt(pcapLocation string) error {
	log.Printf("tshark -r %s -o 'tls.keylog_file: %s' -Px -Y http", pcapLocation, t.sslKeysPath)
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("tshark -r %s -o \"tls.keylog_file: %s\" -Px -Y tls", pcapLocation, t.sslKeysPath))
	tsharkData, err := cmd.Output()
	if err != nil {
		return err
	}
	if len(tsharkData) == 0 {
		return errors.New("no data found")
	}
	log.Printf("Ok, got data: %s", tsharkData)
	return nil
}
