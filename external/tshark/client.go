package tshark

import (
	"fmt"
	"log"
	"os/exec"
)

//Client Tshark is used for decrypt captured pcap files.
type Tshark struct {
	SslKeysPath string
}

func New(
	sslKeyPath string,
) *Tshark {
	return &Tshark{
		SslKeysPath: sslKeyPath,
	}
}

func (t *Tshark) Decrypt(pcapLocation string) {
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("tshark -r %s -o \"ssl.keylog_file: %s\" -Px -Y http", pcapLocation, t.SslKeysPath))
	tsharkData, err := cmd.Output()
	if err != nil {
		log.Fatalf("[FATAL]: Cannot open decryption program: %s", err)
	}
	log.Printf("Ok, got data: %d", len(tsharkData))
}
