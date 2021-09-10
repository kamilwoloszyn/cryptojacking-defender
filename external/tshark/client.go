package tshark

import (
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

// Decrypt drcrypt traffic using a keys obtaines from browser and saves file to a specific location.
func (t *Tshark) Decrypt(pcapLocation string, decrypedPathJSON string) error {
	log.Printf("tshark -r %s -o 'tls.keylog_file: %s' -Px -Y http", pcapLocation, t.sslKeysPath)
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("tshark -r %s -o \"tls.keylog_file: %s\" -Y tls -Px -T json -e ip.src -e ip.dst -e tls.record.content_type -e data-text-lines -e tls.record.content_type -e frame.number -e frame.len -e frame.time -e frame.time_relative -e text > %s", pcapLocation, t.sslKeysPath, decrypedPathJSON))
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
