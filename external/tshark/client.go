package tshark

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/pkg/errors"
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
	cmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("tshark -r %s -o \"tls.keylog_file: %s\" -Y tls -Px -T json -e ip.src -e ip.dst -e tls.record.content_type -e data-text-lines -e tls.record.content_type -e frame.number -e frame.len -e frame.time -e frame.time_relative -e text", pcapLocation, t.sslKeysPath))
	data, _ := cmd.Output()
	// if err != nil {
	// 	return fmt.Errorf("%s caused a following error: %s", cmd.String(), err)
	// }
	if err := save(data, decrypedPathJSON); err != nil {
		return err
	}
	return nil
}

func save(data []byte, filePath string) error {
	if filePath == "" {
		return errors.New("empty path file")
	}
	err := os.WriteFile(filePath, data, 0777)
	if err != nil {
		return err
	}
	return nil
}
