package tcpdump

import (
	"context"
	"log"
	"os"
	"os/exec"
	"sync"
)

type TcpDump struct {
	NetworkInterface string
	OutputFile       string
}

func New(
	networkIntreface string, outputFile string,
) *TcpDump {
	return &TcpDump{
		NetworkInterface: networkIntreface,
		OutputFile:       outputFile,
	}

}

func (tcp *TcpDump) Capture(ctx context.Context, wg *sync.WaitGroup) {
	tcpRes := make(chan bool, 1)
	wg.Add(1)
	go func(tcpRes chan bool, ctx context.Context) {
		cmd := exec.Command("/bin/sh", "-c", "sudo tcpdump -i "+tcp.NetworkInterface+" -w "+tcp.OutputFile)
		if err := cmd.Start(); err != nil {
			log.Fatalf("[FATAL]: Couldn't start capture program:%s", err.Error())
		}
		<-ctx.Done()
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			log.Println("[INFO]: Cannot interrupt TcpDump, trying do it force ...")
			cmd.Process.Kill()
		}
		wg.Done()

	}(tcpRes, ctx)
}
