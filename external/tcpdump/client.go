package tcpdump

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"time"
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

func (tcp *TcpDump) Capture(cCtx context.Context, wg *sync.WaitGroup) {

	tcpRes := make(chan bool, 1)
	wg.Add(1)
	go func(tcpRes chan bool, cCtx context.Context) {
		defer wg.Done()
		cmd := exec.Command("/bin/sh", "-c", "sudo tcpdump -i "+tcp.NetworkInterface+" -w "+tcp.OutputFile)
		if err := cmd.Start(); err != nil {
			log.Fatalf("[FATAL]: Couldn't start capture program:%s", err.Error())
		}
		<-cCtx.Done()
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			log.Println("[INFO]: Cannot interrupt TcpDump, trying do it force ...")
			cmd.Process.Kill()
		}
		if err := tcp.makePermissionForCurrentUser(); err != nil {
			log.Fatalf("[FATAL]: Couldn't set permissions properly")
		}
	}(tcpRes, cCtx)
}

func (tcp *TcpDump) FixBrokenPackage(ctx context.Context) {
	tcpDumpCtx, tcpDumpCancel := context.WithTimeout(ctx, 30*time.Second)
	defer tcpDumpCancel()
	cmd := exec.CommandContext(tcpDumpCtx, "/bin/sh", "-c", fmt.Sprintf("pcapfix %s -o %s ", tcp.OutputFile, tcp.OutputFile))
	if err := cmd.Run(); err != nil {
		log.Printf("[ERROR]: Cannot fix corrupt package: %s", err)
	}
}

func (tcp *TcpDump) makePermissionForCurrentUser() error {
	userName, err := tcp.getUserName()
	if err != nil {
		log.Fatalf("[FATAL]: Cannot get username: %s", err)
	}
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sudo chown %s %s", userName, tcp.OutputFile))
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func (tcp *TcpDump) getUserName() (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return user.Username, nil

}
