package main

import (
	"context"
	"log"
	"sync"

	"github.com/caarlos0/env"
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/chrome"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/tcpdump"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/tshark"
	"github.com/kamilwoloszyn/cryptojacking-defender/utils/cleanup"
)

func main() {
	var (
		wg sync.WaitGroup
	)
	ctx := context.Background()
	cfg := config.Config{}

	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("[FATAL]: Cannot parse config: %s. Unexpected behavior may occur.", err)
	}
	log.Println("[INFO]: Config loaded succesfully")
	tcpDumpCtx, cancelTcpDump := context.WithCancel(ctx)
	tcpDump := tcpdump.New(cfg.NetworkInterface, cfg.TcpDumpFilePath)
	log.Println("[INFO]: Starting capturing ...\n [WARNING]: Password may be required for sudo")
	tcpDump.Capture(tcpDumpCtx, &wg)
	log.Println("[INFO]: Waiting for a browser .. ")
	chromeBrowser := chrome.New(cfg.BrowserSSLFilePath)
	if err := chromeBrowser.Run(); err != nil {
		log.Fatalf("[FATAL]: Couldn't run chrome browser: %s. Exiting.", err)
	}
	log.Println("[INFO]: Browser closed. Looking for dump program ...")
	cancelTcpDump()
	wg.Wait()
	log.Println("[INFO]: Fixing corrupted package")
	tcpDump.FixBrokenPackage(ctx)
	tsharkClient := tshark.New(cfg.BrowserSSLFilePath)
	log.Println("[INFO]: Decrypting traffic ...")
	tsharkClient.Decrypt(cfg.TcpDumpFilePath)
	//cleanup
	log.Println("[INFO]: Cleaning files ...")
	cleanup.RemoveAsCurrentUser(cfg.BrowserSSLFilePath, cfg.TcpDumpFilePath)

}
