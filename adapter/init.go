package adapter

import (
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/chrome"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/tcpdump"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/tshark"
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
)

type ExternalServices struct {
	chrome  *chrome.Chrome
	tcpdump *tcpdump.TcpDump
	tshark  *tshark.Tshark
}

func Inititalize(cfg *config.Config) ExternalServices {
	chromeClient := chrome.New(cfg.BrowserSSLFilePath)
	tcpdumpClient := tcpdump.New(cfg.NetworkInterface, cfg.TcpDumpFilePath)
	tsharkClient := tshark.New(cfg.BrowserSSLFilePath)
	return ExternalServices{
		chrome:  chromeClient,
		tcpdump: tcpdumpClient,
		tshark:  tsharkClient,
	}
}

func (es *ExternalServices) Chrome() *chrome.Chrome {
	return es.chrome
}

func (es *ExternalServices) TcpDump() *tcpdump.TcpDump {
	return es.tcpdump
}

func (es *ExternalServices) Tshark() *tshark.Tshark {
	return es.tshark
}
