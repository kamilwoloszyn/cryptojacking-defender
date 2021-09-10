package external

import (
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/chrome"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/tcpdump"
	"github.com/kamilwoloszyn/cryptojacking-defender/external/tshark"
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
