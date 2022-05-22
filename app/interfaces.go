package app

import (
	"context"
	"sync"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

type Chrome interface {
	Run() error
}

type TcpDump interface {
	Capture(context.Context, *sync.WaitGroup)
	FixBrokenPackage(context.Context)
}

type Tshark interface {
	Decrypt(string, string) error
}

type DataProcessor interface {
	Initialize() (float64, error)
	Estimate([]domain.TsTrainingData, []string)
}

type MinerScan interface {
	Scan(t *traffic.Traffic) int
}

type Wordlist interface {
	Extract(string) (*Wordlist, error)
}
