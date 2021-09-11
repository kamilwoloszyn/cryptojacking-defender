package models

import (
	"sync"

	"github.com/kamilwoloszyn/cryptojacking-defender/config"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/dataprocessor"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/minerscan"
	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/tstraining"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/wordlist"
)

const (
	WordlistPath = "/static/wordlist.txt"
)

// AppModules contains initialization modules, other modules that cannot be save in this struct has separate methods.
type AppModules struct {
	wordlist      *wordlist.WordList
	minerscanner  *minerscan.MinerScanner
	dataProcessor *dataprocessor.DataProcessor
}

func InitializeModules(cfg *config.Config, wg *sync.WaitGroup) (AppModules, error) {
	wordList, err := wordlist.ParseFromFile(cfg.ProjectRootPath + WordlistPath)
	if err != nil {
		return AppModules{}, err
	}
	dataProcessor, err := dataprocessor.New(cfg.ProjectRootPath + cfg.TrainingCSVPath)
	if err != nil {
		return AppModules{}, err
	}
	minerScanner := minerscan.New(wordList)

	return AppModules{
		wordlist:      wordList,
		dataProcessor: dataProcessor,
		minerscanner:  minerScanner,
	}, nil
}

func (a *AppModules) WordList() *wordlist.WordList {
	return a.wordlist
}

func (a *AppModules) DataProcessor() *dataprocessor.DataProcessor {
	return a.dataProcessor
}

func (a *AppModules) MinnerScanner() *minerscan.MinerScanner {
	return a.minerscanner
}

func (a *AppModules) ParseTrafficFromJSONFile(jsonFileAbsPath string) ([]traffic.Traffic, error) {
	return traffic.ParseFromJSONFile(jsonFileAbsPath)
}

func (a *AppModules) GenerateTrafficStatistcs(traffic *[]traffic.Traffic) ([]packetflow.TrafficStatistic, error) {
	return packetflow.Generate(traffic, a.minerscanner)
}

func (a *AppModules) GenerateTrainingData(trafficStats *[]packetflow.TrafficStatistic) []tstraining.TsTrainingData {
	return tstraining.Extract(trafficStats)
}

func (a *AppModules) SaveTrainingData(data []tstraining.TsTrainingData, absPath string) error {
	return tstraining.SaveAsCSV(data, absPath)
}

func (a *AppModules) ReadFromCSV(absPath string, containsHeader bool) ([]tstraining.TsTrainingData, error) {
	return tstraining.ReadFromCSV(absPath, containsHeader)
}
