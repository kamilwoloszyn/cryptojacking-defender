package app

import (
	"sync"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/dataprocessor"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/minerscan"
	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/app/packet-flow"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/tstraining"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
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
	dataProcessor, err := dataprocessor.New(cfg.ProjectRootPath + cfg.TrainingCSVPathRelative)
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

func (a *AppModules) GenerateTrafficStatistcs(traffic *[]traffic.Traffic) ([]domain.TrafficStatistic, error) {
	return packetflow.Generate(traffic, a.minerscanner)
}

func (a *AppModules) GenerateTrainingData(trafficStats *[]domain.TrafficStatistic) []domain.TsTrainingData {
	return tstraining.Extract(trafficStats)
}

func (a *AppModules) SaveTrainingData(data []domain.TsTrainingData, absPath string, containsIP, isForPrediction bool) error {
	return tstraining.SaveAsCSV(data, absPath, containsIP, isForPrediction)
}

func (a *AppModules) ReadFromCSV(absPath string, containsHeader bool) ([]domain.TsTrainingData, error) {
	return tstraining.ReadFromCSV(absPath, containsHeader)
}
