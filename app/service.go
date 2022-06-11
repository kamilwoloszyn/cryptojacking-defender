package app

import (
	"context"
	"sync"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

type Service struct {
	chrome                    Chrome
	tcpdump                   TcpDump
	tshark                    Tshark
	dataProcessor             DataProcessor
	minerScanner              MinerScanner
	dataTrainer               DataTrainer
	trafficParser             TrafficParser
	trafficStatisticGenerator TrafficStatisticGenerator
	wordList                  Wordlist
}

func NewService(
	chrome Chrome,
	tcpdump TcpDump,
	tshark Tshark,
	dataProcessor DataProcessor,
	minerScanner MinerScanner,
	dataTrainer DataTrainer,
	trafficParser TrafficParser,
	trafficStatisticsGenerator TrafficStatisticGenerator,
	wordList Wordlist,
) *Service {
	return &Service{
		chrome:                    chrome,
		tcpdump:                   tcpdump,
		tshark:                    tshark,
		dataProcessor:             dataProcessor,
		minerScanner:              minerScanner,
		dataTrainer:               dataTrainer,
		trafficParser:             trafficParser,
		trafficStatisticGenerator: trafficStatisticsGenerator,
		wordList:                  wordList,
	}
}

func (s *Service) RunChrome() error {
	return s.chrome.RunChrome()
}

func (s *Service) TcpDumpCapture(ctx context.Context, wg *sync.WaitGroup) {
	s.tcpdump.TcpDumpCapture(ctx, wg)
}

func (s *Service) FixBrokenPackage(ctx context.Context) {
	s.tcpdump.FixBrokenPackage(ctx)
}

func (s *Service) ProcessTrainingData() (float64, error) {
	return s.dataProcessor.ProcessTrainingData()
}

func (s *Service) Estimate(testDataPath string) ([]string, error) {
	return s.dataProcessor.Estimate(testDataPath)
}

func (s *Service) PrintStatistic(trafficStats []domain.TsTrainingData, resultLabels []string) {
	s.dataProcessor.PrintStatistic(trafficStats, resultLabels)
}

func (s *Service) Scan(t *domain.Traffic) int {
	return s.minerScanner.Scan(t)
}

func (s *Service) Generate(traffic *[]domain.Traffic) ([]domain.TrafficStatistic, error) {
	return s.trafficStatisticGenerator.Generate(traffic)
}

func (s *Service) SelectIP(ts []domain.TrafficStatistic, ipToSelect string) []domain.TrafficStatistic {
	return s.trafficStatisticGenerator.SelectIP(ts, ipToSelect)
}

func (s *Service) ParseFromJSONFile() ([]domain.Traffic, error) {
	return s.trafficParser.ParseFromJSONFile()
}

func (s *Service) ParseFromJSONString(JSONStr string) ([]domain.Traffic, error) {
	return s.trafficParser.ParseFromJSONString(JSONStr)
}

func (s *Service) Extract(trafficStats *[]domain.TrafficStatistic) []domain.TsTrainingData {
	return s.dataTrainer.Extract(trafficStats)
}

func (s *Service) SaveAsJSON(data *[]domain.TsTrainingData, absPath string) error {
	return s.dataTrainer.SaveAsJSON(data, absPath)
}

func (s *Service) LoadFromJSON(absPath string) ([]domain.TsTrainingData, error) {
	return s.dataTrainer.LoadFromJSON(absPath)
}

func (s *Service) SaveAsCSV(data []domain.TsTrainingData, absPath string) error {
	return s.dataTrainer.SaveAsCSV(data, absPath)
}

func (s *Service) ReadFromCSV() ([]domain.TsTrainingData, error) {
	return s.dataTrainer.ReadFromCSV()
}

func (s *Service) ParseFromFile() (*wordlist.WordListResponse, error) {
	return s.wordList.ParseFromFile()
}
