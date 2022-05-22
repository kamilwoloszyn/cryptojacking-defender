package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type DataTrainer interface {
	Extract(*[]domain.TrafficStatistic) []domain.TsTrainingData
	SaveAsJSON(*[]domain.TsTrainingData, string) error
	LoadFromJSON(string) ([]domain.TsTrainingData, error)
	SaveAsCSV([]domain.TsTrainingData, string) error
	ReadFromCSV() ([]domain.TsTrainingData, error)
}
