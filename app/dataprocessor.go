package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type DataProcessor interface {
	Initialize() (float64, error)
	Estimate() ([]string, error)
	PrintStatistic([]domain.TsTrainingData, []string)
}
