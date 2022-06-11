package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type DataProcessor interface {
	ProcessTrainingData() (float64, error)
	Estimate(string) ([]string, error)
	PrintStatistic([]domain.TsTrainingData, []string)
}
