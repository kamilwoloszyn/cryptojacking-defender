package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type TrafficStatisticGenerator interface {
	Generate(*[]domain.Traffic) ([]domain.TrafficStatistic, error)
	SelectIP([]domain.TrafficStatistic, string) []domain.TrafficStatistic
}
