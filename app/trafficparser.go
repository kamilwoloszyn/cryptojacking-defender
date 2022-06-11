package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type TrafficParser interface {
	ParseFromJSONFile() ([]domain.Traffic, error)
	ParseFromJSONString(string) ([]domain.Traffic, error)
}
