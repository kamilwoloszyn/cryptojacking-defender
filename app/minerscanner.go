package app

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MinerScanner interface {
	Scan(t *domain.Traffic) int
}
