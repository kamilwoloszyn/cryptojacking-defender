package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockedTrafficStatisticGenerator struct {
	MockGenerate func(*[]domain.Traffic) ([]domain.TrafficStatistic, error)
	MockSelectIP func([]domain.TrafficStatistic, string) []domain.TrafficStatistic
}

func (m *MockedTrafficStatisticGenerator) Generate(t *[]domain.Traffic) ([]domain.TrafficStatistic, error) {
	if m.MockGenerate != nil {
		return m.MockGenerate(t)
	}
	return []domain.TrafficStatistic{}, ErrNotMocked
}

func (m *MockedTrafficStatisticGenerator) SelectIP(ts []domain.TrafficStatistic, ipToSelect string) []domain.TrafficStatistic {
	if m.MockSelectIP != nil {
		return m.MockSelectIP(ts, ipToSelect)
	}
	return []domain.TrafficStatistic{}
}
