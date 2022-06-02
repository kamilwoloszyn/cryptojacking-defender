package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockedMinerScanner struct {
	MockScan func(*domain.Traffic) int
}

func (m *MockedMinerScanner) Scan(t *domain.Traffic) int {
	if m.MockScan != nil {
		return m.MockScan(t)
	}
	return 0
}
