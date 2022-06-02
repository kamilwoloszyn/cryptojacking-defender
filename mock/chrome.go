package mock

type MockedChrome struct {
	RunMock func() error
}

func (m *MockedChrome) Run() error {
	if m.RunMock != nil {
		return m.RunMock()
	}
	return ErrNotMocked
}
