package mock

type MockedTshark struct {
	MockDecrypt func(string, string) error
}

func (m *MockedTshark) Decrypt(pcapLocation string, decryptedPathJSON string) error {
	if m.MockDecrypt != nil {
		return m.MockDecrypt(pcapLocation, decryptedPathJSON)
	}
	return ErrNotMocked
}
