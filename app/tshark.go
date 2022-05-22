package app

type Tshark interface {
	Decrypt(string, string) error
}
