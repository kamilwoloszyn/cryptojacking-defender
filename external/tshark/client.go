package tshark

type Tshark struct {
	SslKeysPath string
}

func (t *Tshark) Decrypt(pcapLocation string) {
	//cmd := exec.Command("/bin/sh", "-c", "tshark ")
}
