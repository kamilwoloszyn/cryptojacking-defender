package analyzer

type IPAddr string

type TrafficInfo struct {
	From         IPAddr
	To           IPAddr
	Protocol     string
	UnmaskedData string
}

func NewTraffic() *[]TrafficInfo {
	return &[]TrafficInfo{}
}

func (t *TrafficInfo) ParseFile(absPath string) error {
	return nil
}
