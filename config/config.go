package config

type Config struct {
	NetworkInterface   string `env:"NETWORK_INTERFACE" envDefault:"enp6s0"`
	TcpDumpFilePath    string `env:"TCPDUMP_ROOT_PATH" envDefault:"/tmp/traffic.pcap"`
	BrowserSSLFilePath string `env:"BROWSER_SSL_FILE_PATH" envDefault:"/tmp/keys.txt"`
}
