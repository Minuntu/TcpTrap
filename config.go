package TcpTrap

type Config struct {
	Pcap struct {
		Location string
	}
	Hosts map[string]Host
}

type Host struct {
	Pcap   string
	Listen string
	Target Target
	SSL    struct {
		Enabled    bool
		CommonName string `yaml:"cn"`
		Issuer     string `yaml:"issuer"`
		Org        string `yaml:"org"`
	}
}

type Target struct {
	Host string
	SSL  struct {
		Enabled bool
		Verify  bool
	}
}
