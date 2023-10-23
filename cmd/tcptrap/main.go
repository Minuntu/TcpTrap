package main

import (
	"github.com/LeakIX/TcpTrap"
	"gopkg.in/yaml.v2"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configFile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	var config TcpTrap.Config
	err = yaml.NewDecoder(configFile).Decode(&config)
	if err != nil {
		panic(err)
	}
	var proxies []*TcpTrap.Proxy

	for _, host := range config.Hosts {
		pcapFile, err := os.Create(host.Pcap)
		if err != nil {
			panic(err)
		}
		proxy, err := TcpTrap.NewProxy(pcapFile, host)
		if err != nil {
			panic(err)
		}
		proxies = append(proxies, proxy)
	}
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	for _, proxy := range proxies {
		proxy.Shutdown()
	}
}
