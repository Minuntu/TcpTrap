package TcpTrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"math/big"
	"net"
	"time"
)

type Proxy struct {
	Listener     net.Listener
	Host         Host
	SourceHost   string
	SourcePort   string
	TargetHost   string
	TargetPort   string
	packetWriter *pcapgo.Writer
	PcapFile     io.WriteCloser
	PacketChan   chan Packet
}

func NewProxy(pcapFile io.WriteCloser, host Host) (*Proxy, error) {
	sourceHost, sourcePort, err := net.SplitHostPort(host.Listen)
	if err != nil {
		return nil, err
	}
	targetHost, targetPort, err := net.SplitHostPort(host.Target.Host)
	if err != nil {
		return nil, err
	}
	// LinkTypeIPv4
	pw := pcapgo.NewWriter(pcapFile)
	pw.WriteFileHeader(65536, layers.LinkTypeIPv4)
	if err != nil {
		return nil, err
	}
	proxy := &Proxy{
		SourceHost:   sourceHost,
		SourcePort:   sourcePort,
		TargetHost:   targetHost,
		TargetPort:   targetPort,
		Host:         host,
		packetWriter: pw,
		PcapFile:     pcapFile,
		PacketChan:   make(chan Packet, 1024),
	}
	go proxy.startPacketWriter()
	go proxy.Listen()
	return proxy, nil
}

func (p *Proxy) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	p.PacketChan <- Packet{
		CaptureInfo: ci,
		Data:        data,
	}
	return nil
}

func (p *Proxy) startPacketWriter() {
	// I exist as a buffer because pcapgo packet writer is not thread safe
	for {
		packet, open := <-p.PacketChan
		if !open {
			return
		}
		err := p.packetWriter.WritePacket(packet.CaptureInfo, packet.Data)
		if err != nil {
			panic(err)
		}
	}
}

func (p *Proxy) Listen() {
	var err error
	if p.Host.SSL.Enabled {
		p.Listener, err = tls.Listen("tcp", net.JoinHostPort(p.SourceHost, p.SourcePort), &tls.Config{
			Certificates: []tls.Certificate{p.SelfSignedCert()},
		})
	} else {
		p.Listener, err = net.Listen("tcp", net.JoinHostPort(p.SourceHost, p.SourcePort))
	}

	if err != nil {
		panic(err)
	}
	for {
		conn, err := p.Listener.Accept()
		if err != nil {
			log.Println(err)
			break
		}
		go HandleConnection(p, conn)
	}
}

func (p *Proxy) Shutdown() {
	p.Listener.Close()
	for {
		if len(p.PacketChan) == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	p.PcapFile.Close()
}

func (p *Proxy) SelfSignedCert() tls.Certificate {
	if p.Host.SSL.CommonName == "" {
		p.Host.SSL.CommonName = "secure.example.com"
	}
	if p.Host.SSL.Org == "" {
		p.Host.SSL.Org = "ACME Inc."
	}
	if p.Host.SSL.Issuer == "" {
		p.Host.SSL.Issuer = "ACME Inc."
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	//priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	randMax := new(big.Int)
	randMax.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(randMax, big.NewInt(1))
	randomSerial, _ := rand.Int(rand.Reader, randMax)
	cert := x509.Certificate{
		SerialNumber: randomSerial,
		Issuer: pkix.Name{
			Organization: []string{p.Host.SSL.Issuer},
		},
		Subject: pkix.Name{
			CommonName:   p.Host.SSL.CommonName,
			Organization: []string{p.Host.SSL.Org},
		},
		NotBefore:             time.Now().Add(time.Hour * -(24 * 123)),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	newCert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	parsedCert, err := x509.ParseCertificate(newCert)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{parsedCert.Raw},
		PrivateKey:  priv,
		Leaf:        parsedCert,
	}
}

type Packet struct {
	CaptureInfo gopacket.CaptureInfo
	Data        []byte
}
