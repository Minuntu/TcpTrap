package TcpTrap

import (
	"crypto/tls"
	"github.com/charmbracelet/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Connection is a just-enough TCP/IP stack proxy/recorder
// It emulates the transport and network layer for capture
// and can be set as a TLS (re)encryption proxy if configured,
// saving unencrypted data in the capture
type Connection struct {
	proxy        *Proxy
	remoteConn   net.Conn
	backendConn  net.Conn
	remoteSeq    uint32
	remoteAck    uint32
	backendSeq   uint32
	backendAck   uint32
	localAddr    net.Addr
	closing      bool
	readBytes    int64
	writtenBytes int64
	sync.WaitGroup
}

// HandleConnection Creates a connection and start proxying client to backend
func HandleConnection(p *Proxy, conn net.Conn) {
	var err error
	connection := &Connection{
		remoteConn: conn,
		proxy:      p,
	}
	if p.Host.Target.SSL.Enabled {
		connection.backendConn, err = tls.Dial("tcp", net.JoinHostPort(p.TargetHost, p.TargetPort), &tls.Config{InsecureSkipVerify: true})
	} else {
		connection.backendConn, err = net.Dial("tcp", net.JoinHostPort(p.TargetHost, p.TargetPort))
	}
	if err != nil {
		connection.remoteConn.Close()
		return
	}
	if p.Host.Target.PcapUseBackendIp {
		connection.localAddr = connection.backendConn.RemoteAddr()
	} else if ip := net.ParseIP(p.Host.Target.PcapFakeIp); ip != nil {
		port, _ := strconv.Atoi(p.SourcePort)
		connection.localAddr = &net.TCPAddr{
			IP:   ip,
			Port: port,
		}
	} else {
		connection.localAddr = connection.remoteConn.LocalAddr()
	}

	log.Info("opening connection", "remote_addr", conn.RemoteAddr(), "backend_addr", connection.backendConn.RemoteAddr())
	connection.fakeTCPHandshake()
	connection.Add(1)
	go connection.Proxy(connection.remoteConn, connection.backendConn, true)
	connection.Add(1)
	go connection.Proxy(connection.backendConn, connection.remoteConn, false)
	connection.Wait()
	log.Info("closed connection", "remote_addr", conn.RemoteAddr(), "backend_addr", connection.backendConn.RemoteAddr(), "read", connection.readBytes, "written", connection.writtenBytes)

}

// Proxy Copy every packet from src to dst
// Dumps packets to proxy's PCAP writer
func (c *Connection) Proxy(src net.Conn, dst net.Conn, source bool) {
	defer c.Done()
	// Close connections when source is done
	defer src.Close()
	defer dst.Close()
	// Average MTU
	buf := make([]byte, 1500)
	var written int64
	var err error
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Dump packets depending on direction
			if source {
				c.DumpPacket(src.RemoteAddr(), c.localAddr, buf[0:nr], source)
			} else {
				c.DumpPacket(c.localAddr, dst.RemoteAddr(), buf[0:nr], source)
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrShortWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			c.closing = true
			break
		}
	}
	if err != nil && !c.closing {
		log.Warn(err)
	}
	if source {
		c.readBytes += written
	} else {
		c.writtenBytes += written
	}
	log.Debug("connection closed", "source", src.RemoteAddr().String(), "target", dst.RemoteAddr(), "transferred", written)
}

// getTcpIpBaseLayers Creates TCP/IP base layers for our packet dump
func (c *Connection) getTcpIpBaseLayers(sourceAddress, targetAddress net.Addr) (SerializableNetworkLayer, *layers.TCP) {
	sourceHost, sourcePortString, err := net.SplitHostPort(sourceAddress.String())
	if err != nil {
		panic(err)
	}
	targetHost, targetPortString, err := net.SplitHostPort(targetAddress.String())
	if err != nil {
		panic(err)
	}
	sourcePort, err := strconv.Atoi(sourcePortString)
	if err != nil {
		panic(err)
	}
	targetPort, err := strconv.Atoi(targetPortString)
	if err != nil {
		panic(err)
	}
	sourceIP := net.ParseIP(sourceHost)
	targetIP := net.ParseIP(targetHost)
	var ip SerializableNetworkLayer
	if sourceIP.To4() != nil && targetIP.To4() != nil {
		ip = &layers.IPv4{
			Version:  4,
			TOS:      0,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    sourceIP,
			DstIP:    targetIP,
		}
	} else {
		ip = &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      sourceIP,
			DstIP:      targetIP,
		}
	}
	tcp := layers.TCP{
		Window:  5000,
		SrcPort: layers.TCPPort(sourcePort),
		DstPort: layers.TCPPort(targetPort),
	}
	return ip, &tcp
}

// SerializableNetworkLayer combined interface acceptable by both SetNetworkLayerForChecksum and SerializeLayers
type SerializableNetworkLayer interface {
	gopacket.NetworkLayer
	gopacket.SerializableLayer
}

// fakeTCPHandshake Creates a TCP handshake in the packet dump, setting up the rest of the connection
// This also has the effect of recording SYN scan activity
func (c *Connection) fakeTCPHandshake() {
	buff := gopacket.NewSerializeBuffer()
	ip, tcp := c.getTcpIpBaseLayers(c.remoteConn.RemoteAddr(), c.localAddr)
	tcp.SYN = true
	tcp.Seq = c.remoteSeq
	tcp.Ack = c.remoteSeq
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(
		buff,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp,
	)
	packet := buff.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}

	c.proxy.WritePacket(ci, packet)
	c.backendAck++
	c.remoteSeq++

	buff2 := gopacket.NewSerializeBuffer()
	ip, tcp = c.getTcpIpBaseLayers(c.localAddr, c.remoteConn.RemoteAddr())
	tcp.SYN = true
	tcp.ACK = true
	tcp.Seq = c.backendSeq
	tcp.Ack = c.backendAck
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(
		buff2,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp,
	)
	packet2 := buff2.Bytes()
	ci = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet2),
		Length:        len(packet2),
	}

	c.proxy.WritePacket(ci, packet2)
	c.remoteAck++
	c.backendSeq++
	buff3 := gopacket.NewSerializeBuffer()
	ip, tcp = c.getTcpIpBaseLayers(c.remoteConn.RemoteAddr(), c.localAddr)
	tcp.ACK = true
	tcp.Seq = c.remoteSeq
	tcp.Ack = c.remoteAck
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(
		buff3,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp,
	)
	packet3 := buff3.Bytes()
	ci = gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}

	err := c.proxy.WritePacket(ci, packet3)
	if err != nil {
		panic(err)
	}
}

// DumpPacket writes a packet to the packet writer, increment our seq/ack according to sent/received data
func (c *Connection) DumpPacket(sourceAddress, targetAddress net.Addr, buffer []byte, source bool) {
	buff := gopacket.NewSerializeBuffer()
	ip, tcp := c.getTcpIpBaseLayers(sourceAddress, targetAddress)
	tcp.ACK = true
	if source {
		tcp.Seq = c.remoteSeq
		tcp.Ack = c.remoteAck
	} else {
		tcp.Seq = c.backendSeq
		tcp.Ack = c.backendAck
	}
	tcp.SetNetworkLayerForChecksum(ip)
	gopacket.SerializeLayers(
		buff,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp, gopacket.Payload(buffer),
	)
	packet := buff.Bytes()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}
	err := c.proxy.WritePacket(ci, packet)
	if err != nil {
		panic(err)
	}
	if source {
		c.backendAck += uint32(len(buffer))
		c.remoteSeq += uint32(len(buffer))
	} else {
		c.remoteAck += uint32(len(buffer))
		c.backendSeq += uint32(len(buffer))
	}
}
