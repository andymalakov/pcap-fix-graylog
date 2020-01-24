package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	// libpcap
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	// Graylog GELF
	"github.com/duythinht/gelf"
	"github.com/duythinht/gelf/client"
)

var (
	device      = flag.String("interface", "\\Device\\NPF_Loopback", "Network interface to listen on")
	snapshotLen = flag.Int("snapshot-length", 262144, "Snapshot length. Utility will snarf given number of bytes from each packet")
	promiscuous = flag.Bool("promiscuous-mode", false, "Enables promiscuous mode")
	verbose     = flag.Bool("verbose", false, "Verbose output mode")
	listMode    = flag.Bool("list-interfaces", false, "Print the list of the network interfaces available on the system")
	portRange   = flag.String("port-range", "", "Port range in NNNN-MMMM format. For example: 9000-9100")
	graylogHost = flag.String("graylog-host", "localhost", "Graylog host name")
	graylogPort = flag.Int("graylog-port", 9001, "Graylog port")
	serverName  = flag.String("server-name", "fix-log", "Server name as it will appear in Graylog logs")
	skipHeartbeats = flag.Bool("skip-heartbeats", true, "Skip FIX Heartbeat(0) messages")

	timeout          time.Duration = pcap.BlockForever
	err              error
	handle           *pcap.Handle
	fromPort, toPort int

	graylogClient client.Gelf
)

//TODO: Filter out heartbeats
//TODO:

func main() {
	flag.Parse()

	if *listMode {
		findDevices()
	} else {
		capture(buildPcapFilter())
	}
}

func buildPcapFilter() string {
	var result string = "tcp"

	if len(*portRange) > 0 {
		fromPort, toPort = parsePortRange(*portRange)
		result += " and portrange " + *portRange
	}

	result += " and greater 60" // skip nonsense packets like ACK/SYNC/etc

	return result
}

func parsePortRange(portRange string) (fromPort int, toPort int) {
	fmt.Sscanf(portRange, "%d-%d", &fromPort, &toPort)
	return
}

func findDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func capture(filter string) {
	var snapshotLength = int32(*snapshotLen)

	graylogClient := client.New(client.Config{
		GraylogHost: *graylogHost,
		GraylogPort: *graylogPort,
	})

	defer graylogClient.Close()

	fmt.Printf("Caprure from interface: \"%s\" using filter: \"%s\"\n", *device, filter)
	fmt.Printf("Destination Graylog: \"%s:%d\"\n", *graylogHost, *graylogPort)

	if handle, err := pcap.OpenLive(*device, snapshotLength, *promiscuous, timeout); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			process(packet)
		}
	}
}

func process(packet gopacket.Packet) {

	var captureInfo = packet.Metadata().CaptureInfo
	if captureInfo.Length > 32 {
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			var payload = applicationLayer.Payload()

			//fmt.Printf("Packet length %d, payload length: %d\n", captureInfo.Length, len(payload))

			if len(payload) > 8 {
				// Check for "8=FIX." header
				if payload[0] == byte('8') &&
					payload[1] == byte('=') &&
					payload[2] == byte('F') &&
					payload[3] == byte('I') &&
					payload[4] == byte('X') &&
					payload[5] == byte('.') {

					processFIXPayload(captureInfo.Timestamp, payload)
				}
			}
		}
	}
}

func processFIXPayload(timestamp time.Time, payload []byte) {
	
	// if (*skipHeartbeats) {
	// 	if ()
	// }

	replaceSOH(payload)

	if *verbose {
		fmt.Printf("%s: %s\n", timestamp.Format(time.RFC822), payload)
	}

	logMessage := logPacket(timestamp, payload).ToJSON() //TODO: Generate JSON using string builder?

	//TODO: Compress? buffer := chunk.ZipMessage(message)

	//TODO: Chunking message

	fmt.Printf("%s: %s\n", timestamp.Format(time.RFC822), logMessage)

	graylogClient.Send(logMessage)
}

const FIELD_SOH byte = 1
const FIELD_SEPARATOR byte = byte('|')

func replaceSOH(message []byte) {
	for index, value := range message {
		if value == FIELD_SOH {
			message[index] = FIELD_SEPARATOR
		}
	}
}

func logPacket(timestamp time.Time, payload []byte) *gelf.Log {
	return &gelf.Log{
		Version:      "1.1",
		Host:         *serverName,
		Timestamp:    timestamp.Unix(),
		Level:        3,
		ShortMessage: string(payload),
	}
}

// func exitErrorf(msg string, args ...interface{}) {
// 	fmt.Fprintf(os.Stderr, msg+"\n", args...)
// 	os.Exit(1)
// }
