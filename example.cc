#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "VlanLayer.h"
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>

int  main() {
	/*
	   Frame 1: 85 bytes on wire (680 bits)
	   Ethernet II
Destination: LLDP_Multicast (01:80:c2:00:00:0e)
Source: 02:eb:8d:ba:68:d7 (02:eb:8d:ba:68:d7)
Type: 802.1 Link Layer Discovery Protocol (LLDP) (0x88cc)
Trailer: 310000
Link Layer Discovery Protocol
Chassis Subtype = MAC address, Id: 00:00:00:00:00:01
Port Subtype = Port component, Id: 31
Time To Live = 120 sec
Open Networking Laboratory - Unknown (1)
Open Networking Laboratory - Unknown (2)
Port Description = port1
End of LLDPDU
	 */
	const uint8_t lldpPacket[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E, 0x02, 0xEB, 0x8D, 0xBA, 0x68, 0xD7, 0x88, 0xCC, 0x02, 0x07,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x02, 0x02, 0x31, 0x06, 0x02, 0x00, 0x78, 0xFE,
		0x12, 0xA4, 0x23, 0x05, 0x01, 0x4F, 0x4E, 0x4F, 0x53, 0x20, 0x44, 0x69, 0x73, 0x63, 0x6F, 0x76,
		0x65, 0x72, 0x79, 0xFE, 0x17, 0xA4, 0x23, 0x05, 0x02, 0x6F, 0x66, 0x3A, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x08, 0x05, 0x70, 0x6F,
		0x72, 0x74, 0x31, 0x00, 0x00};

	/*
	   Frame 1: 64 bytes on wire (512 bits)
	   Ethernet II
Destination: Nearest-non-TPMR-bridge (01:80:c2:00:00:03)
Source: IntelCor_82:fa:83 (90:e2:ba:82:fa:83)
Type: 802.1Q Virtual LAN (0x8100)
802.1Q Virtual LAN
000. .... .... .... = Priority: Best Effort (default) (0)
...0 .... .... .... = DEI: Ineligible
.... 1111 1111 1011 = ID: 4091
Type: 802.1X Authentication (0x888e)
Padding: 000000000000000000000000000000000000000000000000\xe2\x80\xa6
Trailer: 00000000
802.1X Authentication
Version: 802.1X-2001 (1)
Type: Start (1)
Length: 0
	 */
	const uint8_t eapPacket[] =  {0x01, 0x80, 0xC2, 0x00, 0x00, 0x03, 0x90, 0xE2, 0xBA, 0x82, 0xFA, 0x83, 0x81, 0x00, 0x0F, 0xFB,
		0x88, 0x8E, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/*
	   Frame 1: 346 bytes on wire (2768 bits)
	   Ethernet II
Destination: Broadcast (ff:ff:ff:ff:ff:ff)
Source: IntelCor_82:fa:83 (90:e2:ba:82:fa:83)
Type: 802.1Q Virtual LAN (0x8100)
802.1Q Virtual LAN
000. .... .... .... = Priority: Best Effort (default) (0)
...0 .... .... .... = DEI: Ineligible
.... 0000 0110 1111 = ID: 111
Type: IPv4 (0x0800)
Internet Protocol Version 4
0100 .... = Version: 4
.... 0101 = Header Length: 20 bytes (5)
Differentiated Services Field: 0x10 (DSCP: Unknown, ECN: Not-ECT)
Total Length: 328
Identification: 0x0000 (0)
Flags: 0x0000
Fragment offset: 0
Time to live: 128
Protocol: UDP (17)
Header checksum: 0x3996
Header checksum status: Unverified
Source: 0.0.0.0
Destination: 255.255.255.255
User Datagram Protocol
Source Port: 68
Destination Port: 67
Length: 308
Checksum: 0x1f49
Checksum Status: Unverified
Stream index: 0
Timestamps
Dynamic Host Configuration Protocol (Discover)
Message type: Boot Request (1)
Hardware type: Ethernet (0x01)
Hardware address length: 6
Hops: 0
Transaction ID: 0x29acc278
Seconds elapsed: 96
Bootp flags: 0x0000 (Unicast)
Client IP address: 0.0.0.0
Your (client) IP address: 0.0.0.0
Next server IP address: 0.0.0.0
Relay agent IP address: 0.0.0.0
Client MAC address: IntelCor_82:fa:83 (90:e2:ba:82:fa:83)
Client hardware address padding: 00000000000000000000
Server host name not given
Boot file name not given
Magic cookie: DHCP
Option: (53) DHCP Message Type (Discover)
Option: (12) Host Name
Option: (55) Parameter Request List
Option: (255) End
Padding: 000000000000000000000000000000000000000000000000\xe2\x80\xa6
	 */
	const uint8_t dhcpPacket[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0xE2, 0xBA, 0x82, 0xFA, 0x83, 0x81, 0x00, 0x00, 0x6F,
		0x08, 0x00, 0x45, 0x10, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, 0x39, 0x96, 0x00, 0x00,
		0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x44, 0x00, 0x43, 0x01, 0x34, 0x1F, 0x49, 0x01, 0x01,
		0x06, 0x00, 0x29, 0xAC, 0xC2, 0x78, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0xE2, 0xBA, 0x82, 0xFA, 0x83,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01,
		0x01, 0x0C, 0x0C, 0x41, 0x4C, 0x50, 0x48, 0x65, 0x33, 0x64, 0x31, 0x63, 0x66, 0x64, 0x65, 0x37,
		0x0D, 0x01, 0x1C, 0x02, 0x03, 0x0F, 0x06, 0x77, 0x0C, 0x2C, 0x2F, 0x1A, 0x79, 0x2A, 0xFF, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/*
	   Frame 1: 60 bytes on wire (480 bits)
	   Ethernet II
	   802.1Q Virtual LAN
	   101. .... .... .... = Priority: Voice, < 10ms latency and jitter (5)
	   ...0 .... .... .... = DEI: Ineligible
	   .... 0000 0011 0111 = ID: 55
Type: IPv4 (0x0800)
Padding: 0000
Internet Protocol Version 4
Internet Group Management Protocol
	 */
	const uint8_t igmpPacket[] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x16, 0x90, 0xE2, 0xBA, 0x82, 0xF9, 0x75, 0x81, 0x00, 0xA0, 0x37,
		0x08, 0x00, 0x46, 0xC0, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0x03, 0xFA, 0x00, 0x00,
		0x00, 0x00, 0xE0, 0x00, 0x00, 0x16, 0x94, 0x04, 0x00, 0x00, 0x22, 0x00, 0xF8, 0xE5, 0x00, 0x00,
		0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0xE1, 0x16, 0x00, 0x02, 0x00, 0x00};

	struct timeval tv = {10, 0};


	//// LLDP Start //////
	printf("\n\n\nLLDP Processing start\n");
	pcpp::RawPacket lldpRawPacket(lldpPacket, sizeof(lldpPacket), tv, false, pcpp::LINKTYPE_ETHERNET);
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&lldpRawPacket);

	// Checking for IPV4 packet
	if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
		printf("packet is of ipv4\n");
	}

	pcpp::EthLayer* ethernetLayerLldp = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayerLldp == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		exit(1);
	}

	// print the source and dest MAC addresses and the Ether type
	printf("\nSource MAC address: %s\n", ethernetLayerLldp->getSourceMac().toString().c_str());
	printf("Destination MAC address: %s\n", ethernetLayerLldp->getDestMac().toString().c_str());
	printf("Ether type = 0x%X\n", ntohs(ethernetLayerLldp->getEthHeader()->etherType));

	// Getting Vlan layer
	pcpp::VlanLayer* vlanLayerLldp = parsedPacket.getLayerOfType<pcpp::VlanLayer>();
	if (vlanLayerLldp == NULL)
	{
		printf("Something went wrong, couldn't find vlan layer\n");
	} else {
		printf("Ether type = 0x%X\n", vlanLayerLldp->getVlanID());
	}

	//////// LLDP END //////////


	//////// EAP Start //////////
	printf("\n\n\nEAP Processing start\n");
	pcpp::RawPacket eapRawPacket(eapPacket, sizeof(eapPacket), tv, false, pcpp::LINKTYPE_ETHERNET);
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacketEap(&eapRawPacket);
	pcpp::EthLayer* ethernetLayerEap = parsedPacketEap.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayerEap == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		exit(1);
	}

	// print the source and dest MAC addresses and the Ether type
	printf("\nSource MAC address: %s\n", ethernetLayerEap->getSourceMac().toString().c_str());
	printf("Destination MAC address: %s\n", ethernetLayerEap->getDestMac().toString().c_str());
	printf("Ether type = 0x%X\n", ntohs(ethernetLayerEap->getEthHeader()->etherType));

	// Getting Vlan layer
	pcpp::VlanLayer* vlanLayerEap = parsedPacketEap.getLayerOfType<pcpp::VlanLayer>();
	if (vlanLayerEap == NULL)
	{
		printf("Something went wrong, couldn't find vlan layer\n");
	} else {
		printf("EAP Vid = 0x%X\n", vlanLayerEap->getVlanID());
		printf("Ether type = 0x%X\n", ntohs((vlanLayerEap->getVlanHeader()->etherType)));
	}


	//////// EAP End //////////

	///// DHCP start //////
	printf("\n\n\nDHCP processing start\n");
	pcpp::RawPacket dhcpRawPacket(dhcpPacket, sizeof(dhcpPacket), tv, false, pcpp::LINKTYPE_ETHERNET);
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacketDhcp(&dhcpRawPacket);
	pcpp::EthLayer* ethernetLayerDhcp = parsedPacketDhcp.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayerDhcp == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		exit(1);
	}

	// print the source and dest MAC addresses and the Ether type
	printf("\nSource MAC address: %s\n", ethernetLayerDhcp->getSourceMac().toString().c_str());
	printf("Destination MAC address: %s\n", ethernetLayerDhcp->getDestMac().toString().c_str());
	uint16_t dhcpEtherType = ntohs(ethernetLayerDhcp->getEthHeader()->etherType);

	if (dhcpEtherType != 0x0800) {
		// Getting Vlan layer
		pcpp::VlanLayer* vlanLayerDhcp = parsedPacketDhcp.getLayerOfType<pcpp::VlanLayer>();
		if (vlanLayerDhcp == NULL)
		{
			printf("Something went wrong, couldn't find vlan layer\n");
		} else {
			printf("VlanVid of DHCP = 0x%X\n", vlanLayerDhcp->getVlanID());
			if ( ntohs((vlanLayerDhcp->getVlanHeader()->etherType)) == 0x0800) {
				vlanLayerDhcp->parseNextLayer();
				pcpp::IPv4Layer *ipv4Layer = (pcpp::IPv4Layer*)vlanLayerDhcp->getNextLayer();
				printf("protocol of the dhcp packet is %d\n", ipv4Layer->getIPv4Header()->protocol);

			}
		}
	}

	//// DHCP end /////

	///// IGMP start //////
	printf("\n\n\n IGMP processing start\n");
	pcpp::RawPacket igmpRawPacket(igmpPacket, sizeof(igmpPacket), tv, false, pcpp::LINKTYPE_ETHERNET);
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacketIgmp(&igmpRawPacket);
	pcpp::EthLayer* ethernetLayerIgmp = parsedPacketIgmp.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayerIgmp == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		exit(1);
	}

	// print the source and dest MAC addresses and the Ether type
	printf("\nSource MAC address: %s\n", ethernetLayerIgmp->getSourceMac().toString().c_str());
	printf("Destination MAC address: %s\n", ethernetLayerIgmp->getDestMac().toString().c_str());
	uint16_t igmpEtherType = ntohs(ethernetLayerIgmp->getEthHeader()->etherType);

	if (igmpEtherType != 0x0800) {
		// Getting Vlan layer
		pcpp::VlanLayer* vlanLayerIgmp = parsedPacketIgmp.getLayerOfType<pcpp::VlanLayer>();
		if (vlanLayerIgmp == NULL)
		{
			printf("Something went wrong, couldn't find vlan layer\n");
		} else {
			printf("VlanVid of DHCP = 0x%X\n", vlanLayerIgmp->getVlanID());
			if ( ntohs((vlanLayerIgmp->getVlanHeader()->etherType)) == 0x0800) {
				vlanLayerIgmp->parseNextLayer();
				pcpp::IPv4Layer *ipv4Layer = (pcpp::IPv4Layer*)vlanLayerIgmp->getNextLayer();
				printf("protocol of the igmp packet is %d\n", ipv4Layer->getIPv4Header()->protocol);

			}
		}
	}

	//// IGMP end /////


	return 0;
}
