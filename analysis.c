#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <signal.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define port 80

// Initialise mutual exclusive lock for detections of SYN, ARP cache poisoning, and blacklist.
pthread_mutex_t SYNLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ARPLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blacklistLock = PTHREAD_MUTEX_INITIALIZER;

// Initialise the counters.
int SYNCounter = 0;
int ARPResponseCounter = 0;
int blacklistCounter = 0;

// Initialise IP and its counter for detection of SYN flooding attack.
int uniqueIPCounter = 0;
u_int **uniqueIP;

// Print attributes of IP (header).
void printIP(const struct iphdr *IPHeader) {
	printf("\n[IP header]\n");
	printf("Version: %hu\n", IPHeader -> version);
	printf("IHL: %hu\n", IPHeader -> ihl);
	printf("TOS: %hu\n", IPHeader -> tos);
	printf("Total Length: %hu\n", IPHeader -> tot_len);
	printf("Identification: %hu\n", IPHeader -> id);
	printf("Fragment Offset: %hu\n", IPHeader -> frag_off);
	printf("Time To Live: %hu\n", IPHeader -> ttl);
	printf("Protocol: %hu\n", IPHeader -> protocol);
	printf("Header Checksum: %hu\n", IPHeader -> check);
	printf("Source IP Address: %hu\n", IPHeader -> saddr);
	printf("Destination IP Address: %hu\n", IPHeader -> daddr);
}

// Print attributes of TCP (header).
void printTCP(const struct tcphdr *TCPHeader) {
	printf("\n[TCP header]\n");
	printf("Source port: %hu\n", TCPHeader -> source);
	printf("Destination port: %hu\n", TCPHeader -> dest);
	printf("Sequence number: %hu\n", TCPHeader -> seq);
	printf("Acknowledgment number: %hu\n", TCPHeader -> ack_seq);
	printf("DO: %hu\n", TCPHeader -> doff);
	printf("URG: %hu\n", TCPHeader -> urg);
	printf("ACK: %hu\n", TCPHeader -> ack);
	printf("PSH: %hu\n", TCPHeader -> psh);
	printf("RST: %hu\n", TCPHeader -> rst);
	printf("SYN: %hu\n", TCPHeader -> syn);
	printf("FIN: %hu\n", TCPHeader -> fin);
}

// Print attributes of Ethernet header including source MAC, destination MAC, and type.
void printEthernet(const struct ether_header *ethernetHeader) {
	u_int index;
	printf("\n[Ethernet header]\n");
	printf("Source MAC: ");
	for (index = 0; index <= 5; ++ index) {
		printf("%02x", ethernetHeader -> ether_shost[index]);
		if (index <= 4) {printf(":");}
	}
	printf("\nDestination MAC: ");
	for (index = 0; index <= 5; ++ index) {
		printf("%02x", ethernetHeader -> ether_dhost[index]);
		if (index <= 4) {printf(":");}
	}
	printf("\nType: %hu\n", ethernetHeader -> ether_type);

}

// Print ARP information of ethernet.
void printARP(const struct ether_arp *eth_arp) {
	u_int index;
	printf("\n[ARP header]\n");
	for (index = 0; index <= 5; index ++) {printf("Sender Hardware Address: %hu\n", eth_arp -> arp_sha[index]);}
	for (index = 0; index <= 3; index ++) {printf("Sender Protocol Address: %hu\n", eth_arp -> arp_spa[index]);}
	for (index = 0; index <= 5; index ++) {printf("Target Hardware Address: %hu\n", eth_arp -> arp_tha[index]);}
	for (index = 0; index <= 3; index ++) {printf("Target Protocol Address: %hu\n", eth_arp -> arp_tpa[index]);}
}

// Print Ethernet, IP, and TCP information (called by FUNCTION analyse with CONDITION verbose).
void printInformation(const struct ether_header *ethernetHeader, 
					  const struct iphdr *IPHeader, 
					  const struct tcphdr *TCPHeader){
	printEthernet(ethernetHeader);
	printIP(IPHeader);
	printTCP(TCPHeader);
}

// Check whether an IP is stored before. Return 0 if an IP has been stored before, 1 otherwise.
int checkIPUniqueness(u_int *currentIP, u_int **IPArray, int counter){
	int index;
	for(index = 0; index < counter; index ++){
		// Loop IPArray to match a given IP.
		// Return 0 if current IP exists in the IPArray.
		if(currentIP == IPArray[index])
			return 0;
	}
	// Return 1 if current IP does not exist in the IPArray *(a unique IP).
	return 1;
}

// Clear memory allocation of ARRAY uniqueIP.
void clearIPArray(){
	int index;
	// Loop uniqueIP to free each memory allocation.
	for(index = 0; index < uniqueIPCounter; index ++){
		free(uniqueIP[index]);
	}
	free(uniqueIP);
}

// Check SYN flooding attack.
void checkSYNAttack(const struct iphdr *IPHeader, const struct tcphdr *TCPHeader){
	// Initialise current IP address.
	u_int currentIP;
	// Filter TCP SYN packets:
	// SYN bit is set to 1 and all other flag bits are set to 0. 
	if((u_int)TCPHeader -> syn == 1 
	 & (u_int)TCPHeader -> urg == 0 
	 & (u_int)TCPHeader -> ack == 0 
	 & (u_int)TCPHeader -> psh == 0
	 & (u_int)TCPHeader -> rst == 0
	 & (u_int)TCPHeader -> fin == 0){
		pthread_mutex_lock(&SYNLock);
		// Increment the counter of SYN.
		SYNCounter ++;
		pthread_mutex_unlock(&SYNLock);
		// Retrieve an IP address into currentIP.
		currentIP = IPHeader -> saddr;

		// If there is no IP stored before (then this is the first one).
		if(uniqueIPCounter == 0){
			pthread_mutex_lock(&SYNLock);
			// Increment the counter of unique IP.
			uniqueIPCounter ++;
			pthread_mutex_unlock(&SYNLock);
			// Create a dynamically growing array to store the source IP addresses of the incoming SYN packets.
			uniqueIP = malloc(uniqueIPCounter * sizeof(*uniqueIP));
			if(uniqueIP == NULL)clearIPArray();
			uniqueIP[0] = malloc(16 * sizeof(char *));
			if(uniqueIP[0] == NULL)clearIPArray();
			// Store current IP.
			uniqueIP[0] = currentIP;
		}
		// If there are IPs stored in the array before and the current IP has NOT been stored before (a unique IP).
		else if(checkIPUniqueness(currentIP, uniqueIP, uniqueIPCounter)){
			pthread_mutex_lock(&SYNLock);
			// Increment the counter of unique IP.
			uniqueIPCounter ++;
			pthread_mutex_unlock(&SYNLock);
			// Reallocate the array as there is a new IP added.
			uniqueIP = realloc(uniqueIP, uniqueIPCounter * sizeof(*uniqueIP));
			if(uniqueIP == NULL)clearIPArray();
			uniqueIP[uniqueIPCounter - 1] = malloc(16 * sizeof(char *));
			if(uniqueIP[uniqueIPCounter - 1] == NULL)clearIPArray();
			uniqueIP[uniqueIPCounter - 1] = currentIP;
		}
	}
}

// Check ARP cache poisoning attack.
void checkARPAttack(const struct ether_header *ethernetHeader, const struct iphdr *IPHeader, int verbose){
		// Filter ethernet packets by its header type (which should be ARP).
	if(ntohs(ethernetHeader -> ether_type) == ETHERTYPE_ARP) {
		// Use ether_arp struct defined in netinet/if_ether.h.
		const struct ether_arp *eth_arp = (struct ether_arp *) IPHeader;
		// Check ARP operation code (Number 2 means REPLY).
		if(ntohs(eth_arp -> arp_op) == 2){
			pthread_mutex_lock(&ARPLock);
			// Increment the counter of possible ARP response.
			ARPResponseCounter ++;
			pthread_mutex_unlock(&ARPLock);
		}
	}
}

// Check whether a connection tries to contact websites in the blacklist.
void checkBlackList(const struct tcphdr *TCPHeader, const struct iphdr *IPHeader, const u_char *packet) {
	//  Filter TCP packets that are sent to port 80
	if (ntohs(TCPHeader -> dest) == port) {
		// Retrieve the packet given a TCP (increase TCP pointer by DO).
		packet += TCPHeader -> doff * 4;
		// Check whether the hostname is in the blacklist (including "www.google.co.uk" and "www.bbc.com").
		// Increment the counter if the hostname is in the blacklist and give a notice with IP information.
		if(strstr(packet, "Host: www.google.co.uk") || strstr(packet, "Host: www.bbc.com")){
			pthread_mutex_lock(&blacklistLock);
			// Increment the counter of blacklist attempt.
			blacklistCounter ++;
			pthread_mutex_unlock(&blacklistLock);
			// Give a notice with IP information.
			printf("==============================\n");
			printf("Blacklisted URL violation detected\n");
			printf("Source IP Address: %hu\n", IPHeader -> saddr);
			printf("Destination IP Address: %hu\n", IPHeader -> daddr);
			printf("==============================\n");
			printf("\n");
		}
	}
}

// Output a report after killing the program using Cntrl+c.
void intrusionDetection(int signo) {
	if (signo == SIGINT) {
		printf("\nIntrusion Detection Report:\n");
		printf("%d SYN packets detected from %d different IPs (syn attack)\n", SYNCounter, uniqueIPCounter);
		printf("%d ARP responses (cache poisoning)\n", ARPResponseCounter);
		printf("%d URL Blacklist violations\n", blacklistCounter);
		exit(0);
	}
}

// Operate the "main" function of checking (called by Function threadProcess in File dispatch.c).
void analyse(struct pcap_pkthdr *header, 
			 const unsigned char *packet, 
			 int verbose) {

	signal(SIGINT, intrusionDetection);

	// Retrieve ethernet header by its pointer which is the top of a packet.
	const struct ether_header *ethernetHeader = (struct ether_header *) packet;

	// Retrieve IP header by its pointer which is after the ethernet one.
	const struct iphdr *IPHeader = (struct iphdr *) (packet += ETH_HLEN);

	// Retrieve TCP header by its pointer which is after IP and ethernet ones.
	const struct tcphdr *TCPHeader = (struct tcphdr *) (packet += (IPHeader -> ihl * 4));
	
	// Print information of ethernet, IP, and TCP with CONDITION verbose.
	if(verbose)printInformation(ethernetHeader, IPHeader, TCPHeader);

	// Operate the checking of SYN flooding attack, attempt to visit websites in the blacklist, and ARP cache poisoning.
	checkSYNAttack(IPHeader, TCPHeader);
	checkARPAttack(ethernetHeader, IPHeader, verbose);
	checkBlackList(TCPHeader, IPHeader, packet);
}