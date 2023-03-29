#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "dispatch.h"

// Callback of pcap sniffing a packet (to make sure the termination is handled properly).
void handler(u_char *verbose, const struct pcap_pkthdr *header, const u_char *packet) {
	dispatch(&header, packet, (int) verbose);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {

  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet.
  // capturing session. check the man page of pcap_open_live().
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  // pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) process packets from a live capture instead of using pcap_next() to proceed.
  pcap_loop(pcap_handle, 0, handler, (u_char *) verbose);
}