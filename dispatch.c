#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Construct a thread unit to enable multithreading (pthreads) of checking.
struct threadUnit {
	struct pcap_pkthdr *header;
	const u_char *packet;
	int verbose;
};

// Process the thread to analyse packet.
void *threadProcess(void *args) {
	// Casting a void pointer in Function pthread_create().
	struct threadUnit *subject = (struct threadUnit *) args;
	analyse(subject -> header, subject -> packet, subject -> verbose);
	// Release the memory.
	free(subject);
} 

void dispatch(struct pcap_pkthdr *header, 
			  const unsigned char *packet, 
			  int verbose) {
	pthread_t thread;
	struct threadUnit *args = malloc(sizeof(struct threadUnit));
	args -> header = header;
	args -> packet = packet;
	args -> verbose = verbose;
	pthread_create(&thread, NULL, &threadProcess, (void *) args);
	pthread_detach(thread);
}