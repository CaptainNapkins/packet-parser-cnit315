#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char *dev = argv[1];
	char *errbuf = "error occured";
	printf("Device: %s\n", dev);
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	return(0);
}
