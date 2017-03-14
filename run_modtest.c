#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "modtest.h"

int main(int argc, char **argv) {
	int err = 0;
	// Try to open serial port
	int fd = open(argv[1], O_RDWR | O_NOCTTY | O_NONBLOCK);
	if(fd == -1) {
		printf("Couldn't open %s\n", argv[1]);
		return -1;
	}

	printf("Start modtest.\n");

	struct modtest_result mt;
	mt.testno = 1;
	mt.next_testno = 1;

	while(mt.next_testno != -1) {
		if(err = ioctl(fd, 0x9999, &mt)) {
			perror("ioctl failed");
			close(fd);
			return -err;
		}
		printf("TestNo #%d: %s\n", mt.testno, mt.msg);
		mt.testno = mt.next_testno;
	}


	printf("Finish modtest.\n");
}


