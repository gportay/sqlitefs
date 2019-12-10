/*
 * Copyright (c) 2015-2017 Gaël PORTAY <gael.portay@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __HEXDUMP_H__
#define __HEXDUMP_H__

#include <stdio.h>

#define __min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static int DUMPHEADER = 1;
static int DUMPFOOTER = 1;
static int DUMPADDR = 1;
static unsigned int ROWSIZE = 0x10;
static char EMPTYBYTE = ' ';

static inline
void hexdump_line(FILE *f, const void *buffer, unsigned int bufsize)
{
	const unsigned char *buf = (unsigned char *)buffer;
	unsigned int j;

	for (j = 0; j < __min(ROWSIZE, bufsize); j++)
		fprintf(f, " %02x", buf[j]);

	for (j = 0; j < __min(ROWSIZE-bufsize, ROWSIZE); j++)
		fprintf(f, " %-2c", EMPTYBYTE);

	fprintf(f, "\t");

	for (j = 0; j < __min(ROWSIZE, bufsize); j++) {
		if ((buf[j] < 0x20) || (buf[j] >= 0x7F))
			fprintf(f, ".");
		else
			fprintf(f, "%c", (char)buf[j]);
	}

	for (j = 0; j < __min(ROWSIZE-bufsize, ROWSIZE); j++)
		fprintf(f, "%c", EMPTYBYTE);
}

static inline
void fhexdump(FILE *f, unsigned int address, const void *buffer,
	      unsigned int bufsize)
{
	const unsigned char *buf = (const unsigned char *)buffer;
	unsigned int r, row, size = 0;

	row = bufsize / ROWSIZE;
	if (bufsize % ROWSIZE)
		row++;

	if (DUMPHEADER) {
		fprintf(f, "%s:", "@address");
		for (r = 0; r < ROWSIZE; r ++)
			fprintf(f, " %02x", r);
		fprintf(f, "\n");
	}

	for (r = 0; r < row; r++) {
		unsigned int s = __min(bufsize - size, ROWSIZE);

		if (DUMPADDR)
			fprintf(f, "%08x:", address + size);

		hexdump_line(f, buf, s);
		buf += s;
		size += s;
		fprintf(f, "\n");
	}

	if (DUMPFOOTER)
		fprintf(f, "%08x\n", address + size);
}

static inline
void hexdump(unsigned int address, const void *buffer, unsigned int bufsize)
{
	return fhexdump(stdout, address, buffer, bufsize);
}

#undef __min

#endif /* __HEXDUMP_H__ */
