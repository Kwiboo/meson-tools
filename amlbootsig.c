/*
 * Copyright (c) 2017 Andreas Färber
 *
 * SPDX-License-Identifier: GPL-2.0-or-later WITH openvpn-openssl-exception
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "meson.h"

/*
 * REPRODUCIBLE_OUTPUT: For the benefit of generating reproducible packages,
 * deviate from aml_encrypt_gxb in not using random / time-based values.
 */
#define REPRODUCIBLE_OUTPUT

static int boot_sig(const char *input, const char *output)
{
	FILE *fin, *fout;
	uint8_t random[16];
	uint8_t *src_buf, *buf, *fip_buf;
	struct AmlogicHeader hdr = {
		.sig = AMLOGIC_SIGNATURE,
		.size = sizeof(struct AmlogicHeader),
		.header_size = sizeof(struct AmlogicHeader),
		.version_major = 1,
		.version_minor = 1, // 0 for gxbb, 1 for gxl
	};
	SHA256_CTX sha256_ctx;
	uint8_t sha256_digest[SHA256_DIGEST_LENGTH];

	assert(sizeof(struct AmlogicHeader) == 64);

	src_buf = malloc(0xf000);
	if (src_buf == NULL)
		return 1;

	fin = fopen(input, "rb");
	if (fin == NULL) {
		perror(input);
		return 1;
	}

	fout = fopen(output, "wb");
	if (fout == NULL) {
		perror(output);
		return 1;
	}

	for (int i = 0; i < 16; i++)
#ifdef REPRODUCIBLE_OUTPUT
		random[i] = 0x42;
#else
		random[i] = rand();
#endif

	fwrite(random, 1, 16, fout);

	fread(src_buf, 1, 0xf000, fin);

	if (strncmp(src_buf + 16, "@AML", 4) == 0) {
		fprintf(stderr, "@AML discovered in input!\n");
		return 1;
	}

	hdr.digest_type = 0; // 0 for normal boot / sha256 digest
	hdr.digest_offset = hdr.size; // sha256 digest is stored at to digest_offset, must follow directly after header
	hdr.digest_size = 512; // can probably be set to SHA256_DIGEST_LENGTH
	hdr.size += hdr.digest_size;

	hdr.padding_type = 0;
	hdr.padding_offset = hdr.size;
	hdr.padding_size = 4096 - hdr.padding_offset - 16; // align to 4K
	hdr.size += hdr.padding_size;

	hdr.payload_type = 0;
	hdr.payload_offset = hdr.size; // aligned to end up at 0xd9001000
	hdr.payload_size = 0xf000; // bl1 read 0xc000 starting from 0 (emmc) or 512 (sd)
	hdr.size += hdr.payload_size;

	// data to include in the sha256 digest
	hdr.data_offset = hdr.digest_offset + SHA256_DIGEST_LENGTH; // start directly after sha256 digest
	hdr.data_size = hdr.size - hdr.data_offset; // include all data until end

	buf = malloc(hdr.size);
	if (buf == NULL) {
		perror("malloc");
		return 1;
	}

	memset(buf, 0, hdr.size);
	memcpy(buf, &hdr, hdr.header_size);
	memcpy(buf + hdr.payload_offset, src_buf, hdr.payload_size);

	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, buf, hdr.header_size); // header
	SHA256_Update(&sha256_ctx, buf + hdr.data_offset, hdr.data_size); // data
	memset(sha256_digest, 0, sizeof(sha256_digest));
	SHA256_Final(sha256_digest, &sha256_ctx);
	memcpy(buf + hdr.digest_offset, sha256_digest, sizeof(sha256_digest));

	fwrite(buf, 1, hdr.size, fout);

	fclose(fout);
	fclose(fin);

	free(src_buf);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: %s input output\n", argv[0]);
		return 1;
	}

	return boot_sig(argv[1], argv[2]);
}
