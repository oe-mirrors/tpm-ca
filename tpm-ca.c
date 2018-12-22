/*
 * tpm-ca.c
 *
 * Copyright (C) 2017 Dream Property GmbH, Germany
 *                    https://dreambox.de/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <tpmd.h>

enum ca_tag {
	TAG_MID		= 0x01,
	TAG_SERIAL	= 0x03,
	TAG_HWADDR	= 0x04,
	TAG_DATE	= 0x06,
	TAG_ASERIAL	= 0x07,
};

static const unsigned char tpm_root_mod[128] = {
	0x9F, 0x7C, 0xE4, 0x47, 0xC9, 0xB4, 0xF4, 0x23, 0x26, 0xCE, 0xB3, 0xFE, 0xDA, 0xC9, 0x55, 0x60,
	0xD8, 0x8C, 0x73, 0x6F, 0x90, 0x9B, 0x5C, 0x62, 0xC0, 0x89, 0xD1, 0x8C, 0x9E, 0x4A, 0x54, 0xC5,
	0x58, 0xA1, 0xB8, 0x13, 0x35, 0x45, 0x02, 0xC9, 0xB2, 0xE6, 0x74, 0x89, 0xDE, 0xCD, 0x9D, 0x11,
	0xDD, 0xC7, 0xF4, 0xE4, 0xE4, 0xBC, 0xDB, 0x9C, 0xEA, 0x7D, 0xAD, 0xDA, 0x74, 0x72, 0x9B, 0xDC,
	0xBC, 0x18, 0x33, 0xE7, 0xAF, 0x7C, 0xAE, 0x0C, 0xE3, 0xB5, 0x84, 0x8D, 0x0D, 0x8D, 0x9D, 0x32,
	0xD0, 0xCE, 0xD5, 0x71, 0x09, 0x84, 0x63, 0xA8, 0x29, 0x99, 0xDC, 0x3C, 0x22, 0x78, 0xE8, 0x87,
	0x8F, 0x02, 0x3B, 0x53, 0x6D, 0xD5, 0xF0, 0xA3, 0x5F, 0xB7, 0x54, 0x09, 0xDE, 0xA7, 0xF1, 0xC9,
	0xAE, 0x8A, 0xD7, 0xD2, 0xCF, 0xB2, 0x2E, 0x13, 0xFB, 0xAC, 0x6A, 0xDF, 0xB1, 0x1D, 0x3A, 0x3F,
};

static unsigned char fab_ca_cert[210];
static unsigned char datablock_signed[128];

static void ascdump(const char *name, const unsigned char *buf, unsigned int len)
{
	unsigned int i;

	printf("%s=", name);

	for (i = 0; i < len; i++)
		printf("%c", buf[i]);

	printf("\n");
}

static void decdump(const char *name, const unsigned char *buf, unsigned int len)
{
	uint64_t val = 0;
	unsigned int i;

	for (i = 0; i < len; i++) {
		val <<= 8;
		val |= buf[i];
	}

	printf("%s=%" PRIu64 "\n", name, val);
}

static void macdump(const char *name, const unsigned char *buf, unsigned int len)
{
	unsigned int i;

	printf("%s=", name);

	for (i = 0; i < len; i++) {
		if (i != 0)
			printf(":");
		printf("%02X", buf[i]);
	}

	printf("\n");
}

static bool wait_event(int fd, unsigned int events, int timeout)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = events,
	};
	int ret;

	ret = poll(&pfd, 1, timeout);
	if (ret < 0) {
		perror("poll");
		return false;
	}

	if (ret == 0) {
		fprintf(stderr, "timeout\n");
		return false;
	}

	return pfd.revents & events;
}

static bool send_cmd(int fd, enum tpmd_cmd cmd, const void *data, unsigned int len)
{
	unsigned char buf[len + 4];

	buf[0] = (cmd >> 8) & 0xff;
	buf[1] = (cmd >> 0) & 0xff;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = (len >> 0) & 0xff;
	memcpy(&buf[4], data, len);

	if (!wait_event(fd, POLLOUT, 1000))
		return false;

	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
		fprintf(stderr, "%s: incomplete write\n", __func__);
		return false;
	}

	return true;
}

static void *recv_cmd(int fd, unsigned int *tag, unsigned int *len)
{
	unsigned char buf[4];
	void *val;

	if (!wait_event(fd, POLLIN, 1000))
		return NULL;

	if (read(fd, buf, 4) != 4)
		fprintf(stderr, "%s: incomplete read\n", __func__);

	*tag = (buf[0] << 8) | buf[1];
	*len = (buf[2] << 8) | buf[3];

	val = malloc(*len);
	if (read(fd, val, *len) != (ssize_t)*len)
		fprintf(stderr, "%s: incomplete read\n", __func__);

	return val;
}

static void parse_data(const unsigned char *data, unsigned int datalen)
{
	unsigned int i;
	unsigned int tag;
	unsigned int len;
	const unsigned char *val;

	for (i = 0; i < datalen; i += len) {
		tag = data[i++];
		len = data[i++];
		val = &data[i];

		switch (tag) {
		case TPMD_DT_FAB_CA_CERT:
			if (len != 210)
				break;
			memcpy(fab_ca_cert, val, 210);
			break;
		case TPMD_DT_DATABLOCK_SIGNED:
			if (len != 128)
				break;
			memcpy(datablock_signed, val, 128);
			break;
		}
	}
}

static void rsa_pub1024(unsigned char dest[128],
			const unsigned char src[128],
			const unsigned char mod[128])
{
	BIGNUM *bbuf, *bexp, *bmod;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	bbuf = BN_new();
	bexp = BN_new();
	bmod = BN_new();

	BN_bin2bn(src, 128, bbuf);
	BN_bin2bn(mod, 128, bmod);
	BN_bin2bn((const unsigned char *)"\x01\x00\x01", 3, bexp);

	BN_mod_exp(bbuf, bbuf, bexp, bmod, ctx);

	BN_bn2bin(bbuf, dest);

	BN_clear_free(bexp);
	BN_clear_free(bmod);
	BN_clear_free(bbuf);
	BN_CTX_free(ctx);
}

static bool decrypt_block(unsigned char dest[128],
			  const unsigned char *src,
			  unsigned int len,
			  const unsigned char mod[128])
{
	unsigned char hash[20];
	SHA_CTX ctx;

	if ((len != 128) &&
	    (len != 202))
		return false;

	rsa_pub1024(dest, src, mod);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &dest[1], 106);
	if (len == 202)
		SHA1_Update(&ctx, &src[131], 61);
	SHA1_Final(hash, &ctx);

	return (memcmp(hash, &dest[107], 20) == 0);
}

static bool validate_cert(unsigned char dest[128],
			  const unsigned char src[210],
			  const unsigned char mod[128])
{
	unsigned char buf[128];

	if (!decrypt_block(buf, &src[8], 210 - 8, mod))
		return false;

	memcpy(&dest[0], &buf[36], 71);
	memcpy(&dest[71], &src[131 + 8], 57);
	return true;
}

static bool dump_ca(void)
{
	unsigned char mod[128];
	unsigned char buf[128];
	const unsigned char *ca, *data;
	unsigned int i, len;
	unsigned int cs;
	unsigned char dtag, dlen;

	if (!validate_cert(mod, fab_ca_cert, tpm_root_mod)) {
		fprintf(stderr, "could not verify fab_ca_cert\n");
		return false;
	}
	if (!decrypt_block(buf, datablock_signed, 128, mod)) {
		fprintf(stderr, "could not decrypt signed block\n");
		return false;
	}

	ca = &buf[1];

	if (ca[0] != 0xca) {
		fprintf(stderr, "invalid CA tag\n");
		return false;
	}

	if (ca[1] != 0x02) {
		fprintf(stderr, "unknown CA version\n");
		return false;
	}

	len = ca[2];
	if ((len < 3) ||
	    (len > 126)) {
		fprintf(stderr, "invalid CA length #1\n");
		return false;
	}

	// CA 02 LI .. .. FF 01 CS
	cs = 0;
	for (i = 0; i < len; i++)
		cs ^= ca[i];

	if (cs != 0) {
		fprintf(stderr, "invalid CA checksum\n");
	}

	for (i = 3; i < len; i += dlen) {
		dtag = ca[i++];
		dlen = ca[i++];
		data = dlen ? &ca[i] : NULL;

		switch (dtag) {
		case TAG_MID:
			decdump("CA_MID", data, dlen);
			break;
		case TAG_SERIAL:
			decdump("CA_SERIAL", data, dlen);
			break;
		case TAG_HWADDR:
			macdump("CA_HWADDR", data, dlen);
			break;
		case TAG_DATE:
			ascdump("CA_DATE", data, dlen);
			break;
		case TAG_ASERIAL:
			ascdump("CA_ASERIAL", data, dlen);
			break;
		}
	}

	if (i != len) {
		fprintf(stderr, "invalid CA length #2\n");
		return false;
	}

	return true;
}

static bool read_ca(int fd)
{
	unsigned char buf[2];
	unsigned int tag, len;
	unsigned char *val;

	buf[0] = TPMD_DT_FAB_CA_CERT;
	buf[1] = TPMD_DT_DATABLOCK_SIGNED;
	if (!send_cmd(fd, TPMD_CMD_GET_DATA, buf, 2))
		return false;

	val = recv_cmd(fd, &tag, &len);
	if (val == NULL)
		return false;
	assert(tag == TPMD_CMD_GET_DATA);
	parse_data(val, len);
	free(val);

	return dump_ca();
}

int main(void)
{
	struct sockaddr_un addr;
	int fd, retval = 1;

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, TPMD_SOCKET, sizeof(((struct sockaddr_un *)0)->sun_path));

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket");
		return retval;
	}

	if (connect(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		if (errno != EINPROGRESS) {
			perror("connect");
			return EXIT_FAILURE;
		}

		if (!wait_event(fd, POLLOUT, 1000))
			return EXIT_FAILURE;
	}

	return read_ca(fd) ? EXIT_SUCCESS : EXIT_FAILURE;
}
