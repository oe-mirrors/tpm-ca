/*
 * tpm-ca.c
 *
 * Copyright (C) 2019 Dream Property GmbH, Germany
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
#include <openssl/x509_vfy.h>
#include <tpmd.h>

#if !defined(TPMD_API_VERSION)
#define TPMD_CMD_GET_DATA_V2	0x0011
#endif

enum ca_tag {
	TAG_MID		= 0x01,
	TAG_SERIAL	= 0x03,
	TAG_HWADDR	= 0x04,
	TAG_DATE	= 0x06,
	TAG_ASERIAL	= 0x07,
};

struct buffer {
	size_t size;
	unsigned char data[];
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

static const unsigned char tpm2_root_cert[] = {
	0x30, 0x82, 0x01, 0xe3, 0x30, 0x82, 0x01, 0x88, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
	0xf9, 0x69, 0x77, 0x65, 0xb2, 0x2b, 0x72, 0xb8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x02, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x44, 0x45, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x13, 0x44, 0x72,
	0x65, 0x61, 0x6d, 0x20, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x79, 0x20, 0x47, 0x6d, 0x62,
	0x48, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x44, 0x52, 0x31, 0x30,
	0x30, 0x30, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38,
	0x31, 0x31, 0x31, 0x35, 0x32, 0x32, 0x32, 0x37, 0x34, 0x33, 0x5a, 0x17, 0x0d, 0x33, 0x38, 0x31,
	0x31, 0x31, 0x30, 0x32, 0x32, 0x32, 0x37, 0x34, 0x33, 0x5a, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09,
	0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55,
	0x04, 0x0a, 0x0c, 0x13, 0x44, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72,
	0x74, 0x79, 0x20, 0x47, 0x6d, 0x62, 0x48, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0e, 0x44, 0x52, 0x31, 0x30, 0x30, 0x30, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41,
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x11, 0xdd, 0x96, 0xa2, 0x1d,
	0x73, 0x13, 0xad, 0xc4, 0x97, 0xdb, 0x97, 0x78, 0x61, 0x43, 0x59, 0x02, 0xb9, 0xeb, 0x26, 0xf5,
	0xe2, 0xd7, 0x50, 0x62, 0x76, 0x4b, 0xb8, 0xbd, 0x5f, 0x5b, 0x98, 0xc9, 0x02, 0xcb, 0xf2, 0xe5,
	0x02, 0x4f, 0xc8, 0x77, 0x8d, 0x97, 0x9a, 0x86, 0xc3, 0x10, 0x1b, 0x26, 0xde, 0xf9, 0x6e, 0x14,
	0xef, 0x3f, 0x0e, 0x00, 0x54, 0x74, 0x79, 0x97, 0x2f, 0x77, 0x9d, 0xa3, 0x63, 0x30, 0x61, 0x30,
	0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xab, 0xd0, 0x17, 0xb3, 0xbb, 0x4f,
	0x18, 0x5f, 0x14, 0x7b, 0xfb, 0xff, 0x0f, 0x60, 0x9f, 0x75, 0x09, 0xca, 0x12, 0x15, 0x30, 0x1f,
	0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xab, 0xd0, 0x17, 0xb3, 0xbb,
	0x4f, 0x18, 0x5f, 0x14, 0x7b, 0xfb, 0xff, 0x0f, 0x60, 0x9f, 0x75, 0x09, 0xca, 0x12, 0x15, 0x30,
	0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
	0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86,
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30,
	0x46, 0x02, 0x21, 0x00, 0xef, 0x91, 0x24, 0x6f, 0x0e, 0x57, 0x38, 0xb7, 0xba, 0x77, 0xd7, 0xb4,
	0xe6, 0x2f, 0xd2, 0x7f, 0xe5, 0x7e, 0xeb, 0x97, 0xec, 0x33, 0xa2, 0x50, 0x6d, 0x95, 0x7e, 0xc6,
	0x34, 0x50, 0x40, 0xf9, 0x02, 0x21, 0x00, 0xba, 0x3f, 0xc7, 0xc0, 0x6e, 0x1a, 0xf2, 0x85, 0xae,
	0xd8, 0x87, 0x32, 0x64, 0x9b, 0x73, 0x42, 0x8c, 0x0a, 0xe7, 0xcc, 0xdc, 0xd3, 0x35, 0x10, 0x7e,
	0x04, 0x1f, 0xff, 0x30, 0xca, 0x33, 0xc9
};

static unsigned int protocol_version;
static unsigned int tpm_version;
static struct buffer *fab_ca_cert;
static struct buffer *datablock_signed;

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

static void buffer_copy(struct buffer **buf, const void *data, unsigned int size)
{
	*buf = realloc(*buf, sizeof(struct buffer) + size);
	if (*buf == NULL)
		abort();

	(*buf)->size = size;
	memcpy((*buf)->data, data, size);
}

static void parse_data(enum tpmd_cmd cmd, const unsigned char *data, unsigned int datalen)
{
	unsigned int i;
	unsigned int tag;
	unsigned int len;
	const unsigned char *val;

	for (i = 0; i < datalen; i += len) {
		tag = data[i++];
		if (cmd == TPMD_CMD_GET_DATA)
			len = 0;
		else
			len = data[i++] << 8;
		len |= data[i++];
		val = &data[i];

		switch (tag) {
		case TPMD_DT_PROTOCOL_VERSION:
			if (len != 1)
				break;
			protocol_version = val[0];
			break;
		case TPMD_DT_TPM_VERSION:
			if (len != 1)
				break;
			tpm_version = val[0];
			break;
		case TPMD_DT_FAB_CA_CERT:
			buffer_copy(&fab_ca_cert, val, len);
			break;
		case TPMD_DT_DATABLOCK_SIGNED:
			buffer_copy(&datablock_signed, val, len);
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

static int tpm2_validate_cert(const unsigned char *leaf, size_t leaflen)
{
	const unsigned char *ptr;
	X509_STORE *store;
	X509 *cacert;
	int ret = -1;

	OpenSSL_add_all_algorithms();

	ptr = tpm2_root_cert;
	cacert = d2i_X509(NULL, &ptr, sizeof(tpm2_root_cert));

	store = X509_STORE_new();
	X509_STORE_add_cert(store, cacert);

	if (leaf && leaflen) {
		X509 *cert = d2i_X509(NULL, &leaf, leaflen);
		X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();

		X509_STORE_CTX_init(store_ctx, store, cert, NULL);
		if (X509_verify_cert(store_ctx) == 1)
			ret = 0;
		X509_STORE_CTX_free(store_ctx);
		X509_free(cert);
	}

	X509_STORE_free(store);
	X509_free(cacert);
	return ret;
}

static inline void tpm2_xor(unsigned char *dest, const unsigned char *s1, const unsigned char *s2, unsigned int len)
{
	while (len--)
		*dest++ = *s1++ ^ *s2++;
}

static int tpm2_oaep_sha256_decode(unsigned char *msg, unsigned int len, const char *label)
{
	unsigned int buf_len = len - (2 * SHA256_DIGEST_LENGTH) - 2;
	unsigned char *pad = &msg[SHA256_DIGEST_LENGTH];
	unsigned char seed[SHA256_DIGEST_LENGTH];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int msg_end;
	unsigned int i;

	if (buf_len < SHA256_DIGEST_LENGTH)
		return -1;

	buf_len -= buf_len % SHA256_DIGEST_LENGTH;
	msg_end = buf_len;

	SHA256(pad, buf_len + SHA256_DIGEST_LENGTH, hash);
	tpm2_xor(seed, &pad[buf_len + SHA256_DIGEST_LENGTH], hash, SHA256_DIGEST_LENGTH);

	for (i = 0; i < buf_len + SHA256_DIGEST_LENGTH; i += SHA256_DIGEST_LENGTH) {
		SHA256(seed, SHA256_DIGEST_LENGTH, hash);
		tpm2_xor(&pad[i], &pad[i], hash, SHA256_DIGEST_LENGTH);
		seed[0]++;
	}

	/* check label */
	SHA256((const unsigned char *)label, strlen(label), hash);
	if (memcmp(&pad[buf_len], hash, SHA256_DIGEST_LENGTH))
		return -1;

	while (msg_end && pad[msg_end - 1] == 0)
		msg_end--;

	memmove(msg, pad, msg_end);
	memset(&msg[msg_end], 0, len - msg_end);
	return msg_end;
}

static int tpm2_ca_decrypt(const unsigned char *in, unsigned int ilen,
                           const unsigned char *der, unsigned int derlen,
                           unsigned char *out, unsigned int olen)
{
	EVP_PKEY *pkey;
	RSA *key;
	X509 *cert;
	unsigned int rsalen;

	if (olen < ilen)
		return -1;

	cert = d2i_X509(NULL, &der, derlen);
	pkey = X509_get_pubkey(cert);
	X509_free(cert);

	key = EVP_PKEY_get1_RSA(pkey);
	EVP_PKEY_free(pkey);

	rsalen = RSA_size(key);
	RSA_public_encrypt(ilen, in, out, key, RSA_NO_PADDING);
	RSA_free(key);

	if (ilen < rsalen)
		return -1;

	return tpm2_oaep_sha256_decode(out, rsalen, "dreambox");
}

static bool dump_ca(void)
{
	unsigned char mod[128];
	unsigned char buf[512];
	const unsigned char *ca, *data;
	const unsigned char *pca;
	unsigned int i, len;
	unsigned int cs;
	unsigned char dtag, dlen;
	unsigned int ca_version;
	int ca_size;

	if (!(fab_ca_cert && datablock_signed)) {
		fprintf(stderr, "incomplete data\n");
		return false;
	}

	if (tpm_version == 1) {
		if (fab_ca_cert->size != 210 || datablock_signed->size != 128) {
			fprintf(stderr, "invalid data size\n");
			return false;
		}
		if (!validate_cert(mod, fab_ca_cert->data, tpm_root_mod)) {
			fprintf(stderr, "could not verify fab_ca_cert\n");
			return false;
		}
		if (!decrypt_block(buf, datablock_signed->data, 128, mod)) {
			fprintf(stderr, "could not decrypt signed block\n");
			return false;
		}

		ca = &buf[1];
		ca_size = 126;
		ca_version = 2;
	} else if (tpm_version == 2) {
		if (tpm2_validate_cert(fab_ca_cert->data, fab_ca_cert->size) != 0) {
			fprintf(stderr, "could not verify fab_ca_cert\n");
			return false;
		}
		ca_size = tpm2_ca_decrypt(datablock_signed->data, datablock_signed->size, fab_ca_cert->data, fab_ca_cert->size, buf, sizeof(buf));
		if (ca_size < 3) {
			fprintf(stderr, "could not decrypt signed block\n");
			return false;
		}

		ca = buf;
		ca_version = 3;
	}

	if (ca[0] != 0xca) {
		fprintf(stderr, "invalid CA tag\n");
		return false;
	}

	if (ca[1] != ca_version) {
		fprintf(stderr, "unknown CA version\n");
		return false;
	}

	len = ca[2];
	if (ca_version == 2) {
		if (len < 3) {
			fprintf(stderr, "invalid CA length #1\n");
			return false;
		}
		len -= 3;
	}

	if (len + 3 > (unsigned int)ca_size) {
		fprintf(stderr, "invalid CA length #2\n");
		return false;
	}

	// CA VI LI .. .. FF 01 CS
	cs = 0;
	for (i = 0; i < len + 3; i++)
		cs ^= ca[i];

	if (cs != 0) {
		fprintf(stderr, "invalid CA checksum\n");
		if (ca_version > 2)
			return false;
	}

	pca = &ca[3];

	for (i = 0; i < len; i += dlen) {
		if (i + 2 > len) {
			fprintf(stderr, "invalid CA length #3\n");
			return false;
		}

		dtag = pca[i++];
		dlen = pca[i++];

		if (i + dlen > len) {
			fprintf(stderr, "invalid CA length #4\n");
			return false;
		}

		data = dlen ? &pca[i] : NULL;

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
		fprintf(stderr, "invalid CA length #5\n");
		return false;
	}

	return true;
}

static bool read_ca(int fd)
{
	unsigned char buf[2];
	unsigned int tag, len;
	unsigned char *val;
	enum tpmd_cmd cmd;

	buf[0] = TPMD_DT_PROTOCOL_VERSION;
	buf[1] = TPMD_DT_TPM_VERSION;
	if (!send_cmd(fd, TPMD_CMD_GET_DATA, buf, 2))
		return false;

	val = recv_cmd(fd, &tag, &len);
	if (val == NULL)
		return false;
	assert(tag == TPMD_CMD_GET_DATA);
	parse_data(tag, val, len);
	free(val);

	if (tpm_version < 1 || tpm_version > 2) {
		fprintf(stderr, "unsupported tpm version\n");
		return false;
	}

	if (tpm_version > 1 && protocol_version < 3) {
		fprintf(stderr, "invalid protocol version\n");
		return false;
	}

	buf[0] = TPMD_DT_FAB_CA_CERT;
	buf[1] = TPMD_DT_DATABLOCK_SIGNED;
	cmd = (protocol_version >= 3) ? TPMD_CMD_GET_DATA_V2 : TPMD_CMD_GET_DATA;
	if (!send_cmd(fd, cmd, buf, 2))
		return false;

	val = recv_cmd(fd, &tag, &len);
	if (val == NULL)
		return false;
	assert(tag == cmd);
	parse_data(tag, val, len);
	free(val);

	return dump_ca();
}

int main(void)
{
	struct sockaddr_un addr;
	int fd, retval = 1;
	int ret;

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

	ret = read_ca(fd) ? EXIT_SUCCESS : EXIT_FAILURE;

	free(fab_ca_cert);
	free(datablock_signed);

	return ret;
}
