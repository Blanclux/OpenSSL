/**
 * rsacrypt.c
 *  RSA Encrypt/Decrypt & Sign/Verify Test Program for OpenSSL 1.1
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#if defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64)
#include <openssl/applink.c>
#endif

#define KEYBIT_LEN	1024

static void
printHex(const char *title, const unsigned char *s, int len)
{
	int     n;
	printf("%s:", title);
	for (n = 0; n < len; ++n) {
		if ((n % 16) == 0) {
			printf("\n%04x", n);
		}
		printf(" %02x", s[n]);
	}
	printf("\n");
}

int
doCrypt(RSA *prikey, RSA *pubkey, unsigned char *data, int dataLen)
{
	int     i;
	int     encryptLen, decryptLen;
	unsigned char encrypt[1024], decrypt[1024];

	/* encrypt */
	encryptLen = RSA_public_encrypt(dataLen, data, encrypt, pubkey,
									RSA_PKCS1_OAEP_PADDING);
	// print data
	printHex("ENCRYPT", encrypt, encryptLen);
	printf("Encrypt length = %d\n", encryptLen);

	/* decrypt */
	decryptLen = RSA_private_decrypt(encryptLen, encrypt, decrypt, prikey,
									 RSA_PKCS1_OAEP_PADDING);
	printHex("DECRYPT", decrypt, decryptLen);
	if (dataLen != decryptLen) {
		return 1;
	}
	for (i = 0; i < decryptLen; i++) {
		if (data[i] != decrypt[i]) {
			return 1;
		}
	}

	return 0;
}

int
doSign(RSA *prikey, RSA *pubkey, unsigned char *data, int dataLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char sign[256];
	unsigned int signLen;
	int     ret;

	SHA256(data, dataLen, hash);

	/* Sign */
	ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
				   &signLen, prikey);
	printHex("SIGN", sign, signLen);
	printf("Signature length = %d\n", signLen);
	printf("RSA_sign: %s\n", (ret == 1) ? "OK" : "NG");

	/* Verify */
	ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
					 signLen, pubkey);
	printf("RSA_Verify: %s\n", (ret == 1) ? "true" : "false");

	return ret;
}

int
main(int argc, char *argv[])
{
	int     ret;
	char   *text = "The quick brown fox jumps over the lazy dog";
	RSA    *prikey, *pubkey;
	unsigned char *data;
	unsigned int dataLen;
	const BIGNUM  *p, *q, *n, *e, *d;
	BIGNUM  *n2, *e2, *d2;
	BIGNUM  *es;
	char    errbuf[1024];
	FILE   *priKeyFile;

	if (argc > 2) {
		fprintf(stderr, "%s plainText\n", argv[0]);
		return 1;
	}
	if (argc == 1) {
		data = (unsigned char *) text;
		dataLen = (unsigned int) strlen(text);
	} else {
		data = (unsigned char *) argv[1];
		dataLen = (unsigned int) strlen(argv[1]);
	}

	ERR_load_crypto_strings();

	/* generate private key & public key */
	es = BN_new();
	BN_set_word(es, RSA_F4);
	printf("< RSA Key Generation >\n");
	prikey = RSA_new();
	RSA_generate_key_ex(prikey, KEYBIT_LEN, es, NULL);
	if (prikey == NULL) {
		printf("RSA_generate_key: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}
	BN_free(es);
	priKeyFile = fopen("RSAPriKey.pem", "w");
	if (priKeyFile == NULL)	{
		perror("failed to fopen");
		return 1;
	}

	RSA_get0_key(prikey, &n, &e, &d);
	RSA_get0_factors(prikey, &p, &q);
	printf("p = ");
	BN_print_fp(stdout, p);
	puts("");
	printf("q = ");
	BN_print_fp(stdout, q);
	puts("");
	printf("n = ");
	BN_print_fp(stdout, n);
	puts("");
	printf("e = ");
	BN_print_fp(stdout, e);
	puts("");
	printf("d = ");
	BN_print_fp(stdout, d);

	/* write private key to file (PEM format) */
	if (PEM_write_RSAPrivateKey(priKeyFile, prikey, NULL, NULL, 0,
								NULL, NULL) != 1) {
		printf("PEM_write_RSAPrivateKey: err = %s\n",
			   ERR_error_string(ERR_get_error(), errbuf));
		return 1;
	}

	/* copy public keys */
	pubkey = RSA_new();
	n2 = BN_new();
	e2 = BN_new();
	d2 = BN_new();
	BN_copy(n2, n);
	BN_copy(e2, e);
	BN_copy(d2, d);
	RSA_set0_key(pubkey, n2, e2, d2);

	/* encrypt & decrypt */
	printf("\n< RSA Encrypt/Decrypt >\n");
	printHex("PLAIN", data, dataLen);

	ret = doCrypt(prikey, pubkey, data, dataLen);
	if (ret != 0) {
		printf("Encrypt/Decrypt Error.\n");
		return ret;
	}

	printf("\n< RSA Sign/verify >\n");
	ret = doSign(prikey, pubkey, data, dataLen);
	if (ret != 1) {
		printf("Sign/Verify Error.\n");
		return ret;
	}

	RSA_free(prikey);
	RSA_free(pubkey);

	fclose(priKeyFile);

	return 0;
}
