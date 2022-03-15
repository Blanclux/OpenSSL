/**
 * keyagree.c
 *  DH Program for OpenSSL 1.1
 *  wrtten by blanclux
 *  This software is distributed on an "AS IS" basis WITHOUT WARRANTY OF ANY KIND.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#if defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64)
#include <openssl/applink.c>
#endif

static const char rnd_seed[] = "The quick brown fox jumps over the lazy dog";

int
main(int argc, char *argv[])
{
	DH *a = NULL;
	DH *b = NULL;
	const BIGNUM *pa, *ga;
	BIGNUM *pb, *gb;
	const BIGNUM *prikeya, *pubkeya;
	const BIGNUM *prikeyb, *pubkeyb;
	int i, alen, blen, aout, bout, ck, ret = 1;
	int keyLen = 64;
	unsigned char *abuf = NULL, *bbuf = NULL;

	if (argc > 2) {
		fprintf(stderr, "%s [bitLen]\n", argv[0]);
		return 1;
	}
	if (argc == 2) {
		keyLen = atoi(argv[1]);
	}

	printf("< Diffie-Hellman key agreement >\n");
	RAND_seed(rnd_seed, sizeof rnd_seed);

	if (((a = DH_new()) == NULL)
		|| !DH_generate_parameters_ex(a, keyLen, DH_GENERATOR_5, NULL)) {
		goto err;
	}

	if (!DH_check(a, &ck)) {
		goto err;
	}
	if (ck & DH_CHECK_P_NOT_PRIME) {
		fprintf(stderr, "p value is not prime\n");
	}
	if (ck & DH_CHECK_P_NOT_SAFE_PRIME) {
		fprintf(stderr, "p value is not a safe prime\n");
	}
	if (ck & DH_UNABLE_TO_CHECK_GENERATOR) {
		fprintf(stderr, "unable to check the generator value\n");
	}
	if (ck & DH_NOT_SUITABLE_GENERATOR) {
		fprintf(stderr, "the g value is not a generator\n");
	}

	printf("\n");
	DHparams_print_fp(stdout, a);
	printf("\n");

	b = DH_new();
	if (b == NULL) {
		goto err;
	}

	DH_get0_pqg(a, &pa, NULL, &ga);
	pb = BN_dup(pa);
	gb = BN_dup(ga);
	DH_set0_pqg(b, pb, NULL, gb);

	/* A part */
	printf("< Part A >\n");
	if (!DH_generate_key(a)) {
		goto err;
	}
	DH_get0_key(a, &pubkeya, &prikeya);
	printf("  Private key 1 = ");
	BN_print_fp(stdout, prikeya);
	puts("");
	printf("  Public  key 1 = ");
	BN_print_fp(stdout, pubkeya);
	printf("\n");

	/* B part */
	printf("< Part B >\n");
	if (!DH_generate_key(b)) {
		goto err;
	}
	DH_get0_key(b, &pubkeyb, &prikeyb);
	printf("  Private key 2 = ");
	BN_print_fp(stdout, prikeyb);
	puts("");
	printf("  Public  key 2 = ");
	BN_print_fp(stdout, pubkeyb);
	puts("");

	/* A part */
	alen = DH_size(a);
	abuf = (unsigned char *) OPENSSL_malloc(alen);
	aout = DH_compute_key(abuf, pubkeyb, a);

	printf("< Key agreement >\n");
	printf(" Key length = %d (byte)\n", alen);
	printf("  Key 1 = ");
	for (i = 0; i < aout; i++) {
		printf("%02X", abuf[i]);
	}
	printf("\n");

	/* B part */
	blen = DH_size(b);
	printf(" Key length = %d (byte)\n", blen);
	bbuf = (unsigned char *) OPENSSL_malloc(blen);
	bout = DH_compute_key(bbuf, pubkeya, b);

	printf("  Key 2 = ");
	for (i = 0; i < bout; i++) {
		printf("%02X", bbuf[i]);
	}
	printf("\n");
	if ((aout < 4) || (bout != aout) || (memcmp(abuf, bbuf, aout) != 0)) {
		fprintf(stderr, "Error in DH routines\n");
		ret = 1;
	} else {
		ret = 0;
	}
  err:
	ERR_print_errors_fp(stderr);

	if (abuf != NULL)
		OPENSSL_free(abuf);
	if (bbuf != NULL)
		OPENSSL_free(bbuf);
	if (b != NULL)
		DH_free(b);
	if (a != NULL)
		DH_free(a);

	return ret;
}
