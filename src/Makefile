# Makefile for crypto programs

#OPENSSL_DIR = /usr/local/openssl
#INCDIR	= -I$(OPENSSL_DIR)/include

#LDFLAGS  = -L$(OPENSSL_DIR)/bin -lssl -lcrypto
LDFLAGS  = -lssl -lcrypto

CC  = gcc
RM = rm -f

CFLAGS	= -W -Wall -O3 $(INCDIR)
#CFLAGS	= -W -Wall -g -DDEBUG $(INCDIR)

.c.o:
	$(CC) -c $(CFLAGS) $<

PROGRAM = scipher mdigest fipstest ecdsa eccurve rsacrypt keyagree ecdh \
	vernam rsa_evp dsa_evp pwdcrypt ec_elgamal ecdh_evp

all: scipher mdigest fipstest ecdsa eccurve rsacrypt keyagree ecdh \
	vernam rsa_evp dsa_evp pwdcrypt ec_elgamal ecdh_evp

scipher: scipher.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

mdigest: mdigest.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

fipstest: fipstest.c
	$(CC) -o $@  $(CFLAGS) $< randgen_aes.c $(LDFLAGS)

ecdsa: ecdsa.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

eccurve: eccurve.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

rsacrypt: rsacrypt.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

keyagree: keyagree.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

ecdh: ecdh.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

ecdh_evp: ecdh_evp.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

vernam: vernam.c
	$(CC) -o $@  $(CFLAGS) $< randgen_aes.c $(LDFLAGS)

rsa_evp: rsa_evp.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

dsa_evp: dsa_evp.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

pwdcrypt: pwdcrypt.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

ec_elgamal: ec_elgamal.c
	$(CC) -o $@  $(CFLAGS) $< $(LDFLAGS)

clean:
	$(RM) *.o $(PROGRAM)
