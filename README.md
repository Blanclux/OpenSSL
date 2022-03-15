# OpenSSL    

OpenSSL test programs (for openssl ver.1.1 ～)  

- dsa_evp.c  
   DSA test program  
   usage: dsa_evp [keyLen]

- ec_elgamal.c  
  EC ElGamal test program  
  usage: ec_elgamal [EC curve name]
   
- eccurve.c    
   EC curve name listing program  
   usage: eccurve {-i nID | -n curveName}

-  ecdh.c  
   ECDH test program  
   usage: ecdh [nid]

- ecdh_evp.c  
  ECDH test program  
  usage: ecdh_evp [nid]

- ecdsa.c  
   ECDSA test program  
   usage: ecdsa [nID [EC curve name]]

- fipstest.c  
  FIPS PUB 140-2 test program   
  usage: fipstest

- keyagree.c  
  DH test program  
  usage: keyagree [bitLen]

- mdigest.c  
   Message digest test program  
   usage: mdigest inFile  outFile

- pwdcrypt.c  
  Password cipher test program  
  usage: pwdcrypt {-e | -d} passwd inFile  outFile

- rsa_evp.c  
  RSA test program  
  usage: rsa_evp plainText

- rsacrypt.c  
   RSA encrypt/decrypt & sign/verify test program  
   usage: rsacrypt plainText  

- scipher.c  
  Secret cipher test program  
  usage: scipher {-e | -d} inFile  outFile  

- vernam.c  
  Vernam encryption program    
  usage: vernam [-fFile] [-sSeed] {-e|-d} inFile outFile

