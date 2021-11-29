# Changes to support other algorithms
There are several changes needed to support other algorithms.

## Changes in Crypto Engine
The *opensslsigner.cc* shall be changed to support new algorithms. 
The constructor (line 846) must be changed to support the particular data of the new algorithm.
An example can be found down belox (this is only meant as inspiration):
```
#ifdef HAVE_LIBCRYPTO_FALCON
    if(d_algorithm == 17) {
      d_priv_len = 1281;
      d_pub_len = 897;
      d_sig_len = 690;
      d_id = NID_falcon512;
    }
#endif
#ifdef HAVE_LIBCRYPTO_X
    if(d_algorithm == ALGO_ID) {
      d_priv_len = Y;
      d_pub_len = Z;
      d_sig_len = Y;
      d_id = NID_ALGO;
    }
#endif
    if (d_priv_len == 0) {
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }
``` 
The *convertToISCVector()* function must also be changed to support the new algorithm like follows:
```
if(d_algorithm == ALGO_ID) {
    algorithm = "ALGO ID (Name_of_supported_algorithm)";
  }
```
Then the *create()* function needs to be updated to cop with the size of the new keys addding a condition in the first if conditional.

Finally the *LoaderStruct* needs to be enhanced to support the new algorithm adding following line after line 1280:
```
DNSCryptoKeyEngine::report(1x, &OpenSSLPQCDNSCryptoKeyEngine::maker);
```

## Changes to the configuration files
To be sure the algorithm is supported in the installation, change the *m4/pdns_check_libcrypto_pqc.m4* and add check for the new implemented algorithm using the following templates:
```
# Add checks for other NID algorithm here
  libcrypto_X=no
  
  AC_CHECK_DECLS([NID_X], [
    libcrypto_X=yes
    AC_DEFINE([HAVE_LIBCRYPTO_X], [1], [define to 1 if OpenSSL X support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$ssldir/include/openssl/evp.h>])
```
Also change the IF conditional at the end of the file to take extending algorithm into account.
```
AS_IF([test "$libcrypto_falcon" = "yes" -o "$libcrypto_X" = "yes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_PQC], [1], [define to 1 if OpenSSL PQC support is available.])
  ], [ : ])
```

