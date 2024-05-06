# Changes to support other algorithms
There are several changes needed to support other algorithms.

## Changes in Crypto Engine
The *opensslsigner.cc* shall be changed to support new algorithms. 
The constructor (line 846) must be changed to support the particular data of the new algorithm.
An example can be found down belox (this is only meant as inspiration):
```
#ifdef HAVE_LIBCRYPTO_PQC
    if(d_algorithm == DNSSECKeeper::FALCON512) {
      d_priv_len = 1281;
      d_pub_len = 897;
      d_sig_len = 690;
      d_algname = "falcon512";
    } else if {
      d_priv_len = 2528;
      d_pub_len = 1312;
      d_sig_len = 2420;
      d_algname = "dilithium2";
    } else if {
      d_priv_len = 64;
      d_pub_len = 43;
      d_sig_len = 7856;
      d_algname = "sphincssha2128ssimple";
    }

#endif
#ifdef HAVE_LIBCRYPTO_PQC
    if(d_algorithm == ALGO_ID) {
      d_priv_len = Y;
      d_pub_len = Z;
      d_sig_len = Y;
      d_algname = ALGNAME;
    }
#endif
    if (d_priv_len == 0) {
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }
``` 
**Important:** The NID of the new algorithm should correspond to the NID declared in the OQS library.

The *convertToISCVector()* function must also be changed to support the new algorithm like follows:
```
if(d_algorithm == ALGO_ID) {
    algorithm = "ALGO ID (Name_of_supported_algorithm)";
  }
```
Then the *create()* function needs to be updated to cop with the size of the new keys addding a condition in the first if conditional.

Finally the *LoaderStruct* needs to be enhanced to support the new algorithm adding following line after line 1283:
```
#ifdef HAVE_LIBCRYPTO_X
    DNSCryptoKeyEngine::report(1x, &OpenSSLPQCDNSCryptoKeyEngine::maker);
#endif
```

## Changes to the configuration files
To be sure the algorithm is supported in the installation, change the *m4/pdns_check_libcrypto_pqc.m4* and add check for the new implemented algorithm using the following templates:
```
# Add checks for other NID algorithm here
  libcrypto_x=no
  
  AC_CHECK_DECLS([NID_X], [
    libcrypto_x=yes
    AC_DEFINE([HAVE_LIBCRYPTO_X], [1], [define to 1 if OpenSSL X support is available.])
  ], [ : ],
  [AC_INCLUDES_DEFAULT
  #include <$ssldir/include/openssl/evp.h>])
```
Also change the IF conditional at the end of the file to take extending algorithm into account.
```
AS_IF([test "$libcrypto_pqc" = "yes" -o "$libcrypto_x" = "yes"], [
    AC_DEFINE([HAVE_LIBCRYPTO_PQC], [1], [define to 1 if OpenSSL PQC support is available.])
  ], [ : ])
```

## Changes to the version file
In order to list the algorithm in the features, edit *version.cc* to add the new algorithm as follows:
```
#ifdef HAVE_LIBCRYPTO_X
    "libcrypto-x " <<
#endif
```

## Changes to pdnsutil
In order to support the new algorithm in pdnsutil, you have to edit *pdnsutil.cc* on line 2306 to add the new algorithm:
```
#if defined(HAVE_LIBCRYPTO_PQC
    cout<<"|ALGNAME";
#endif
```
also change the file on line 2706 and 3256 to add the following:
```
#if defined(HAVE_LIBCRYPTO_PQC)
      cerr << "|ALGNAME;
#endif
```

## Changes to DNSSEC Keeper
To start the file *dbnsseckeeper.hh* should be changed to support the new algorithm.
Firstly, the *keyalgorithm_t* enum on line 44 shall be enhanced with the new algorithm and ALgorithm ID.

Then the *shorthand2algorithm()* function shall be changed and a conditional for your algorithm should be added as follows:
```
if (pdns_iequals(algorithm, "x")) return X;
```
After that, change the *algorithm2name()* function and add a case as follows:
```
case X:
    return "x";
```

Then the *dbdnsseckeeper.cc* should be changed to support standard keysize of the new algorithm. For that change the *addKey()* function on line 91 and add a conditional block as follows:
```
else if(algorithm == DNSSECKeeper::X)
        bits = KEY_LENGTH_IN_BITS;
```

## Tests
Tests can be inmplemented and added in *testsigner.cc*. To run the general test provided by pdns, you should change the *dnssecinfra.cc* file and enhance the *testMakers()* funciton (line 273) and add a conditional to support the new algorithm keys length as follows:
```
else if(algo == DNSSECKeeper::X)
    bits = KEY_LENGTH;
```

## Documentation
In order for the newly supported algorithm to appears on the PDNS documentation the *settings.rst* file should be changed to list the new algorithm in the default-ksk-algorithm (line 338) and in the default-zsk-algorithm (line 471).

The *docs/dnssec/profile.rst* should be changed to list the new algorithm in the list of supporteed algorithms (line 19).

Finally the characteristic of the algorithm should be added in the *docs/manpages/pdnsutil.1.rst* (line 75) in the description of the *generate-zone-key*  command and the new algorithm should be added in the list on algorithm supported (line 40).
