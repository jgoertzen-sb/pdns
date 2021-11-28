# Changes to support other algorithms
There are several changes needed to support other algorithms.

## Changes in Crypto Engine
The *opensslsigner.cc* shall be changed to support new algorithms. 
The constructor (line 846) must be changed to support the particular data of the new algorithm.
An example can be found down belox (this is only meant as inspiration):
```
if(d_algorithm == 17) {
      d_priv_len = 1281;
      d_pub_len = 897;
      d_sig_len = 690;
      d_id = NID_falcon512;
    } else if (d_algorithm == 1x) {
      //data of the new algorithm
    } else {
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }
``` 
The *convertToISCVector()* function must also be changed to support the new algorithm like follows:
```
if(d_algorithm == 1x) {
    algorithm = "1x (Name_of_supported_algorithm)";
  }
```
Then the *create()* function needs to be updated to cop with the size of the new keys addding a condition in the first if conditional.

Finally the *LoaderStruct* needs to be enhanced to support the new algorithm adding following line after line 1280:
```
DNSCryptoKeyEngine::report(1x, &OpenSSLPQCDNSCryptoKeyEngine::maker);
```

## Changes to the application
