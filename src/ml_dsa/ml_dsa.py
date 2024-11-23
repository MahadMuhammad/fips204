"""
This module is designed according to the specifications provided in
the NIST FIPS-204 document. You can see more about it here:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#page=27


The first eight functions are the core functions that are used to implement

Algorithm 1 ML-DSA.KeyGen()
Algorithm 2 ML-DSA.Sign(private key, message, context string)
Algorithm 3 ML-DSA.Verify(public key, message, signature, context string)
Algorithm 4 HashML-DSA.Sign(private key, message {0,1} Kleene-star, context string, pre-hash function)
    - In this algorithm, by default the context string is set to an empty string, though applications may specify the use
    of a non-empty context string.
Algorithm 5 HashML-DSA.Verify(public key, message {0,1} Kleene Star, signature, context string (a byte string of 255 or fewer bytes), pre-hash function)
Algorithm 6 ML-DSA.KeyGen_internal(seed {0,1,..,255}^(32+32k(bitlen(q-1)-d)))
Algorithm 7 ML-DSA.Sign_internal(private key, formatted message
, pre-message randomness or dummy variable)
Algorithm 8 ML-DSA.Verify_internal(public key, message, signature)
"""


class ML_DSA:
    pass
