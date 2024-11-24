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

from xoflib import shake256
import os

from ml_dsa.modules.modules import ModuleDilithium


class ML_DSA:
    def __init__(self, parameter_set):
        self.d = parameter_set["d"]
        self.k = parameter_set["k"]
        self.l = parameter_set["l"]
        self.eta = parameter_set["eta"]
        self.tau = parameter_set["tau"]
        self.omega = parameter_set["omega"]
        self.gamma_1 = parameter_set["gamma_1"]
        self.gamma_2 = parameter_set["gamma_2"]
        self.beta = self.tau * self.eta
        self.c_tilde_bytes = parameter_set["c_tilde_bytes"]

        self.M = ModuleDilithium()
        self.R = self.M.ring

        # Use system randomness by default, for deterministic randomness
        # use the method `set_drbg_seed()`
        self.random_bytes = os.urandom

    def keygen(self):
        """
        Algorithm 1 ML-DSA.KeyGen()

        Generates a public-private key pair.
        Output: Public key, private key
        """
        zeta = self.random_bytes(32)  # choose random seed
        if not zeta:
            raise ValueError("Error generating random seed")
        # return pk, sk
        return self.keygen_internal(zeta)

    def keygen_internal(self, zeta):
        """
        Generates a public-private key pair from a seed following
        Algorithm 6 (FIPS 204)
        """
        # Expand with an XOF (SHAKE256)
        seed_domain_sep = zeta + bytes([self.k]) + bytes([self.l])
        seed_bytes = self._h(seed_domain_sep, 128)

        # Split bytes into suitable chunks
        rho, rho_prime, K = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self._expand_matrix_from_seed(rho)

        # Generate the error vectors s1 ∈ R^l, s2 ∈ R^k
        s1, s2 = self._expand_vector_from_seed(rho_prime)

        # Matrix multiplication
        s1_hat = s1.to_ntt()
        t = (A_hat @ s1_hat).from_ntt() + s2

        t1, t0 = t.power_2_round(self.d)

        # Pack up the bytes
        pk = self._pack_pk(rho, t1)
        tr = self._h(pk, 64)
        sk = self._pack_sk(rho, K, tr, s1, s2, t0)

        return pk, sk

    @staticmethod
    def _h(input_bytes, length):
        """
        H: B^*  -> B^*
        """
        return shake256(input_bytes).read(length)

    @staticmethod
    def _pack_pk(rho, t1):
        return rho + t1.bit_pack_t1()

    def _pack_sk(self, rho, K, tr, s1, s2, t0):
        s1_bytes = s1.bit_pack_s(self.eta)
        s2_bytes = s2.bit_pack_s(self.eta)
        t0_bytes = t0.bit_pack_t0()
        return rho + K + tr + s1_bytes + s2_bytes + t0_bytes

    def _expand_matrix_from_seed(self, rho):
        """
        Helper function which generates a element of size
        k x l from a seed `rho`.
        """
        A_data = [[0 for _ in range(self.l)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.l):
                A_data[i][j] = self.R.rejection_sample_ntt_poly(rho, i, j)
        return self.M(A_data)

    def _expand_vector_from_seed(self, rho_prime):
        s1_elements = [
            self.R.rejection_bounded_poly(rho_prime, i, self.eta) for i in range(self.l)
        ]
        s2_elements = [
            self.R.rejection_bounded_poly(rho_prime, i, self.eta)
            for i in range(self.l, self.l + self.k)
        ]

        s1 = self.M.vector(s1_elements)
        s2 = self.M.vector(s2_elements)
        return s1, s2

    def set_drbg_seed(self, seed):
        """
        Change entropy source to a DRBG and seed it with provided value.


        Setting the seed switches the entropy source from :func:`os.urandom()`
        to an AES256 CTR DRBG.


        Used for both deterministic versions of Kyber as well as testing
        alignment with the KAT vectors


        Note:
          currently requires pycryptodome for AES impl.
        """
        try:
            from .aes_ctr_drbg.aes_ctr_drbg import AES_CTR_DRBG

            self._drbg = AES_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_seed
        except ImportError as e:  # pragma: no cover
            print(f"Error importing AES from pycryptodome: {e = }")
            raise Warning(
                "Cannot set DRBG seed due to missing dependencies, try installing requirements: pip -r install requirements"
            )
