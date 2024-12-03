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

import os
from ..modules.modules import ModuleDilithium

try:
    from xoflib import shake256
except ImportError:
    from ..shake.shake_wrapper import shake256


class ML_DSA:
    def __init__(self, parameter_set):
        """
        https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#page=25
        """
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
        # use the method NIST SP 800-90A
        self.random_bytes = os.urandom

    """
    H() uses Shake256 to hash data to 32 and 64 bytes in a
    few places in the code
    """

    @staticmethod
    def H(input_bytes, length):
        """
        FIPS 202
        H(str, l) = SHAKE256(str, 8l)
        H: B^*  -> B^*
        """
        return shake256(input_bytes).read(length)

    def ExpandA(self, rho):
        """
        FIPS 204
        Samples a K * l matrix A-hat of elements of Tq
        generates a element of size k x l from a seed `rho`

        input: a seed `rho` of 32 bytes
        output: Matrix A consisting of elements of Tq and size k x l
        """
        # declare the A matrix
        A_hat = [[0 for s in range(self.l)] for r in range(self.k)]
        for r in range(self.k):
            for s in range(self.l):
                A_hat[r][s] = self.R.rejection_sample_ntt_poly(rho, r, s)  # type: ignore
        return self.M(A_hat)

    def ExpandS(self, rho_prime):
        """
        FIPS 204
        Samples a K * l matrix A-hat of elements of Tq
        generates a element of size k x l from a seed `rho`

        input: a seed `rho` of 32 bytes
        output: Matrix A consisting of elements of Tq and size k x l
        """
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

    def _expand_mask_vector(self, rho, mu):
        elements = [
            self.R.sample_mask_polynomial(rho, i, mu, self.gamma_1)
            for i in range(self.l)
        ]
        return self.M.vector(elements)

    @staticmethod
    def pkEncode(rho, t1):
        """  
        Algorithm 22
        Encodes a public key for ML-DSA into a byte string

        input: rho of 32 bytes, t1
        """
        return rho + t1.bit_pack_t1()

    def skEncode(self, rho, K, tr, s1, s2, t0):
        s1_bytes = s1.bit_pack_s(self.eta)
        s2_bytes = s2.bit_pack_s(self.eta)
        t0_bytes = t0.bit_pack_t0()
        return rho + K + tr + s1_bytes + s2_bytes + t0_bytes

    def _pack_h(self, h):
        non_zero_positions = [
            [i for i, c in enumerate(poly.coeffs) if c == 1]
            for row in h._data
            for poly in row
        ]
        packed = []
        offsets = []
        for positions in non_zero_positions:
            packed.extend(positions)
            offsets.append(len(packed))

        padding_len = self.omega - offsets[-1]
        packed.extend([0 for _ in range(padding_len)])
        return bytes(packed + offsets)

    def _pack_sig(self, c_tilde, z, h):
        return c_tilde + z.bit_pack_z(self.gamma_1) + self._pack_h(h)

    def _unpack_pk(self, pk_bytes):
        rho, t1_bytes = pk_bytes[:32], pk_bytes[32:]
        t1 = self.M.bit_unpack_t1(t1_bytes, self.k, 1)
        return rho, t1

    def _unpack_sk(self, sk_bytes):
        if self.eta == 2:
            s_bytes = 96
        else:
            s_bytes = 128
        s1_len = s_bytes * self.l
        s2_len = s_bytes * self.k
        t0_len = 416 * self.k
        if len(sk_bytes) != 2 * 32 + 64 + s1_len + s2_len + t0_len:
            raise ValueError("SK packed bytes is of the wrong length")

        # Split bytes between seeds and vectors
        sk_seed_bytes, sk_vec_bytes = sk_bytes[:128], sk_bytes[128:]

        # Unpack seed bytes
        rho, K, tr = (
            sk_seed_bytes[:32],
            sk_seed_bytes[32:64],
            sk_seed_bytes[64:128],
        )

        # Unpack vector bytes
        s1_bytes = sk_vec_bytes[:s1_len]
        s2_bytes = sk_vec_bytes[s1_len : s1_len + s2_len]
        t0_bytes = sk_vec_bytes[-t0_len:]

        # Unpack bytes to vectors
        s1 = self.M.bit_unpack_s(s1_bytes, self.l, 1, self.eta)
        s2 = self.M.bit_unpack_s(s2_bytes, self.k, 1, self.eta)
        t0 = self.M.bit_unpack_t0(t0_bytes, self.k, 1)

        return rho, K, tr, s1, s2, t0

    def _unpack_h(self, h_bytes):
        offsets = [0] + list(h_bytes[-self.k :])
        non_zero_positions = [
            list(h_bytes[offsets[i] : offsets[i + 1]]) for i in range(self.k)
        ]

        matrix = []
        for poly_non_zero in non_zero_positions:
            coeffs = [0 for _ in range(256)]
            for non_zero in poly_non_zero:
                coeffs[non_zero] = 1
            matrix.append([self.R(coeffs)])
        return self.M(matrix)

    def _unpack_sig(self, sig_bytes):
        c_tilde = sig_bytes[: self.c_tilde_bytes]
        z_bytes = sig_bytes[self.c_tilde_bytes : -(self.k + self.omega)]
        h_bytes = sig_bytes[-(self.k + self.omega) :]

        z = self.M.bit_unpack_z(z_bytes, self.l, 1, self.gamma_1)
        h = self._unpack_h(h_bytes)
        return c_tilde, z, h

    def keygen_internal(self, zeta):
        """
        Algorithm 6 Generates a public-private key pair from a seed

        input: seed zeta - random seed of 32 bytes
        output: public key and private key
        """
        # Expand with an XOF (SHAKE256)
        # concatenation of strings https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf#page=17
        seed_domain_sep = zeta + bytes([self.k]) + bytes([self.l])
        seed_bytes = self.H(seed_domain_sep, 128)

        # Split bytes into 32 sized chunks
        rho, rho_prime, K = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        # A hat is generated and stored in NTT representation as A hat
        A_hat = self.ExpandA(rho)

        # Generate the error vectors s1 ∈ R^l, s2 ∈ R^k
        (s1, s2) = self.ExpandS(rho_prime)

        # Matrix multiplication
        s1_hat = s1.to_ntt()  # type: ignore
        t = (A_hat @ (s1_hat)).from_ntt() + s2

        # compress T PowerTwoRound is applied componentwise
        t1, t0 = t.power_2_round(self.d)

        # Pack up the bytes
        pk = self.pkEncode(rho, t1)
        tr = self.H(pk, 64)
        sk = self.skEncode(rho, K, tr, s1, s2, t0)

        return (pk, sk)

    def _sign_internal(self, sk_bytes, m, rnd):
        """
        Deterministic algorithm to generate a signature for a formatted message
        M' following Algorithm 7 (FIPS 204)
        """
        # unpack the secret key
        rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)

        # Precompute NTT representation
        s1_hat = s1.to_ntt()  # type: ignore
        s2_hat = s2.to_ntt()  # type: ignore
        t0_hat = t0.to_ntt()  # type: ignore

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self.ExpandA(rho)

        # Set seeds and nonce (kappa)
        mu = self.H(tr + m, 64)
        rho_prime = self.H(K + rnd + mu, 64)

        kappa = 0
        alpha = self.gamma_2 << 1
        while True:
            y = self._expand_mask_vector(rho_prime, kappa)
            y_hat = y.to_ntt()  # type: ignore
            w = (A_hat @ y_hat).from_ntt()

            # increment the nonce
            kappa += self.l

            # NOTE: there is an optimisation possible where both the high and
            # low bits of w are extracted here, which speeds up some checks
            # below and requires the use of make_hint_optimised() -- to see the
            # implementation of this, look at the signing algorithm for
            # dilithium. We include this slower version to mirror the FIPS 204
            # document precisely.
            # Extract out only the high bits
            w1 = w.high_bits(alpha)

            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(self.gamma_2)
            c_tilde = self.H(mu + w1_bytes, self.c_tilde_bytes)
            c = self.R.sample_in_ball(c_tilde, self.tau)
            c_hat = c.to_ntt()

            # NOTE: unlike FIPS 204 we start again as soon as a vector
            # fails the norm bound to reduce any unneeded computations.
            c_s1 = s1_hat.scale(c_hat).from_ntt()
            z = y + c_s1
            if z.check_norm_bound(self.gamma_1 - self.beta):
                continue

            c_s2 = s2_hat.scale(c_hat).from_ntt()
            r0 = (w - c_s2).low_bits(alpha)
            if r0.check_norm_bound(self.gamma_2 - self.beta):
                continue

            c_t0 = t0_hat.scale(c_hat).from_ntt()
            if c_t0.check_norm_bound(self.gamma_2):
                continue

            h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
            if h.sum_hint() > self.omega:
                continue

            return self._pack_sig(c_tilde, z, h)

    def _verify_internal(self, pk_bytes, m, sig_bytes):
        """
        Internal function to verify a signature sigma for a formatted message M'
        following Algorithm 8 (FIPS 204)
        """
        rho, t1 = self._unpack_pk(pk_bytes)
        c_tilde, z, h = self._unpack_sig(sig_bytes)

        if h.sum_hint() > self.omega:  # type: ignore
            return False

        if z.check_norm_bound(self.gamma_1 - self.beta):  # type: ignore
            return False

        A_hat = self.ExpandA(rho)

        tr = self.H(pk_bytes, 64)
        mu = self.H(tr + m, 64)
        c = self.R.sample_in_ball(c_tilde, self.tau)

        # Convert to NTT for computation
        c = c.to_ntt()
        z = z.to_ntt()  # type: ignore

        t1 = t1.scale(1 << self.d)
        t1 = t1.to_ntt()

        Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
        Az_minus_ct1 = Az_minus_ct1.from_ntt()

        w_prime = h.use_hint(Az_minus_ct1, 2 * self.gamma_2)  # type: ignore
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)

        return c_tilde == self.H(mu + w_prime_bytes, self.c_tilde_bytes)

    def keygen(self):
        """
        Algorithm 1 ML-DSA.KeyGen()
        Generates a public-private key pair following

        output: public key and private key
        """
        zeta = self.random_bytes(32)  # choose random seed
        if not zeta:
            raise ValueError("Random bit generation failed")
        # pk, sk
        return self.keygen_internal(zeta)

    def sign(self, sk_bytes, m, ctx=b"", deterministic=False):
        """
        Generates an ML-DSA signature following
        Algorithm 2 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        if deterministic:
            rnd = bytes([0] * 32)
        else:
            rnd = self.random_bytes(32)

        # Format the message using the context
        m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

        # Compute the signature of m_prime
        sig_bytes = self._sign_internal(sk_bytes, m_prime, rnd)
        return sig_bytes

    def verify(self, pk_bytes, m, sig_bytes, ctx=b""):
        """
        Verifies a signature sigma for a message M following
        Algorithm 3 (FIPS 204)
        """
        if len(ctx) > 255:
            raise ValueError(
                f"ctx bytes must have length at most 255, ctx has length {len(ctx) = }"
            )

        # Format the message using the context
        m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

        return self._verify_internal(pk_bytes, m_prime, sig_bytes)
