from dilithium_py.ml_dsa import ML_DSA_44

# Example of signing
pk, sk = ML_DSA_44.keygen()
msg = b"Your message signed by ML_DSA"
sig = ML_DSA_44.sign(sk, msg)
assert ML_DSA_44.verify(pk, msg, sig)

# Verification will fail with the wrong msg or pk
assert not ML_DSA_44.verify(pk, b"", sig)
pk_new, sk_new = ML_DSA_44.keygen()
assert not ML_DSA_44.verify(pk_new, msg, sig)