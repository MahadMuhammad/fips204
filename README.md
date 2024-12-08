> [!NOTE]
> The code here is copied and modified from: https://github.com/GiacomoPope/dilithium-py
>
> I studied this code, as a part of my information security course.
>
> See, official Dilithium implementation: https://github.com/pq-crystals/dilithium
#### Example

```python
>>> from dilithium_py.ml_dsa import ML_DSA_44
>>>
>>> # Example of signing
>>> pk, sk = ML_DSA_44.keygen()
>>> msg = b"Your message signed by ML_DSA"
>>> sig = ML_DSA_44.sign(sk, msg)
>>> assert ML_DSA_44.verify(pk, msg, sig)
>>>
>>> # Verification will fail with the wrong msg or pk
>>> assert not ML_DSA_44.verify(pk, b"", sig)
>>> pk_new, sk_new = ML_DSA_44.keygen()
>>> assert not ML_DSA_44.verify(pk_new, msg, sig)
```

The above example would also work with the other NIST levels `ML_DSA_65` and `ML_DSA_87`.
