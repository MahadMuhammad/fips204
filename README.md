# FIPS 204 ML-DSA Python Implementation

[![License MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/GiacomoPope/dilithium-py/blob/main/LICENSE)
[![GitHub CI](https://github.com/GiacomoPope/dilithium-py/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/GiacomoPope/dilithium-py/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

> :warning: **Under no circumstances should this be used for cryptographic applications.** This is an educational resource and not designed to be secure against any form of side-channel attack. Intended for learning and experimenting with ML-DSA and Dilithium.

## Overview
This repository contains a pure Python implementation of:
1. **ML-DSA**: NIST Module-Lattice-Based Digital Signature Standard following [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
2. **CRYSTALS-Dilithium**: Based on the latest [specification](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf) (v3.1).

## Disclaimer
`dilithium-py` is meant for learning about protocol mechanics and creating a clean, well-commented implementation.

## KATs
This implementation passes all Known Answer Test (KAT) vectors for `dilithium` and `ml_dsa`. KAT files are downloaded or generated and included in the repository.

## Dependencies
To install dependencies, run:
```bash
pip install -r requirements.txt
