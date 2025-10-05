# Design Notes: Encrypted Vector Similarity

This document describes the design choices reflected in the current codebase (`src/main.cpp`) and the intended larger system.

## Scope of this repo vs production

- The code in this repository is a single-party demo: it performs KeyGen, Encrypt, Compute, and Decrypt using a single secret key in `main.cpp` for simplicity and verification.
- The design supports a threshold/multiparty model conceptually (t-of-n partial decryptions). The current code does not implement distributed key generation or partial decryption — that is left as a future integration.

## Core algorithm and packing

- Vector dimension: 512 (constant `DIM` in `main.cpp`).
- Database size (default): 1000 vectors (`NUM_VECTORS`).
- Packing/batch: code uses CKKS batch slots (`parameters.SetBatchSize(8192)`). Each plaintext stores a single vector in the first 512 slots; the remaining slots are zero.
- Similarity: cosine similarity computed as dot-product between unit vectors (vectors are normalized on generation). The code computes elementwise multiplication followed by a sum-reduction (rotations + additions) to obtain the dot product.

Implementation details found in `src/main.cpp`:

- `generateUnitVector(int dim, std::mt19937 &gen)` generates a random unit vector.
- `sumReduction(cc, ciphertext, dim)` performs tree-style rotations and adds to reduce per-slot products into the dot-product value.
- `encryptedMaxImproved(...)` performs a tournament reduction using polynomial-style soft-comparators to compute maxima between ciphertext values.

## Comparator and max reduction

- The comparator is implemented homomorphically using a small polynomial approximation built from scaled differences and low-degree terms (the demo implements a cubic-like correction around a sigmoid/step).
- Max of two values uses the identity max(a,b) = a·σ + b·(1-σ) where σ is an approximation of sign(a-b)/2 + 1/2. The tournament repeatedly reduces the candidate list by pairing neighbors until one ciphertext remains.

## CKKS parameters used in the demo

- Multiplicative depth: 40 (set in `parameters.SetMultiplicativeDepth(40)`).
- Scaling modulus size: 50 (set in `parameters.SetScalingModSize(50)`).
- Batch size: 8192 (set in `parameters.SetBatchSize(8192)`).
- Ring dimension: 32768 (set with `parameters.SetRingDim(32768)`).
- First modulus size: 60 (set with `parameters.SetFirstModSize(60)`).

These choices are conservative for the demo. They can be tuned for larger datasets or different comparator polynomial degrees.

## Practical points and limitations

- Single-key demo: The repo performs `cc->Decrypt(secretKey, encryptedMaxSim, &result);` and prints the decrypted value. To move to threshold decryption, implement distributed key generation, partial decryptions, and combination of partial results.
- Packing: the current code places one vector per plaintext into the first 512 slots. The larger packing strategies (storing multiple vectors per ciphertext) discussed in high-level design are not implemented in the demo and would require reorganizing plaintext layout and rotations accordingly.
- Performance: The demo is single-threaded for most crypto operations; OpenMP is enabled by CMake, and some operations may use parallelism depending on OpenFHE build options.

## Extending to production / large scale

If you want to scale this design to large databases or a true multiparty threshold setup, consider the following incremental steps:

1. Replace single-key decrypt with a threshold keygen and partial-decrypt API (OpenFHE supports distributed keygen primitives in recent versions).
2. Implement packing of multiple 512-D vectors per plaintext slot-layout to amortize expensive rotations (needs careful indexing and rotation key generation for offsets used by sumReduction).
3. Increase comparator polynomial degree (7→9→11) to reduce approximation error; increase multiplicative depth and modulus sizes accordingly.
4. Introduce sharding + streaming: compute local maxima per shard, persist intermediate maxima, then aggregate.
5. Add tests and accuracy regression checks comparing plaintext vs encrypted outputs across multiple random seeds and sizes.

## Error sources and mitigation

- CKKS approximation/quantization: normalize vectors to unit length before encryption; choose scaling/modulus parameters conservatively.
- Polynomial comparator error: increase polynomial degree and modulus budget for lower error.
- Noise growth: increase multiplicative depth and modulus sizes, or enable bootstrapping for unlimited depth (at a performance cost).

## Files of interest

- `src/main.cpp` — demo implementation and the authoritative place for runtime defaults.
- `CMakeLists.txt` — build configuration and expected OpenFHE paths.
