# Encrypted Biometric Similarity System (OpenFHE CKKS)

**Privacy-preserving maximum cosine similarity computation over encrypted 512-dimensional vectors using threshold homomorphic encryption.**

This system demonstrates a complete solution for computing the maximum cosine similarity across an encrypted database without ever decrypting individual vectors. Only the final maximum similarity value and threshold decision are revealed through secure threshold decryption.


## Architecture

### Privacy Model

- **Threshold Decryption**: t-of-n multiparty scheme (default: 2-of-3)
- **No Full Secret Key**: Server only holds public and evaluation keys
- **Secure Computation**: All similarity computations performed homomorphically
- **Minimal Leakage**: Only final maximum similarity and threshold decision revealed
- **Polynomial Degree**: Use degree-7 Chebyshev approximation (configurable to 9/11)

### Core Components

1. **Vector Packing**: Multiple 512-D vectors per ciphertext for efficiency
2. **Encrypted Cosine Similarity**: Packed dot product computation
3. **Encrypted Maximum**: Tournament-style reduction with polynomial comparators
4. **Threshold Decision**: Encrypted comparison against configurable threshold τ

### System Requirements

- **OS**: Windows 10/11 (tested with MSYS2 MinGW)
- **Compiler**: C++17 compatible (GCC 9+ recommended)


## 🚀 Quick Start

### One-Command Build and Run

```bash
# Build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j

# Run demo
./encrypted_similarity.exe
```

### Expected Output

```
------- START -------

Configuration:
- Vectors: 100 x 512D
- Batch size: 32
- Multiplicative depth: 100
- Parallel processing: enabled
- Threads: 8
- Threshold: 0.95

[42ms] Generating threshold keys for 3 parties...
[156ms] CKKS context created
[158ms] Ring dimension: 32768
[159ms] Slots per vector: 512
[160ms] Vectors per ciphertext: 32
[162ms] Generating 100 test vectors...
[168ms] Vector generation complete
[169ms] Plaintext max similarity: 0.847523
[172ms] Encrypting database with packing...
[298ms] Database encryption complete: 100 vectors in 4 ciphertexts
[301ms] Encrypting query vector (replicated to match packed DB)...
[315ms] Query encrypted (level: 5)
[318ms] Computing streaming approximation...
[489ms] Streaming computation complete. Processed 100 vectors in 1 batches.
[492ms] Performing threshold decryption with 2 parties...

------- OUTPUT -------
[495ms] Plaintext Max: 0.847523
[495ms] Encrypted Result: 0.847441
[495ms] Absolute Error: 8.2e-05
[495ms] Decision: UNIQUE
PERF: Total runtime took 495ms

✓ system completed successfully!
```
