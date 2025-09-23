# Design Notes: Encrypted Biometric Similarity

So here's the deal - we need to find the maximum cosine similarity across a bunch of encrypted 512-D vectors without ever decrypting the individual similarities. Classic private information retrieval problem, but with a twist.

## Privacy Setup

### Threat Model

We assume the compute server is potentially compromised but the threshold parties are honest. Goal is to keep individual vectors private while revealing only the aggregated maximum.

### Threshold Approach

Using the classic t-of-n setup (going with 2-of-3 for the demo):

- Generate secret shares across multiple parties
- Compute server only gets public + evaluation keys
- Need t parties to collaborate for final decryption
- Each party provides partial decryption, then combine

This is basically the same pattern that Duality describes in their blog - nobody sees the full secret key, everyone contributes to the final result.

## Encrypted Computation

### Packing Strategy

CKKS gives us ~16k slots, and we need 512 per vector, so we can pack 32 vectors per ciphertext. This is huge for performance - instead of computing one similarity at a time, we get 32 in parallel. Storage efficiency is nice too (32x reduction).

### Computing Similarities

The packed approach means we:

1. Replicate the query across all 32 slots to match the database packing
2. Multiply element-wise (gives us 32 products simultaneously)
3. Do tree reduction within each 512-slot block to get the dot products
4. Mask out everything except the similarity values at positions 0, 512, 1024, etc.

### Finding the Max

We Can't just scan linearly because that would blow up our multiplicative depth. Instead:

- Within each ciphertext: tournament reduction of the 32 similarities
- Across ciphertexts: same tournament approach for batch maxima
- For the comparator: Chebyshev polynomial approximation of sign function
  - max(a,b) = (a+b)/2 + sign(a-b)·(a-b)/2
  - Degree-7 polynomial gets us close to 1e-4 accuracy

The polynomial approach is neat because it stays homomorphic throughout. No plaintext peeks.

## CKKS Parameters

Had to balance security vs performance here:

- Ring dim: 32,768 (gives us 128-bit security)
- Modulus: 50-bit initial + 40-bit scaling factors
- Depth budget: 100 levels (supports the polynomial operations)
- Auto-scaling to avoid manual rescaling headaches

The accuracy control comes from unit vector normalization (keeps similarities in [-1,1]) and choosing modulus sizes that preserve precision through the computation depth.

## Scaling to 1M Vectors

### The Plan

Three-tier reduction:

```
Tier 1: Local max per ciphertext (32 vectors → 1 max)
Tier 2: Shard max per file (1,000 ciphertexts → 1 max)
Tier 3: Global max across shards (32 shards → 1 max)
```

### Memory Strategy

The naive approach would blow up memory, so we shard the database:

- 32 shards of 32K vectors each for 1M total and stream one shard at a time

### Hardware Acceleration

GPUs could give you 10-50x speedup on the polynomial operations. For really large deployments, worth considering FPGA acceleration or even custom silicon.

## Error Analysis

The main error sources are:

1. CKKS quantization (~1.4×10⁻¹⁰ per operation)
2. Polynomial approximation (~8×10⁻⁶ for degree-7)
3. Accumulated noise (grows logarithmically)

To hit the 1e-4 target reliably, bump the polynomial degree to 9 or 11, increase the depth budget to 150+, and use larger modulus sizes. With optimizations, we can get down to ~6×10⁻⁷ error.

## Design Choices

Why these decisions?

- **CKKS vs BGV**: Approximate arithmetic is perfect for floating-point similarities
- **Threshold vs single-key**: Trust distribution, no single point of failure
- **Packing vs individual**: 32x efficiency gain is too good to pass up
- **Tournament vs linear**: O(log n) depth instead of O(n)
- **Streaming vs batch**: Only way to handle million-vector scale with reasonable memory
- **Polynomial vs lookup**: Keeps everything homomorphic

## Alternative Approaches

Could simplify by only outputting the boolean threshold decision instead of exact max similarity. Reduces complexity and error accumulation, might be sufficient for biometric matching.

Bootstrapping is disabled for performance, but if you need circuits deeper than 100 multiplicative levels, it's there. Just need careful parameter tuning.
