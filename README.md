# Encrypted Vector Similarity (OpenFHE CKKS)

This repository contains a demo program that computes the maximum cosine similarity between a query and a database of unit vectors using the CKKS scheme from OpenFHE.

The executable is built as `encrypted_similarity` (Windows: `encrypted_similarity.exe`). The demo generates a synthetic database, encrypts it, computes encrypted cosine similarities against an encrypted query, reduces to the maximum value using a homomorphic comparator, and finally decrypts the result.

## What this project does

- Generates a database of unit vectors (default: 1000 vectors of 512 dimensions).
- Creates an OpenFHE CKKS context and keys.
- Packs vectors into CKKS plaintexts and encrypts them.
- Computes encrypted dot-products (cosine similarity) with the query using packed operations and a sum-reduction.
- Finds the encrypted maximum using a tournament-style comparator implemented with polynomial approximations.
- Decrypts the maximum value and prints accuracy/error against the plaintext max.

## Build requirements

- CMake 3.20 or newer
- A C++17-compatible compiler (MSYS2/MinGW or MSVC/Visual Studio)
- OpenFHE development build available and pointed to by `OpenFHE_ROOT` in `CMakeLists.txt`
- OpenMP (used for parallelism)

See `CMakeLists.txt` for the exact include/library paths used in this repo. By default the file sets:

- `OpenFHE_ROOT` to `c:/Users/Deepak/openfhe-development` (adjust this to your OpenFHE build)

## Build (Windows / MSYS2 pwsh)

Open a shell where CMake and your compiler are available (MSYS2 MinGW, or Developer Command Prompt for MSVC). Then:

```powershell
# create build directory and configure
> mkdir build; cd build
> cmake .. -DCMAKE_BUILD_TYPE=Release

# build the project
> cmake --build . --config Release -- /m

# resulting executable: build/encrypted_similarity.exe
```

If CMake fails to find OpenFHE, edit `CMakeLists.txt` and set `OpenFHE_ROOT` to the path where you built OpenFHE and its `build` directory.

## Run

From the `build` directory:

```powershell
> .\encrypted_similarity.exe
```

The program prints configuration details, progress for encryption/computation steps, and a final report including the decrypted encrypted max, plaintext max (computed locally for verification), absolute error, and a simple threshold decision.

## Key default constants (from `src/main.cpp`)

- DIMENSION: 512
- DATABASE SIZE: 1000 (variable `NUM_VECTORS` in `main.cpp`)
- THRESHOLD: 0.8 (variable `THRESHOLD`)
- CKKS parameters: multiplicative depth 40, scaling mod size 50, ring dimension 32768, batch size 8192

These values are set in `src/main.cpp` and can be tuned there.

## Notes

- The code uses OpenFHE high-level API types (e.g. `CryptoContextCKKSRNS`, `DCRTPoly`) and requires the include/library layout used when building OpenFHE.
- The current demo performs single-party key generation and decryption (for simplicity). The design notes describe a threshold/multiparty model, but the code in `src/main.cpp` performs a straightforward `Decrypt(secretKey, encryptedMaxSim, &result)` step.
- This README documents how to build and run the code as it exists in the repository. For production or multiparty usage, the key-generation and decryption flow must be adapted accordingly.
