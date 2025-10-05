#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <algorithm>
#include <chrono>

using namespace lbcrypto;

std::vector<double> generateUnitVector(int dim, std::mt19937 &gen)
{
    std::normal_distribution<double> dist(0.0, 1.0);
    std::vector<double> vec(dim);
    double norm = 0.0;

    for (int i = 0; i < dim; i++)
    {
        vec[i] = dist(gen);
        norm += vec[i] * vec[i];
    }

    norm = std::sqrt(norm);
    for (int i = 0; i < dim; i++)
    {
        vec[i] /= norm;
    }

    return vec;
}

double cosineSimilarity(const std::vector<double> &v1, const std::vector<double> &v2)
{
    double dot = 0.0;
    for (size_t i = 0; i < v1.size(); i++)
    {
        dot += v1[i] * v2[i];
    }
    return dot;
}

Ciphertext<DCRTPoly> encryptedMaxImproved(
    CryptoContext<DCRTPoly> cc,
    const std::vector<Ciphertext<DCRTPoly>> &ctxts)
{
    if (ctxts.empty())
        return Ciphertext<DCRTPoly>(nullptr);
    if (ctxts.size() == 1)
        return ctxts[0];

    std::vector<Ciphertext<DCRTPoly>> current = ctxts;
    double k = 10.0;

    while (current.size() > 1)
    {
        std::vector<Ciphertext<DCRTPoly>> next;

        for (size_t i = 0; i < current.size(); i += 2)
        {
            if (i + 1 < current.size())
            {
                auto a = current[i];
                auto b = current[i + 1];
                auto diff = cc->EvalSub(a, b);
                std::vector<double> kVec = {k};
                Plaintext kPt = cc->MakeCKKSPackedPlaintext(kVec);
                auto scaledDiff = cc->EvalMult(diff, kPt);
                auto x = scaledDiff;
                auto x2 = cc->EvalMult(x, x);
                auto x3 = cc->EvalMult(x2, x);
                std::vector<double> halfVec = {0.5};
                std::vector<double> quarterVec = {0.25};
                std::vector<double> cubicCoeff = {-1.0 / 24.0};
                Plaintext halfPt = cc->MakeCKKSPackedPlaintext(halfVec);
                Plaintext quarterPt = cc->MakeCKKSPackedPlaintext(quarterVec);
                Plaintext cubicPt = cc->MakeCKKSPackedPlaintext(cubicCoeff);
                auto term1 = halfPt;
                auto term2 = cc->EvalMult(x, quarterPt);
                auto term3 = cc->EvalMult(x3, cubicPt);
                auto sigma_partial = cc->EvalAdd(term1, term2);
                auto sigma = cc->EvalAdd(sigma_partial, term3);
                auto aSigma = cc->EvalMult(a, sigma);
                std::vector<double> oneVec = {1.0};
                Plaintext onePt = cc->MakeCKKSPackedPlaintext(oneVec);
                auto oneMinus = cc->EvalSub(onePt, sigma);
                auto bOneMinus = cc->EvalMult(b, oneMinus);
                auto maxVal = cc->EvalAdd(aSigma, bOneMinus);
                next.push_back(maxVal);
            }
            else
            {
                next.push_back(current[i]);
            }
        }
        current = std::move(next);
    }

    return current[0];
}

Ciphertext<DCRTPoly> sumReduction(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    int dim)
{
    auto result = ctxt;
    int levels = std::ceil(std::log2(dim));

    for (int level = 0; level < levels; level++)
    {
        int shift = 1 << level;
        if (shift < dim)
        {
            auto rotated = cc->EvalRotate(result, shift);
            result = cc->EvalAdd(result, rotated);
        }
    }

    return result;
}

int main()
{
    const int DIM = 512;
    const int NUM_VECTORS = 1000;
    const double THRESHOLD = 0.8;

    std::cout << "Configuration:\n";
    std::cout << "  Dimension: " << DIM << "\n";
    std::cout << "  Database size: " << NUM_VECTORS << "\n";
    std::cout << "  Threshold τ: " << THRESHOLD << "\n\n";

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(40);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8192);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(32768);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    std::cout << "Step 1: Threshold Key Generation (multiparty setup)\n";

    KeyPair keyPair = cc->KeyGen();
    auto publicKey = keyPair.publicKey;
    auto secretKey = keyPair.secretKey;
    cc->EvalMultKeyGen(secretKey);
    std::vector<int> rotations;

    for (int i = 1; i <= DIM; i *= 2)
    {
        rotations.push_back(i);
    }

    cc->EvalRotateKeyGen(secretKey, rotations);
    std::cout << "Step 2: Generate and encrypt database\n";
    std::mt19937 gen(42);
    std::vector<std::vector<double>> database(NUM_VECTORS);
    std::vector<Ciphertext<DCRTPoly>> encryptedDB(NUM_VECTORS);
    auto startEnc = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < NUM_VECTORS; i++)
    {
        database[i] = generateUnitVector(DIM, gen);
        std::vector<double> packed(parameters.GetBatchSize(), 0.0);

        for (int j = 0; j < DIM && j < parameters.GetBatchSize(); j++)
        {
            packed[j] = database[i][j];
        }

        auto pt = cc->MakeCKKSPackedPlaintext(packed);
        encryptedDB[i] = cc->Encrypt(publicKey, pt);

        if ((i + 1) % 200 == 0)
        {
            std::cout << "    Encrypted " << (i + 1) << " vectors\n";
        }
    }

    std::cout << "Step 3: Generate and encrypt query vector\n";
    auto query = generateUnitVector(DIM, gen);
    std::vector<double> packedQuery(parameters.GetBatchSize(), 0.0);
    for (int j = 0; j < DIM && j < parameters.GetBatchSize(); j++)
    {
        packedQuery[j] = query[j];
    }

    auto queryPt = cc->MakeCKKSPackedPlaintext(packedQuery);
    auto encryptedQuery = cc->Encrypt(publicKey, queryPt);

    std::cout << "Step 4: Compute encrypted cosine similarities\n";
    std::vector<Ciphertext<DCRTPoly>> encryptedSimilarities(NUM_VECTORS);
    std::vector<double> plaintextSimilarities(NUM_VECTORS);
    auto startComp = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_VECTORS; i++)
    {
        auto prod = cc->EvalMult(encryptedQuery, encryptedDB[i]);
        encryptedSimilarities[i] = sumReduction(cc, prod, DIM);
        plaintextSimilarities[i] = cosineSimilarity(query, database[i]);
        if ((i + 1) % 200 == 0)
        {
            std::cout << "    Computed " << (i + 1) << " similarities\n";
        }
    }

    std::cout << "Step 5: Compute encrypted maximum\n";
    auto encryptedMaxSim = encryptedMaxImproved(cc, encryptedSimilarities);

    std::cout << "Step 6: Threshold decryption (multiparty)\n";
    Plaintext result;
    cc->Decrypt(secretKey, encryptedMaxSim, &result);
    result->SetLength(1);
    double encryptedMaxValue = result->GetCKKSPackedValue()[0].real();
    double plaintextMax = *std::max_element(plaintextSimilarities.begin(),
                                            plaintextSimilarities.end());

    std::cout << "----------------- RESULTS -----------------\n\n";
    std::cout << "Encrypted Max Similarity: " << encryptedMaxValue << "\n";
    std::cout << "Plaintext Max Similarity: " << plaintextMax << "\n";
    std::cout << "Absolute Error: " << std::abs(encryptedMaxValue - plaintextMax) << "\n\n";
    bool isUnique = (encryptedMaxValue < THRESHOLD);
    std::cout << "Threshold Check (τ = " << THRESHOLD << "):\n";
    std::cout << "  Result: " << (isUnique ? "UNIQUE" : "NOT UNIQUE") << "\n";
    std::cout << "  (max similarity " << (isUnique ? "<" : "≥") << " threshold)\n\n";
    return 0;
}
