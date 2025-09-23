#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <fstream>
#include <cmath>
#include <stdexcept>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <thread>
#include <future>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "ThresholdVectorSimilarity.h"

using namespace lbcrypto;
using namespace std;

ThresholdVectorSimilarity::ThresholdVectorSimilarity(VectorConfig config)
    : m_config(config)
{
    setupCKKS();
    generateThresholdKeys();
}

void ThresholdVectorSimilarity::setupCKKS()
{
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(m_config.multDepth);
    parameters.SetFirstModSize(50);
    parameters.SetScalingModSize(40);
    parameters.SetBatchSize(16384);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(32768);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);

    m_cryptoContext = GenCryptoContext(parameters);
    m_cryptoContext->Enable(PKE);
    m_cryptoContext->Enable(KEYSWITCH);
    m_cryptoContext->Enable(LEVELEDSHE);
    m_cryptoContext->Enable(ADVANCEDSHE);
    m_cryptoContext->Enable(MULTIPARTY);

    if (!m_cryptoContext)
    {
        throw runtime_error("Failed to create crypto context");
    }

    m_rotationIndices.clear();
    for (int r = 1; r < (int)m_config.vecDim; r <<= 1)
    {
        m_rotationIndices.push_back(r);
    }

    m_slotsPerVector = m_config.vecDim;
    size_t totalSlots = m_cryptoContext->GetRingDimension() / 2;
    m_vectorsPerCiphertext = (totalSlots >= m_slotsPerVector) ? totalSlots / m_slotsPerVector : 1;

    if (m_vectorsPerCiphertext == 0)
    {
        m_vectorsPerCiphertext = 1;
    }

    size_t blockShift = m_slotsPerVector;
    for (size_t step = 1; step < m_vectorsPerCiphertext; step <<= 1)
    {
        long rot = static_cast<long>(step * blockShift);
        if (rot < static_cast<long>(m_cryptoContext->GetRingDimension() / 2))
        {
            m_rotationIndices.push_back(static_cast<int>(rot));
        }
    }

    logProgress("CKKS context created");
    logProgress("Ring dimension: " + to_string(m_cryptoContext->GetRingDimension()));
    logProgress("Slots per vector: " + to_string(m_slotsPerVector));
    logProgress("Vectors per ciphertext: " + to_string(m_vectorsPerCiphertext));
}

void ThresholdVectorSimilarity::generateThresholdKeys()
{
    logProgress("Generating threshold keys for " + to_string(m_config.numParties) + " parties...");

    // Generate main keypair
    auto kp1 = m_cryptoContext->KeyGen();
    // This creates shares where t-of-n parties are needed to decrypt
    auto kp2 = m_cryptoContext->MultipartyKeyGen(kp1.publicKey);
    vector<PrivateKey<DCRTPoly>> secretShares;
    secretShares.push_back(kp1.secretKey);

    for (int i = 1; i < m_config.numParties; i++)
    {
        auto kpNext = m_cryptoContext->MultipartyKeyGen(kp1.publicKey);
        secretShares.push_back(kpNext.secretKey);
    }

    vector<PrivateKey<DCRTPoly>> shareSubset;
    for (int i = 0; i < m_config.threshold; i++)
    {
        shareSubset.push_back(secretShares[i]);
    }

    m_publicKey = kp1.publicKey;
    m_secretKeyShares = secretShares;
    m_simulationSecretKey = kp1.secretKey;

    m_cryptoContext->EvalMultKeyGen(m_simulationSecretKey);
    m_cryptoContext->EvalRotateKeyGen(m_simulationSecretKey, m_rotationIndices);
}

void ThresholdVectorSimilarity::run()
{
    m_startTime = chrono::high_resolution_clock::now();
    logProgress("------- Privacy-First Verification -------");
    logProgress("Configuration: " + to_string(m_config.numVectors) + " vectors x " + to_string(m_config.vecDim) + "D");
    logProgress("Batch size: " + to_string(m_config.batchSize));
    logProgress("Threads: " + to_string(m_config.numThreads));

    auto database = generateTestVectors(m_config.numVectors, m_config.vecDim);
    auto query = generateTestVectors(1, m_config.vecDim)[0];
    auto ptStart = chrono::high_resolution_clock::now();
    double plaintextMax = computePlaintextMaxSimilarity(query, database);
    auto ptEnd = chrono::high_resolution_clock::now();

    logProgress("Plaintext max similarity: " + to_string(plaintextMax));
    logPerformance("Plaintext computation", chrono::duration_cast<chrono::milliseconds>(ptEnd - ptStart));
    string dbFile = encryptVectorDatabaseToFile(database);
    auto encQuery = encryptQueryVector(query);

    database.clear();
    database.shrink_to_fit();
    query.clear();
    query.shrink_to_fit();

    auto encStart = chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> encResult = computeStreamingApproximation(dbFile, encQuery);
    auto encEnd = chrono::high_resolution_clock::now();
    logPerformance("Encrypted pipeline", chrono::duration_cast<chrono::milliseconds>(encEnd - encStart));
    double encResultValue = thresholdDecryptResult(encResult);
    bool isUnique = computeThresholdDecision(encResultValue);

    if (remove(dbFile.c_str()) != 0)
    {
        logProgress("Warning: Could not delete temporary file");
    }

    auto totalEnd = chrono::high_resolution_clock::now();
    auto totalDuration = chrono::duration_cast<chrono::milliseconds>(totalEnd - m_startTime);

    logProgress("------- OUTPUT -------");
    logProgress("Plaintext Max: " + to_string(plaintextMax));
    logProgress("Encrypted Result: " + to_string(encResultValue));
    logProgress("Absolute Error: " + to_string(abs(plaintextMax - encResultValue)));
    logProgress("Decision: " + string(isUnique ? "UNIQUE" : "NOT UNIQUE"));
    logPerformance("Total runtime", totalDuration);
}

vector<vector<double>> ThresholdVectorSimilarity::generateTestVectors(size_t numVectors, size_t dimension)
{
    logProgress("Generating " + to_string(numVectors) + " test vectors...");
    vector<vector<double>> vecs(numVectors, vector<double>(dimension));
    mt19937 gen(42);
    normal_distribution<double> dist(0.0, 1.0);

    if (m_config.enableParallel && numVectors > 100)
    {
        vector<future<void>> futures;
        size_t vectorsPerThread = numVectors / m_config.numThreads;

        for (int t = 0; t < m_config.numThreads; ++t)
        {
            size_t start = t * vectorsPerThread;
            size_t end = (t == m_config.numThreads - 1) ? numVectors : (t + 1) * vectorsPerThread;
            futures.push_back(async(launch::async, [&, start, end]()
                                    {
                mt19937 localGen(42 + t);
                normal_distribution<double> localDist(0.0, 1.0);
                for (size_t i = start; i < end; ++i) {
                    double norm = 0.0;
                    for (size_t j = 0; j < dimension; ++j) {
                        vecs[i][j] = localDist(localGen);
                        norm += vecs[i][j] * vecs[i][j];
                    }
                    norm = sqrt(norm);
                    if (norm == 0.0) norm = 1.0;
                    for (size_t j = 0; j < dimension; ++j) {
                        vecs[i][j] /= norm;
                    }
                } }));
        }

        for (auto &f : futures)
            f.wait();
    }
    else
    {
        for (size_t i = 0; i < numVectors; ++i)
        {
            double norm = 0.0;
            for (size_t j = 0; j < dimension; ++j)
            {
                vecs[i][j] = dist(gen);
                norm += vecs[i][j] * vecs[i][j];
            }
            norm = sqrt(norm);
            if (norm == 0.0)
                norm = 1.0;
            for (size_t j = 0; j < dimension; ++j)
            {
                vecs[i][j] /= norm;
            }
        }
    }

    logProgress("Vector generation complete");
    return vecs;
}

string ThresholdVectorSimilarity::encryptVectorDatabaseToFile(const vector<vector<double>> &vectors)
{
    logProgress("Encrypting database with packing...");
    const string fname = "encrypted_db.bin";
    ofstream ofs(fname, ios::binary);
    if (!ofs)
        throw runtime_error("Failed to create file: " + fname);

    size_t vectorsProcessed = 0;
    size_t ciphertextsCreated = 0;

    for (size_t i = 0; i < vectors.size(); i += m_vectorsPerCiphertext)
    {
        size_t vectorsToPack = min(m_vectorsPerCiphertext, vectors.size() - i);
        vector<double> packedData(m_cryptoContext->GetRingDimension() / 2, 0.0);
        for (size_t v = 0; v < vectorsToPack; ++v)
        {
            size_t startSlot = v * m_slotsPerVector;
            for (size_t j = 0; j < m_slotsPerVector && (startSlot + j) < packedData.size(); ++j)
            {
                packedData[startSlot + j] = vectors[i + v][j];
            }
        }

        Plaintext pt = m_cryptoContext->MakeCKKSPackedPlaintext(packedData);
        auto ct = m_cryptoContext->Encrypt(m_publicKey, pt);
        Serial::Serialize(ct, ofs, SerType::BINARY);
        vectorsProcessed += vectorsToPack;
        ciphertextsCreated++;

        if (vectorsProcessed % 100 == 0)
        {
            logProgress("Encrypted " + to_string(vectorsProcessed) + " vectors...");
        }
    }

    logProgress("Database encryption complete: " + to_string(vectorsProcessed) + " vectors in " + to_string(ciphertextsCreated) + " ciphertexts");
    return fname;
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::encryptQueryVector(const vector<double> &q)
{
    logProgress("Encrypting query vector (replicated to match packed DB)...");
    size_t slotCount = m_cryptoContext->GetRingDimension() / 2;
    vector<double> packedQuery(slotCount, 0.0);

    for (size_t b = 0; b < m_vectorsPerCiphertext; ++b)
    {
        size_t base = b * m_slotsPerVector;
        for (size_t i = 0; i < m_slotsPerVector; ++i)
        {
            packedQuery[base + i] = q[i];
        }
    }

    Plaintext pt = m_cryptoContext->MakeCKKSPackedPlaintext(packedQuery);
    auto ct = m_cryptoContext->Encrypt(m_publicKey, pt);
    logProgress("Query encrypted (level: " + to_string(ct->GetLevel()) + ")");
    return ct;
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::computeCosineSimilarity(
    const Ciphertext<DCRTPoly> &query,
    const Ciphertext<DCRTPoly> &dbvec)
{

    // When you have multiple vectors packed in one ciphertext,
    // you need to compute multiple dot products simultaneously
    auto product = m_cryptoContext->EvalMult(query, dbvec);
    Ciphertext<DCRTPoly> result = product;

    // Blocked reduction within each 512-slot block. Mask to prevent cross-block mixing.
    const size_t slotCount = m_cryptoContext->GetRingDimension() / 2;
    for (size_t offset = 1; offset < m_slotsPerVector; offset <<= 1)
    {
        auto rotated = m_cryptoContext->EvalRotate(result, static_cast<int>(offset));
        vector<double> mask(slotCount, 0.0);
        for (size_t b = 0; b < m_vectorsPerCiphertext; ++b)
        {
            size_t base = b * m_slotsPerVector;
            size_t end = min(base + m_slotsPerVector, slotCount);
            for (size_t j = base; j < end; ++j)
            {
                size_t jInBlock = j - base;
                if (jInBlock + offset < m_slotsPerVector)
                {
                    mask[j] = 1.0;
                }
            }
        }
        Plaintext maskPt = m_cryptoContext->MakeCKKSPackedPlaintext(mask);
        auto rotatedMasked = m_cryptoContext->EvalMult(rotated, maskPt);
        result = m_cryptoContext->EvalAdd(result, rotatedMasked);
    }

    vector<double> mask(m_cryptoContext->GetRingDimension() / 2, 0.0);
    for (size_t i = 0; i < m_vectorsPerCiphertext; i++)
    {
        mask[i * m_slotsPerVector] = 1.0;
    }
    Plaintext maskPt = m_cryptoContext->MakeCKKSPackedPlaintext(mask);
    result = m_cryptoContext->EvalMult(result, maskPt);

    return result;
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::reorganizePackedResults(
    const Ciphertext<DCRTPoly> &sparseResults)
{
    vector<Ciphertext<DCRTPoly>> extracted;
    for (size_t i = 0; i < m_vectorsPerCiphertext; i++)
    {
        // Rotate to bring position i*m_slotsPerVector to position 0
        auto rotated = m_cryptoContext->EvalRotate(sparseResults,
                                                   -static_cast<int>(i * m_slotsPerVector));

        vector<double> mask(m_cryptoContext->GetRingDimension() / 2, 0.0);
        mask[i] = 1.0;
        Plaintext maskPt = m_cryptoContext->MakeCKKSPackedPlaintext(mask);

        extracted.push_back(m_cryptoContext->EvalMult(rotated, maskPt));
    }

    Ciphertext<DCRTPoly> consolidated = extracted[0];
    for (size_t i = 1; i < extracted.size(); i++)
    {
        consolidated = m_cryptoContext->EvalAdd(consolidated, extracted[i]);
    }

    return consolidated;
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::computeStreamingApproximation(const string &dbFilePath, const Ciphertext<DCRTPoly> &encQuery)
{
    logProgress("Computing streaming approximation...");
    ifstream ifs(dbFilePath, ios::binary);

    if (!ifs)
        throw runtime_error("Cannot open database file: " + dbFilePath);

    Ciphertext<DCRTPoly> globalResult = nullptr;
    vector<Ciphertext<DCRTPoly>> batchSims;
    batchSims.reserve(m_config.batchSize);
    size_t count = 0;
    size_t numBatches = 0;
    m_processedVectors = 0;

    while (ifs.peek() != EOF)
    {
        Ciphertext<DCRTPoly> ct;
        Serial::Deserialize(ct, ifs, SerType::BINARY);
        if (ifs.fail())
            break;

        auto simPacked = computeCosineSimilarity(encQuery, ct);
        batchSims.push_back(std::move(simPacked));
        count += m_vectorsPerCiphertext;
        m_processedVectors += m_vectorsPerCiphertext;

        if (count > 0 && count % 200 == 0)
        {
            logProgress("Processed " + to_string(count) + " vectors...");
        }
    }

    if (!batchSims.empty())
    {
        auto batchResult = computeBatchApproximation(batchSims);
        if (globalResult == nullptr)
        {
            globalResult = batchResult;
        }
        else
        {
            vector<Ciphertext<DCRTPoly>> temp = {globalResult, batchResult};
            globalResult = tournamentMax(temp);
        }
    }

    if (globalResult == nullptr)
    {
        throw runtime_error("No vectors were processed from the database.");
    }

    globalResult = reducePackedMaxToScalar(globalResult);
    logProgress("Streaming computation complete. Processed " + to_string(count) + " vectors in " + to_string(numBatches + 1) + " batches.");
    return globalResult;
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::computeBatchApproximation(vector<Ciphertext<DCRTPoly>> &sims)
{
    if (sims.empty())
        throw runtime_error("Cannot process an empty batch.");

    return tournamentMax(sims);
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::tournamentMax(const vector<Ciphertext<DCRTPoly>> &sims)
{
    if (sims.size() == 1)
        return sims[0];

    vector<Ciphertext<DCRTPoly>> currentLevel = sims;
    while (currentLevel.size() > 1)
    {
        vector<Ciphertext<DCRTPoly>> nextLevel;
        nextLevel.reserve((currentLevel.size() + 1) / 2);

        for (size_t i = 0; i < currentLevel.size(); i += 2)
        {
            if (i + 1 < currentLevel.size())
            {
                nextLevel.push_back(chebyshevMax(currentLevel[i], currentLevel[i + 1]));
            }
            else
            {
                nextLevel.push_back(currentLevel[i]);
            }
        }
        currentLevel = move(nextLevel);
    }

    return currentLevel[0];
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::chebyshevMax(
    const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b)
{
    auto sum = m_cryptoContext->EvalAdd(a, b);
    auto diff = m_cryptoContext->EvalSub(a, b);

    // Chebyshev polynomial approximation of sign function
    auto x = m_cryptoContext->EvalMult(diff, 0.5);
    auto x2 = m_cryptoContext->EvalSquare(x);
    auto x3 = m_cryptoContext->EvalMult(x, x2);
    auto x5 = m_cryptoContext->EvalMult(x3, x2);
    auto x7 = m_cryptoContext->EvalMult(x5, x2);

    // Coefficients for degree-7 Chebyshev approximation of sign
    const double c1 = 1.2732395;
    const double c3 = -0.4058712;
    const double c5 = 0.1702815;
    const double c7 = -0.0678970;

    auto sign_approx = m_cryptoContext->EvalMult(x, c1);
    sign_approx = m_cryptoContext->EvalAdd(sign_approx,
                                           m_cryptoContext->EvalMult(x3, c3));
    sign_approx = m_cryptoContext->EvalAdd(sign_approx,
                                           m_cryptoContext->EvalMult(x5, c5));
    sign_approx = m_cryptoContext->EvalAdd(sign_approx,
                                           m_cryptoContext->EvalMult(x7, c7));

    auto avg = m_cryptoContext->EvalMult(sum, 0.5);
    auto signed_diff = m_cryptoContext->EvalMult(
        m_cryptoContext->EvalMult(sign_approx, diff), 0.5);

    return m_cryptoContext->EvalAdd(avg, signed_diff);
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::pureAverage(const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b)
{
    auto sum = m_cryptoContext->EvalAdd(a, b);
    return m_cryptoContext->EvalMult(sum, 0.5);
}

double ThresholdVectorSimilarity::thresholdDecryptResult(const Ciphertext<DCRTPoly> &encryptedResult)
{
    logProgress("Performing threshold decryption with " + to_string(m_config.thresholdT) + " parties...");
    vector<Ciphertext<DCRTPoly>> partialDecryptions;
    auto partialDec1 = m_cryptoContext->MultipartyDecryptLead(
        {encryptedResult}, m_secretKeyShares[0]);
    partialDecryptions.push_back(partialDec1[0]);

    for (int i = 1; i < m_config.threshold; i++)
    {
        auto partialDec = m_cryptoContext->MultipartyDecryptMain(
            {encryptedResult}, m_secretKeyShares[i]);
        partialDecryptions.push_back(partialDec[0]);
    }

    Plaintext plaintextResult;
    m_cryptoContext->MultipartyDecryptFusion(partialDecryptions, &plaintextResult);
    plaintextResult->SetLength(1);
    vector<double> vals = plaintextResult->GetRealPackedValue();

    return vals.empty() ? 0.0 : vals[0];
}

bool ThresholdVectorSimilarity::computeThresholdDecision(double result)
{
    bool isUnique = result < m_config.threshold;
    logProgress("Threshold check: " + to_string(result) + " < " + to_string(m_config.threshold) + " -> " + (isUnique ? "UNIQUE" : "NOT UNIQUE"));
    return isUnique;
}

double ThresholdVectorSimilarity::computePlaintextMaxSimilarity(const vector<double> &q, const vector<vector<double>> &db)
{
    double maxSim = -2.0;

    if (m_config.enableParallel && db.size() > 1000)
    {
        vector<future<double>> futures;
        size_t vectorsPerThread = db.size() / m_config.numThreads;

        for (int t = 0; t < m_config.numThreads; ++t)
        {
            size_t start = t * vectorsPerThread;
            size_t end = (t == m_config.numThreads - 1) ? db.size() : (t + 1) * vectorsPerThread;

            futures.push_back(async(launch::async, [&, start, end]()
                                    {
                double localMax = -2.0;
                for (size_t i = start; i < end; ++i) {
                    double sim = 0.0;
                    for (size_t j = 0; j < q.size(); ++j) {
                        sim += q[j] * db[i][j];
                    }
                    if (sim > localMax) localMax = sim;
                }
                return localMax; }));
        }

        for (auto &f : futures)
        {
            maxSim = max(maxSim, f.get());
        }
    }
    else
    {
        for (const auto &v : db)
        {
            double sim = 0.0;
            for (size_t i = 0; i < q.size(); ++i)
            {
                sim += q[i] * v[i];
            }
            if (sim > maxSim)
                maxSim = sim;
        }
    }

    return maxSim;
}

void ThresholdVectorSimilarity::logProgress(const string &message)
{
    if (m_config.enableLogging)
    {
        auto now = chrono::high_resolution_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - m_startTime);
        cout << "[" << elapsed.count() << "ms] " << message << endl;
    }
}

void ThresholdVectorSimilarity::logPerformance(const string &operation, chrono::milliseconds duration)
{
    if (m_config.enableLogging)
    {
        cout << "PERF: " << operation << " took " << duration.count() << "ms" << endl;
    }
}

void ThresholdVectorSimilarity::optimizeMemoryUsage()
{
    m_secretKeyShares.clear();
    m_secretKeyShares.shrink_to_fit();
}

Ciphertext<DCRTPoly> ThresholdVectorSimilarity::reducePackedMaxToScalar(Ciphertext<DCRTPoly> ctPacked)
{
    // Reduce across block maxima: combine block i with block i+shift (shift = m_slotsPerVector)
    size_t k = m_vectorsPerCiphertext;
    size_t shift = static_cast<size_t>(m_slotsPerVector);

    Ciphertext<DCRTPoly> acc = ctPacked;
    for (size_t step = 1; step < k; step <<= 1)
    {
        // rotate by step blocks (step * shift slots)
        int rot = static_cast<int>(step * shift);
        auto rotated = m_cryptoContext->EvalRotate(acc, rot);
        vector<Ciphertext<DCRTPoly>> temp = {acc, rotated};
        acc = tournamentMax(temp);
    }
    return acc;
}
