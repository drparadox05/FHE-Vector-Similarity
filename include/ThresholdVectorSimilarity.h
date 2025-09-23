#pragma once

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
#include <string>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/ckksrns-scheme.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"

using namespace lbcrypto;
using namespace std;

struct VectorConfig
{
    size_t numVectors = 1000;
    size_t vecDim = 512;
    size_t batchSize = 32;
    int multDepth = 15;
    int thresholdT = 2;
    int numParties = 3;
    double threshold = 0.95;
    bool enableParallel = true;
    int numThreads = 4;
    bool useBootstrap = false;
    bool enableLogging = true;
};

class ThresholdVectorSimilarity
{
private:
    VectorConfig m_config;
    CryptoContext<DCRTPoly> m_cryptoContext;
    PublicKey<DCRTPoly> m_publicKey;
    vector<PrivateKey<DCRTPoly>> m_secretKeyShares;
    PrivateKey<DCRTPoly> m_simulationSecretKey;
    KeyPair<DCRTPoly> m_mainKeyPair;

    vector<int> m_rotationIndices;
    size_t m_slotsPerVector;
    size_t m_vectorsPerCiphertext;

    chrono::high_resolution_clock::time_point m_startTime;
    size_t m_processedVectors = 0;

public:
    ThresholdVectorSimilarity(VectorConfig config);

    void run();
    void setupCKKS();
    void generateThresholdKeys();

    vector<vector<double>> generateTestVectors(size_t numVectors, size_t dimension);
    string encryptVectorDatabaseToFile(const vector<vector<double>> &vectors);
    Ciphertext<DCRTPoly> encryptQueryVector(const vector<double> &q);

    Ciphertext<DCRTPoly> reorganizePackedResults(
        const Ciphertext<DCRTPoly> &sparseResults);
    Ciphertext<DCRTPoly> computeCosineSimilarity(const Ciphertext<DCRTPoly> &query, const Ciphertext<DCRTPoly> &dbvec);
    Ciphertext<DCRTPoly> computeStreamingApproximation(const string &dbFilePath, const Ciphertext<DCRTPoly> &encQuery);
    Ciphertext<DCRTPoly> computeBatchApproximation(vector<Ciphertext<DCRTPoly>> &sims);

    Ciphertext<DCRTPoly> pureAverage(const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b);
    Ciphertext<DCRTPoly> chebyshevMax(const Ciphertext<DCRTPoly> &a, const Ciphertext<DCRTPoly> &b);
    Ciphertext<DCRTPoly> tournamentMax(const vector<Ciphertext<DCRTPoly>> &sims);
    Ciphertext<DCRTPoly> reducePackedMaxToScalar(Ciphertext<DCRTPoly> ctPacked);

    double thresholdDecryptResult(const Ciphertext<DCRTPoly> &encryptedResult);
    bool computeThresholdDecision(double maxValue);

    double computePlaintextMaxSimilarity(const vector<double> &q, const vector<vector<double>> &db);
    void logProgress(const string &message);
    void logPerformance(const string &operation, chrono::milliseconds duration);

    void clearMemory();
    void optimizeMemoryUsage();
};