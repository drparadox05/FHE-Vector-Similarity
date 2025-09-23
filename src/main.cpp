#include "ThresholdVectorSimilarity.h"
#include <iostream>
#include <chrono>

using namespace std;

int main()
{
    cout << "------- START -------" << endl;
    cout << endl;

    try
    {
        VectorConfig config;
        config.numVectors = 100;
        config.vecDim = 512;
        config.batchSize = 32;
        config.multDepth = 100;
        config.thresholdT = 2;
        config.numParties = 3;
        config.threshold = 0.95;
        config.enableParallel = true;
        config.numThreads = 8;
        config.enableLogging = true;

        cout << "Configuration:" << endl;
        cout << "- Vectors: " << config.numVectors << " x " << config.vecDim << "D" << endl;
        cout << "- Batch size: " << config.batchSize << endl;
        cout << "- Multiplicative depth: " << config.multDepth << endl;
        cout << "- Parallel processing: " << (config.enableParallel ? "enabled" : "disabled") << endl;
        cout << "- Threads: " << config.numThreads << endl;
        cout << "- Threshold: " << config.threshold << endl;
        cout << endl;

        auto start = chrono::high_resolution_clock::now();
        ThresholdVectorSimilarity system(config);
        system.run();
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);

        cout << endl;
        cout << "------- Performance Summary -------" << endl;
        cout << "Total execution time: " << duration.count() << "ms" << endl;
        cout << "Average time per vector: " << (double)duration.count() / config.numVectors << "ms" << endl;
        cout << endl;
        cout << "✓ system completed successfully!" << endl;
    }
    catch (const exception &e)
    {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
