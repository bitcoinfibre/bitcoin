// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "bench.h"

#include "blockencodings.h"
#include "consensus/merkle.h"
#include "fec.h"
#include "random.h"
#include "txmempool.h"
#include "utiltime.h"

#include "version.h"
#include "streams.h"

#include "bench/data/block413567.hex.h"

#include <random>

std::vector<std::pair<uint256, CTransactionRef>> extra_txn;

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

class Receiver {
private:
    std::vector<unsigned char> data;
    std::unique_ptr<FECDecoder> decoder;
    PartiallyDownloadedChunkBlock partialBlock;
    bool header_done = false, block_done = false, expecting_full_block;
    size_t header_chunk_count, block_size;

    size_t *total_chunks_consumed, *total_chunks_in_mempool, *non_fec_chunks;

public:
    Receiver(CTxMemPool& poolIn, size_t *total_chunks_consumed_in, size_t *total_chunks_in_mempool_in, size_t *non_fec_chunks_in, bool fIncludeBlock)
        : partialBlock(&poolIn), expecting_full_block(fIncludeBlock), total_chunks_consumed(total_chunks_consumed_in),
        total_chunks_in_mempool(total_chunks_in_mempool_in), non_fec_chunks(non_fec_chunks_in) {}

    ~Receiver() { if (expecting_full_block) assert(header_done && block_done); }

    void InitHeader(size_t header_size, size_t total_chunks) {
        header_chunk_count = DIV_CEIL(header_size, FEC_CHUNK_SIZE);
        decoder.reset(new FECDecoder(header_size, total_chunks));
        data.resize(DIV_CEIL(header_size, FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE);
        (*non_fec_chunks) += header_chunk_count;
    }

    void RecvHeaderChunk(const unsigned char* chunk, size_t idx) {
        if (header_done)
            return;

        assert(decoder->ProvideChunk(chunk, idx));
        if (decoder->DecodeReady()) {
            std::vector<unsigned char> header_data(header_chunk_count * FEC_CHUNK_SIZE);
            for (size_t i = 0; i < header_chunk_count; i++)
                memcpy(&header_data[i * FEC_CHUNK_SIZE], decoder->GetDataPtr(i), FEC_CHUNK_SIZE);

            CBlockHeaderAndLengthShortTxIDs shortIDs;
            VectorInputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
            stream >> shortIDs;

            assert(partialBlock.InitData(shortIDs, extra_txn) == READ_STATUS_OK);

            header_done = true;
        }
        (*total_chunks_consumed)++;
    }

    void InitBlock(size_t block_size_in, size_t total_chunks) {
        assert(header_done);

        block_size = block_size_in;
        decoder.reset(new FECDecoder(block_size, total_chunks));
        data.resize((total_chunks - DIV_CEIL(block_size, FEC_CHUNK_SIZE)) * FEC_CHUNK_SIZE);
        (*non_fec_chunks) += DIV_CEIL(block_size, FEC_CHUNK_SIZE);

        uint32_t total_chunk_count = 0;
        bool fDone = partialBlock.IsIterativeFillDone();
        while (!fDone) {
            size_t firstChunkProcessed;
            if (!total_chunk_count)
                total_chunk_count = partialBlock.GetChunkCount();
            ReadStatus res = partialBlock.DoIterativeFill(firstChunkProcessed);
            assert(res == READ_STATUS_OK);
            while (firstChunkProcessed < total_chunk_count && partialBlock.IsChunkAvailable(firstChunkProcessed)) {
                decoder->ProvideChunk(partialBlock.GetChunk(firstChunkProcessed), firstChunkProcessed);
                (*total_chunks_in_mempool)++;
                firstChunkProcessed++;
            }

            fDone = partialBlock.IsIterativeFillDone();
        }
    }

    bool RecvBlockChunk(const unsigned char* chunk, size_t idx) {
        if (block_done)
            return true;

        unsigned char *dest = NULL;
        if (idx >= DIV_CEIL(block_size, FEC_CHUNK_SIZE))
            dest = &data[(idx - DIV_CEIL(block_size, FEC_CHUNK_SIZE)) * FEC_CHUNK_SIZE];
        else if (!partialBlock.IsChunkAvailable(idx)) {
            dest = partialBlock.GetChunk(idx);
            memcpy(dest, chunk, FEC_CHUNK_SIZE);
            partialBlock.MarkChunkAvailable(idx);
        }
        if (dest == NULL)
            return false;

        assert(decoder->ProvideChunk(chunk, idx));

        (*total_chunks_consumed)++;

        if (decoder->DecodeReady()) {
            for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
                if (!partialBlock.IsChunkAvailable(i)) {
                    memcpy(partialBlock.GetChunk(i), decoder->GetDataPtr(i), FEC_CHUNK_SIZE);
                    partialBlock.MarkChunkAvailable(i);
                }
            }

            assert(partialBlock.FinalizeBlock() == READ_STATUS_OK);
            assert(partialBlock.GetBlock()->GetHash() == uint256S("0000000000000000025aff8be8a55df8f89c77296db6198f272d6577325d4069"));
            bool mutated;
            assert(partialBlock.GetBlock()->hashMerkleRoot == BlockMerkleRoot(*partialBlock.GetBlock(), &mutated));
            assert(!mutated);

            block_done = true;
            return true;
        }

        return false;
    }
};

void Send(CBlock& block, Receiver& recv, bool fIncludeBlock) {
    CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, true);
    ChunkCodedBlock fecBlock(block, headerAndIDs);

    std::vector<unsigned char> header_data;
    VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
    stream << headerAndIDs;

    size_t header_size = header_data.size();
    std::vector<unsigned char> header_fec_chunks(2*(DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10) * FEC_CHUNK_SIZE);
    FECEncoder header_encoder(&header_data, &header_fec_chunks);

    recv.InitHeader(header_size, DIV_CEIL(header_size, FEC_CHUNK_SIZE) + header_fec_chunks.size() / FEC_CHUNK_SIZE);

    std::mt19937 g(0xdeadbeef);

    for (size_t i = 0; i < DIV_CEIL(header_size, FEC_CHUNK_SIZE); i++) {
        std::vector<unsigned char>::iterator endit = header_data.begin() + std::min(header_size, (i+1) * FEC_CHUNK_SIZE);
        std::vector<unsigned char> chunk(header_data.begin() + i * FEC_CHUNK_SIZE, endit);
        chunk.resize(FEC_CHUNK_SIZE);
        if (g() & 3)
            recv.RecvHeaderChunk(&chunk[0], i);
    }

    for (size_t i = 0; i < 2 * DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10; i++) {
        assert(header_encoder.BuildChunk(i));
        if (g() & 3)
            recv.RecvHeaderChunk(&header_fec_chunks[i * FEC_CHUNK_SIZE], i + DIV_CEIL(header_size, FEC_CHUNK_SIZE));
    }

    if (!fIncludeBlock)
        return;

    size_t block_size = fecBlock.GetCodedBlock().size();
    std::vector<unsigned char> block_fec_chunks(2 * (DIV_CEIL(block_size, FEC_CHUNK_SIZE) + 10) * FEC_CHUNK_SIZE);
    FECEncoder block_encoder(&fecBlock.GetCodedBlock(), &block_fec_chunks);

    recv.InitBlock(block_size, DIV_CEIL(block_size, FEC_CHUNK_SIZE) + block_fec_chunks.size() / FEC_CHUNK_SIZE);

    for (size_t i = 0; i < block_fec_chunks.size() / FEC_CHUNK_SIZE; i++) {
        assert(block_encoder.BuildChunk(i));
        if (g() & 3)
            recv.RecvBlockChunk(&block_fec_chunks[i * FEC_CHUNK_SIZE], i + DIV_CEIL(block_size, FEC_CHUNK_SIZE));
    }

    for (size_t i = 0; i < block_size / FEC_CHUNK_SIZE; i++) {
        if (g() & 3)
            if (recv.RecvBlockChunk(&fecBlock.GetCodedBlock()[i * FEC_CHUNK_SIZE], i))
                return;
    }
}

// noinline here for easier profiling
void __attribute__((noinline)) DoRealFECedBlockRoundTripTest(benchmark::State& state, CTxMemPool& pool, CBlock& block, bool fIncludeBlock) {
    size_t total_chunks_consumed, total_chunks_in_mempool, non_fec_chunks;
    while (state.KeepRunning()) {
        total_chunks_consumed = 0;
        total_chunks_in_mempool = 0;
        non_fec_chunks = 0;
        Receiver recv(pool, &total_chunks_consumed, &total_chunks_in_mempool, &non_fec_chunks, fIncludeBlock);
        Send(block, recv, fIncludeBlock);
    }

    fprintf(stderr, "Ate %lu/%lu chunks after getting %lu for free\n", total_chunks_consumed, non_fec_chunks, total_chunks_in_mempool);
}

static void RealFECedBlockRoundTripTest(benchmark::State& state, int ntxn, bool fIncludeBlock=true)
{
    CBlock block;

    CDataStream stream((const char*)blockencodings_tests::block413567,
            (const char*)&blockencodings_tests::block413567[sizeof(blockencodings_tests::block413567)],
            SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    bool mutated;
    assert(block.hashMerkleRoot == BlockMerkleRoot(block, &mutated));
    assert(!mutated);
    assert(block.GetHash() == uint256S("0000000000000000025aff8be8a55df8f89c77296db6198f272d6577325d4069"));

    std::mt19937_64 g(0xdeadbeef);
    g(); // Because I like this more

    std::vector<CTransactionRef> vtx2(block.vtx.begin() + 1, block.vtx.end());
    std::shuffle(vtx2.begin(), vtx2.end(), g);

    CMutableTransaction txtmp;
    txtmp.vin.resize(1);
    txtmp.vout.resize(1);
    txtmp.vout[0].nValue = 10;

    CTxMemPool pool;
    for (int i = 0; i < ntxn; i++) {
        pool.addUnchecked(vtx2[i]->GetHash(), CTxMemPoolEntry(vtx2[i], 0, 0, 0, false, 0, LockPoints()));
        for (int j = 0; j < 32; j++) {
            txtmp.vin[0].prevout.hash = GetRandHash();
            pool.addUnchecked(txtmp.GetHash(), CTxMemPoolEntry(MakeTransactionRef(txtmp), 0, 0, 0, false, 0, LockPoints()));
        }
    }

    DoRealFECedBlockRoundTripTest(state, pool, block, fIncludeBlock);
}

static void FECBlockRTTTest0(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 0); }
static void FECBlockRTTTest0500(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 500); }
static void FECBlockRTTTest1000(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1000); }
static void FECBlockRTTTest1500(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1500); }
static void FECBlockRTTTest1550(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1550); }
static void FECBlockRTTTest1555(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1555); }

static void FECHeaderRTTTest1550(benchmark::State& state) { RealFECedBlockRoundTripTest(state, 1550, false); }

BENCHMARK(FECBlockRTTTest0);
BENCHMARK(FECBlockRTTTest0500);
BENCHMARK(FECBlockRTTTest1000);
BENCHMARK(FECBlockRTTTest1500);
BENCHMARK(FECBlockRTTTest1550);
BENCHMARK(FECBlockRTTTest1555);

BENCHMARK(FECHeaderRTTTest1550);

static void FECEncodeBenchmark(benchmark::State& state, bool fAll) {
    std::vector<unsigned char> data((const unsigned char*)blockencodings_tests::block413567,
            (const unsigned char*)&blockencodings_tests::block413567[sizeof(blockencodings_tests::block413567)]);

    while (state.KeepRunning()) {
        std::vector<unsigned char> fec(DIV_CEIL(data.size(), FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE);
        FECEncoder enc(&data, &fec);
        if (fAll)
            assert(enc.PrefillChunks());
        else
            assert(enc.BuildChunk(0));
    }
}

static void FECEncodeOneBenchmark(benchmark::State& state) { FECEncodeBenchmark(state, false); }
static void FECEncodeAllBenchmark(benchmark::State& state) { FECEncodeBenchmark(state, true); }

static void FECDecodeBenchmark(benchmark::State& state, unsigned mask) {
    std::vector<unsigned char> data((const unsigned char*)blockencodings_tests::block413567,
            (const unsigned char*)&blockencodings_tests::block413567[sizeof(blockencodings_tests::block413567)]);
    std::vector<unsigned char> fec(DIV_CEIL(data.size(), FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE);
    FECEncoder enc(&data, &fec);
    assert(enc.PrefillChunks());

    std::mt19937 g(0xdeadbeef);

    while (state.KeepRunning()) {
        size_t chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
        FECDecoder dec(data.size(), chunks * 2);
        for (size_t i = 0; i < chunks && !dec.DecodeReady(); i++) {
            if (g() & mask)
                assert(dec.ProvideChunk(&data[i * FEC_CHUNK_SIZE], i));
        }

        for (size_t i = 0; i < chunks && !dec.DecodeReady(); i++) {
            if (g() & mask)
                assert(dec.ProvideChunk(&fec[i * FEC_CHUNK_SIZE], i + chunks));
        }

        assert(dec.DecodeReady());
    }
}

static void FECDecodeBenchmark3(benchmark::State& state) { FECDecodeBenchmark(state, 0x3); }
static void FECDecodeBenchmark7(benchmark::State& state) { FECDecodeBenchmark(state, 0x7); }
static void FECDecodeBenchmarkF(benchmark::State& state) { FECDecodeBenchmark(state, 0xf); }

BENCHMARK(FECEncodeAllBenchmark);
BENCHMARK(FECEncodeOneBenchmark);
BENCHMARK(FECDecodeBenchmark3);
BENCHMARK(FECDecodeBenchmark7);
BENCHMARK(FECDecodeBenchmarkF);
