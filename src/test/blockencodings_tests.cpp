// Copyright (c) 2011-2019 The Bitcoin Core developers
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <blockencodings.h>
#include <consensus/merkle.h>
#include <chainparams.h>
#include <pow.h>
#include <streams.h>
#include <fec.h>
#include <random.h>

#include <test/setup_common.h>

#include "test/data/block413567.hex.h"

#include <boost/test/unit_test.hpp>
#include <random>

std::vector<std::pair<uint256, CTransactionRef>> extra_txn;

struct RegtestingSetup : public TestingSetup {
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(blockencodings_tests, RegtestingSetup)

static CBlock BuildBlockTestCase() {
    CBlock block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42;

    block.vtx.resize(3);
    block.vtx[0] = MakeTransactionRef(tx);
    block.nVersion = 42;
    block.hashPrevBlock = InsecureRand256();
    block.nBits = 0x207fffff;

    tx.vin[0].prevout.hash = InsecureRand256();
    tx.vin[0].prevout.n = 0;
    block.vtx[1] = MakeTransactionRef(tx);

    tx.vin.resize(FEC_CHUNK_SIZE / 38);
    for (size_t i = 0; i < tx.vin.size(); i++) {
        tx.vin[i].prevout.hash = InsecureRand256();
        tx.vin[i].prevout.n = 0;
    }
    size_t tx2Size = GetSerializeSize(tx, PROTOCOL_VERSION);
    assert(tx2Size > FEC_CHUNK_SIZE && tx2Size < 2*FEC_CHUNK_SIZE);
    block.vtx[2] = MakeTransactionRef(tx);

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    return block;
}

// Number of shared use_counts we expect for a tx we haven't touched
// (block + mempool + our copy from the GetSharedTx call)
constexpr long SHARED_TX_OFFSET{3};

BOOST_AUTO_TEST_CASE(SimpleRoundTripTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    LOCK2(cs_main, pool.cs);
    pool.addUnchecked(entry.FromTx(block.vtx[2]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    // Do a simple ShortTxIDs RT
    {
        CBlockHeaderAndShortTxIDs shortIDs(block, true);

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        BOOST_CHECK( partialBlock.IsTxAvailable(0));
        BOOST_CHECK(!partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

        size_t poolSize = pool.size();
        pool.removeRecursive(*block.vtx[2], MemPoolRemovalReason::REPLACED);
        BOOST_CHECK_EQUAL(pool.size(), poolSize - 1);

        CBlock block2;
        {
            PartiallyDownloadedBlock tmp = partialBlock;
            BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_INVALID); // No transactions
            partialBlock = tmp;
        }

        // Wrong transaction
        {
            PartiallyDownloadedBlock tmp = partialBlock;
            partialBlock.FillBlock(block2, {block.vtx[2]}); // Current implementation doesn't check txn here, but don't require that
            partialBlock = tmp;
        }
        bool mutated;
        BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));

        CBlock block3;
        BOOST_CHECK(partialBlock.FillBlock(block3, {block.vtx[1]}) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
}

class TestHeaderAndShortIDs {
    // Utility to encode custom CBlockHeaderAndShortTxIDs
public:
    CBlockHeader header;
    uint64_t nonce;
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

    explicit TestHeaderAndShortIDs(const CBlockHeaderAndShortTxIDs& orig) {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << orig;
        stream >> *this;
    }
    explicit TestHeaderAndShortIDs(const CBlock& block) :
        TestHeaderAndShortIDs(CBlockHeaderAndShortTxIDs(block, true)) {}

    uint64_t GetShortID(const uint256& txhash) const {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << *this;
        CBlockHeaderAndShortTxIDs base;
        stream >> base;
        return base.GetShortID(txhash);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(nonce);
        size_t shorttxids_size = shorttxids.size();
        READWRITE(VARINT(shorttxids_size));
        shorttxids.resize(shorttxids_size);
        for (size_t i = 0; i < shorttxids.size(); i++) {
            uint32_t lsb = shorttxids[i] & 0xffffffff;
            uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
            READWRITE(lsb);
            READWRITE(msb);
            shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
        }
        READWRITE(prefilledtxn);
    }
};

BOOST_AUTO_TEST_CASE(NonCoinbasePreforwardRTTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    LOCK2(cs_main, pool.cs);
    pool.addUnchecked(entry.FromTx(block.vtx[2]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    uint256 txhash;

    // Test with pre-forwarding tx 1, but not coinbase
    {
        TestHeaderAndShortIDs shortIDs(block);
        shortIDs.prefilledtxn.resize(1);
        shortIDs.prefilledtxn[0] = {1, block.vtx[1]};
        shortIDs.shorttxids.resize(2);
        shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[0]->GetHash());
        shortIDs.shorttxids[1] = shortIDs.GetShortID(block.vtx[2]->GetHash());

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        BOOST_CHECK(!partialBlock.IsTxAvailable(0));
        BOOST_CHECK( partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1); // +1 because of partialBlock

        CBlock block2;
        {
            PartiallyDownloadedBlock tmp = partialBlock;
            BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_INVALID); // No transactions
            partialBlock = tmp;
        }

        // Wrong transaction
        {
            PartiallyDownloadedBlock tmp = partialBlock;
            partialBlock.FillBlock(block2, {block.vtx[1]}); // Current implementation doesn't check txn here, but don't require that
            partialBlock = tmp;
        }
        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 2); // +2 because of partialBlock and block2
        bool mutated;
        BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));

        CBlock block3;
        PartiallyDownloadedBlock partialBlockCopy = partialBlock;
        BOOST_CHECK(partialBlock.FillBlock(block3, {block.vtx[0]}) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
        BOOST_CHECK(!mutated);

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 3); // +2 because of partialBlock and block2 and block3

        txhash = block.vtx[2]->GetHash();
        block.vtx.clear();
        block2.vtx.clear();
        block3.vtx.clear();
        BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1 - 1); // + 1 because of partialBlock; -1 because of block.
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET - 1); // -1 because of block
}

BOOST_AUTO_TEST_CASE(SufficientPreforwardRTTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    LOCK2(cs_main, pool.cs);
    pool.addUnchecked(entry.FromTx(block.vtx[1]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    uint256 txhash;

    // Test with pre-forwarding coinbase + tx 2 with tx 1 in mempool
    {
        TestHeaderAndShortIDs shortIDs(block);
        shortIDs.prefilledtxn.resize(2);
        shortIDs.prefilledtxn[0] = {0, block.vtx[0]};
        shortIDs.prefilledtxn[1] = {1, block.vtx[2]}; // id == 1 as it is 1 after index 1
        shortIDs.shorttxids.resize(1);
        shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[1]->GetHash());

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        BOOST_CHECK( partialBlock.IsTxAvailable(0));
        BOOST_CHECK( partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

        CBlock block2;
        PartiallyDownloadedBlock partialBlockCopy = partialBlock;
        BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
        BOOST_CHECK(!mutated);

        txhash = block.vtx[1]->GetHash();
        block.vtx.clear();
        block2.vtx.clear();
        BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1 - 1); // + 1 because of partialBlock; -1 because of block.
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET - 1); // -1 because of block
}

BOOST_AUTO_TEST_CASE(EmptyBlockRoundTripTest)
{
    CTxMemPool pool;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig.resize(10);
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 42;

    CBlock block;
    block.vtx.resize(1);
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
    block.nVersion = 42;
    block.hashPrevBlock = InsecureRand256();
    block.nBits = 0x207fffff;

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;

    // Test simple header round-trip with only coinbase
    {
        CBlockHeaderAndShortTxIDs shortIDs(block, false);

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        BOOST_CHECK(partialBlock.IsTxAvailable(0));

        CBlock block2;
        std::vector<CTransactionRef> vtx_missing;
        BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
        BOOST_CHECK(!mutated);
    }

    // Do a FEC-coded-block RT
    {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block);
        stream << headerAndIDs;

        ChunkCodedBlock fecBlock(block, headerAndIDs);
        BOOST_CHECK_EQUAL(fecBlock.GetCodedBlock().size(), FEC_CHUNK_SIZE);

        CBlockHeaderAndLengthShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedChunkBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        size_t firstChunkProcessed;
        while (!partialBlock.IsIterativeFillDone())
            BOOST_CHECK(partialBlock.DoIterativeFill(firstChunkProcessed) == READ_STATUS_OK);

        BOOST_CHECK(partialBlock.FinalizeBlock() == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), partialBlock.GetBlock()->GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(*partialBlock.GetBlock(), &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
}

BOOST_AUTO_TEST_CASE(SimpleBlockFECRoundTripTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    LOCK2(cs_main, pool.cs);
    pool.addUnchecked(entry.FromTx(CMutableTransaction(*block.vtx[2])));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET - 1);

    // Do a FEC-coded-block RT
    {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block);
        stream << headerAndIDs;

        ChunkCodedBlock fecBlock(block, headerAndIDs);
        BOOST_CHECK_EQUAL(fecBlock.GetCodedBlock().size(), 2 * FEC_CHUNK_SIZE);

        CBlockHeaderAndLengthShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedChunkBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        size_t firstChunkProcessed;
        while (!partialBlock.IsIterativeFillDone())
            BOOST_CHECK(partialBlock.DoIterativeFill(firstChunkProcessed) == READ_STATUS_OK);
        // Check the partial block picked txn in order: tx2, *
        BOOST_CHECK( partialBlock.IsChunkAvailable(0));
        BOOST_CHECK(!partialBlock.IsChunkAvailable(1));
        BOOST_CHECK(!memcmp(partialBlock.GetChunk(0), &fecBlock.GetCodedBlock()[0], FEC_CHUNK_SIZE));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

        memcpy(partialBlock.GetChunk(1), &fecBlock.GetCodedBlock()[FEC_CHUNK_SIZE], FEC_CHUNK_SIZE);
        partialBlock.MarkChunkAvailable(1);

        BOOST_CHECK(partialBlock.FinalizeBlock() == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), partialBlock.GetBlock()->GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(*partialBlock.GetBlock(), &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET - 1);
}

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

BOOST_AUTO_TEST_CASE(FECedBlockFECRoundTripTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    LOCK2(cs_main, pool.cs);
    pool.addUnchecked(entry.FromTx(CMutableTransaction(*block.vtx[2])));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET - 1);

    // Do a FEC-coded-block RT
    {
        size_t header_size, block_size;
        std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> header_fec_chunks(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[5]), std::forward_as_tuple(5));
        std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> block_fec_chunks(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[5]), std::forward_as_tuple(5));

        {
            CBlockHeaderAndLengthShortTxIDs headerAndIDs(block);
            ChunkCodedBlock fecBlock(block, headerAndIDs);

            std::vector<unsigned char> header_data;
            VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
            stream << headerAndIDs;
            BOOST_CHECK(BuildFECChunks(header_data, header_fec_chunks));
            header_size = header_data.size();

            BOOST_CHECK_EQUAL(fecBlock.GetCodedBlock().size(), 2 * FEC_CHUNK_SIZE);
            BOOST_CHECK(BuildFECChunks(fecBlock.GetCodedBlock(), block_fec_chunks));
            block_size = fecBlock.GetCodedBlock().size();
        }

        CBlockHeaderAndLengthShortTxIDs shortIDs2;
        {
            FECDecoder header_decoder(header_size);

            // Two header chunks shoud be more than sufficient
            BOOST_CHECK(header_decoder.ProvideChunk(&header_fec_chunks.first[0], header_fec_chunks.second[0]));
            BOOST_CHECK(header_decoder.ProvideChunk(&header_fec_chunks.first[1], header_fec_chunks.second[1]));
            BOOST_CHECK(header_decoder.DecodeReady());

            std::vector<unsigned char> header_data(DIV_CEIL(header_size, FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE);
            for (size_t i = 0; i < DIV_CEIL(header_size, FEC_CHUNK_SIZE); i++)
                memcpy(&header_data[i * FEC_CHUNK_SIZE], header_decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

            VectorInputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
            stream >> shortIDs2;
        }

        PartiallyDownloadedChunkBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
        size_t firstChunkProcessed;
        while (!partialBlock.IsIterativeFillDone())
            BOOST_CHECK(partialBlock.DoIterativeFill(firstChunkProcessed) == READ_STATUS_OK);
        // Check the partial block picked txn in order: tx2, *
        BOOST_CHECK( partialBlock.IsChunkAvailable(0));
        BOOST_CHECK(!partialBlock.IsChunkAvailable(1));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

        std::vector<unsigned char> block_data(block_size);
        {
            FECDecoder block_decoder(block_size);

            // Mempool gave us one chunk
            BOOST_CHECK(block_decoder.ProvideChunk(partialBlock.GetChunk(0), 0));

            // This (obviously) should not be sufficient
            BOOST_CHECK(!block_decoder.DecodeReady());

            BOOST_CHECK(block_decoder.ProvideChunk(&block_fec_chunks.first[2], block_fec_chunks.second[2]));
            // This might be sufficient
            if (!block_decoder.DecodeReady()) {
                // This might not be sufficient...check that adding the same chunk does nothing if its not
                BOOST_CHECK(block_decoder.ProvideChunk(&block_fec_chunks.first[2], block_fec_chunks.second[2]));
                BOOST_CHECK(!block_decoder.DecodeReady());

                // Adding another chunk might be sufficient
                BOOST_CHECK(block_decoder.ProvideChunk(&block_fec_chunks.first[3], block_fec_chunks.second[3]));
                if (!block_decoder.DecodeReady())
                    BOOST_CHECK(block_decoder.ProvideChunk(&block_fec_chunks.first[0], block_fec_chunks.second[0]));

                // But three FEC chunks should definitely be enough
                BOOST_CHECK(block_decoder.DecodeReady());
            }

            for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++)
                memcpy(&block_data[i * FEC_CHUNK_SIZE], block_decoder.GetDataPtr(i), FEC_CHUNK_SIZE);
        }

        BOOST_CHECK(!memcmp(partialBlock.GetChunk(0), &block_data[0], FEC_CHUNK_SIZE));

        memcpy(partialBlock.GetChunk(1), &block_data[FEC_CHUNK_SIZE], FEC_CHUNK_SIZE);
        partialBlock.MarkChunkAvailable(1);

        BOOST_CHECK(partialBlock.FinalizeBlock() == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), partialBlock.GetBlock()->GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(*partialBlock.GetBlock(), &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);
}

static void TestBlockWithMempool(const CBlock& block, CTxMemPool& pool) {
    // Do a FEC-coded-block RT
    size_t header_size, block_size;
    std::vector<std::pair<size_t, std::vector<unsigned char> > > header_chunks;
    std::vector<std::pair<size_t, std::vector<unsigned char> > > block_chunks;

    {
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block);
        ChunkCodedBlock fecBlock(block, headerAndIDs);

        std::vector<unsigned char> header_data;
        VectorOutputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
        stream << headerAndIDs;

        header_size = header_data.size();
        size_t header_fec_chunk_count = DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10;
        std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> header_fec_chunks(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[header_fec_chunk_count]), std::forward_as_tuple(header_fec_chunk_count));
        BOOST_CHECK(BuildFECChunks(header_data, header_fec_chunks));

        for (size_t i = 0; i < DIV_CEIL(header_size, FEC_CHUNK_SIZE); i++) {
            std::vector<unsigned char>::iterator endit = header_data.begin() + std::min(header_size, (i+1) * FEC_CHUNK_SIZE);
            header_chunks.push_back(std::make_pair(i,
                        std::vector<unsigned char>(header_data.begin() + i * FEC_CHUNK_SIZE, endit)));
            header_chunks.back().second.resize(FEC_CHUNK_SIZE);
        }
        for (size_t i = 0; i < DIV_CEIL(header_size, FEC_CHUNK_SIZE) + 10; i++)
            header_chunks.push_back(std::make_pair(header_fec_chunks.second[i],
                        std::vector<unsigned char>(((unsigned char*)&header_fec_chunks.first[i]), ((unsigned char*)&header_fec_chunks.first[i]) + FEC_CHUNK_SIZE)));

        block_size = fecBlock.GetCodedBlock().size();
        BOOST_CHECK(block_size % FEC_CHUNK_SIZE == 0);
        size_t block_fec_chunk_count = DIV_CEIL(block_size, FEC_CHUNK_SIZE) + 10;
        std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> block_fec_chunks(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[block_fec_chunk_count]), std::forward_as_tuple(block_fec_chunk_count));
        BOOST_CHECK(BuildFECChunks(fecBlock.GetCodedBlock(), block_fec_chunks));

        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++)
            block_chunks.push_back(std::make_pair(i,
                        std::vector<unsigned char>(fecBlock.GetCodedBlock().begin() + i * FEC_CHUNK_SIZE, fecBlock.GetCodedBlock().begin() + (i+1) * FEC_CHUNK_SIZE)));
        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE) + 10; i++)
            block_chunks.push_back(std::make_pair(block_fec_chunks.second[i],
                        std::vector<unsigned char>(((unsigned char*)&block_fec_chunks.first[i]), ((unsigned char*)&block_fec_chunks.first[i]) + FEC_CHUNK_SIZE)));
    }

    CBlockHeaderAndLengthShortTxIDs shortIDs;
    {
        size_t header_chunk_count = DIV_CEIL(header_size, FEC_CHUNK_SIZE);
        FECDecoder header_decoder(header_size);

        // Pass in random chunks until we have enough
        std::random_shuffle(header_chunks.begin(), header_chunks.end());
        for (size_t i = 0; i < header_chunks.size() - 5 && !header_decoder.DecodeReady(); i++)
            BOOST_CHECK(header_decoder.ProvideChunk(&header_chunks[i].second[0], header_chunks[i].first));
        BOOST_CHECK(header_decoder.DecodeReady());

        std::vector<unsigned char> header_data(header_chunk_count * FEC_CHUNK_SIZE);
        for (size_t i = 0; i < header_chunk_count; i++)
            memcpy(&header_data[i * FEC_CHUNK_SIZE], header_decoder.GetDataPtr(i), FEC_CHUNK_SIZE);

        VectorInputStream stream(&header_data, SER_NETWORK, PROTOCOL_VERSION);
        stream >> shortIDs;
    }

    PartiallyDownloadedChunkBlock partialBlock(&pool);
    BOOST_CHECK(partialBlock.InitData(shortIDs, extra_txn) == READ_STATUS_OK);
    size_t firstChunkProcessed;
    while (!partialBlock.IsIterativeFillDone())
        BOOST_CHECK(partialBlock.DoIterativeFill(firstChunkProcessed) == READ_STATUS_OK);

    if (!partialBlock.IsBlockAvailable()) {
        FECDecoder block_decoder(block_size);
        std::vector<std::pair<size_t, std::vector<unsigned char> > > block_chunks_sorted(block_chunks);

        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
            if (partialBlock.IsChunkAvailable(i)) {
                BOOST_CHECK(block_decoder.ProvideChunk(partialBlock.GetChunk(i), i));
                BOOST_CHECK(!memcmp(partialBlock.GetChunk(i), &block_chunks_sorted[i].second[0], FEC_CHUNK_SIZE));
            }
        }

        // Pass in random chunks until we have enough
        std::random_shuffle(block_chunks.begin(), block_chunks.end());
        for (size_t i = 0; i < block_chunks.size() - 5 && !block_decoder.DecodeReady(); i++)
            BOOST_CHECK(block_decoder.ProvideChunk(&block_chunks[i].second[0], block_chunks[i].first));

        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
            if (!partialBlock.IsChunkAvailable(i)) {
                memcpy(partialBlock.GetChunk(i), block_decoder.GetDataPtr(i), FEC_CHUNK_SIZE);
                partialBlock.MarkChunkAvailable(i);
            }
        }

        for (size_t i = 0; i < DIV_CEIL(block_size, FEC_CHUNK_SIZE); i++) {
            BOOST_CHECK(partialBlock.IsChunkAvailable(i));
            BOOST_CHECK(!memcmp(partialBlock.GetChunk(i), &block_chunks_sorted[i].second[0], FEC_CHUNK_SIZE));
        }
    }

    BOOST_CHECK(partialBlock.FinalizeBlock() == READ_STATUS_OK);
    BOOST_CHECK_EQUAL(block.GetHash().ToString(), partialBlock.GetBlock()->GetHash().ToString());
    bool mutated;
    BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(*partialBlock.GetBlock(), &mutated).ToString());
    BOOST_CHECK(!mutated);
}

BOOST_AUTO_TEST_CASE(RealFECedBlockRoundTripTest)
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

    for (size_t i = 0; i < 10; i++) {
        std::vector<CTransactionRef> vtx2(block.vtx.begin() + 1, block.vtx.end());
        std::shuffle(vtx2.begin(), vtx2.end(), g);

        size_t k = 0;
        for (size_t j = 1220; k < vtx2.size(); j /= 5) { // 1220 txn, 244 txn, 48 txn, 10 txn a few times
            j = std::max(j, (size_t)10);

            CTxMemPool pool;
            TestMemPoolEntryHelper entry;

            LOCK2(cs_main, pool.cs);
            for (const size_t k_init = k; k - k_init < j && k < vtx2.size(); k++)
                pool.addUnchecked(entry.FromTx(CMutableTransaction(*vtx2[k])));

            TestBlockWithMempool(block, pool);
        }
    }

    // Test with an empty mempool
    CTxMemPool pool;
    TestBlockWithMempool(block, pool);

    LOCK2(cs_main, pool.cs);
    // Test with all txn (except coinbase) available in mempool
    TestMemPoolEntryHelper entry;
    for (size_t i = 1; i < block.vtx.size(); i++)
        pool.addUnchecked(entry.FromTx(CMutableTransaction(*block.vtx[i])));
    TestBlockWithMempool(block, pool);
}

BOOST_AUTO_TEST_CASE(TransactionsRequestSerializationTest) {
    BlockTransactionsRequest req1;
    req1.blockhash = InsecureRand256();
    req1.indexes.resize(4);
    req1.indexes[0] = 0;
    req1.indexes[1] = 1;
    req1.indexes[2] = 3;
    req1.indexes[3] = 4;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << req1;

    BlockTransactionsRequest req2;
    stream >> req2;

    BOOST_CHECK_EQUAL(req1.blockhash.ToString(), req2.blockhash.ToString());
    BOOST_CHECK_EQUAL(req1.indexes.size(), req2.indexes.size());
    BOOST_CHECK_EQUAL(req1.indexes[0], req2.indexes[0]);
    BOOST_CHECK_EQUAL(req1.indexes[1], req2.indexes[1]);
    BOOST_CHECK_EQUAL(req1.indexes[2], req2.indexes[2]);
    BOOST_CHECK_EQUAL(req1.indexes[3], req2.indexes[3]);
}

BOOST_AUTO_TEST_CASE(TransactionsRequestDeserializationMaxTest) {
    // Check that the highest legal index is decoded correctly
    BlockTransactionsRequest req0;
    req0.blockhash = InsecureRand256();
    req0.indexes.resize(1);
    req0.indexes[0] = 0xffff;
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << req0;

    BlockTransactionsRequest req1;
    stream >> req1;
    BOOST_CHECK_EQUAL(req0.indexes.size(), req1.indexes.size());
    BOOST_CHECK_EQUAL(req0.indexes[0], req1.indexes[0]);
}

BOOST_AUTO_TEST_CASE(TransactionsRequestDeserializationOverflowTest) {
    // Any set of index deltas that starts with N values that sum to (0x10000 - N)
    // causes the edge-case overflow that was originally not checked for. Such
    // a request cannot be created by serializing a real BlockTransactionsRequest
    // due to the overflow, so here we'll serialize from raw deltas.
    BlockTransactionsRequest req0;
    req0.blockhash = InsecureRand256();
    req0.indexes.resize(3);
    req0.indexes[0] = 0x7000;
    req0.indexes[1] = 0x10000 - 0x7000 - 2;
    req0.indexes[2] = 0;
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << req0.blockhash;
    WriteCompactSize(stream, req0.indexes.size());
    WriteCompactSize(stream, req0.indexes[0]);
    WriteCompactSize(stream, req0.indexes[1]);
    WriteCompactSize(stream, req0.indexes[2]);

    BlockTransactionsRequest req1;
    try {
        stream >> req1;
        // before patch: deserialize above succeeds and this check fails, demonstrating the overflow
        BOOST_CHECK(req1.indexes[1] < req1.indexes[2]);
        // this shouldn't be reachable before or after patch
        BOOST_CHECK(0);
    } catch(std::ios_base::failure &) {
        // deserialize should fail
        BOOST_CHECK(true); // Needed to suppress "Test case [...] did not check any assertions"
    }
}

BOOST_AUTO_TEST_SUITE_END()
