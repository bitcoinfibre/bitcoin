// Copyright (c) 2016-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKENCODINGS_H
#define BITCOIN_BLOCKENCODINGS_H

#include <fec.h> // For consumers - defines FEC_CHUNK_SIZE
#include <primitives/block.h>

#include <memory>

class CTxMemPool;

// Dumb helper to handle CTransaction compression at serialize-time
struct TransactionCompressor {
private:
    CTransactionRef& tx;
public:
    explicit TransactionCompressor(CTransactionRef& txIn) : tx(txIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(tx); //TODO: Compress tx encoding
    }
};

class BlockTransactionsRequest {
public:
    // A BlockTransactionsRequest message
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockhash);
        uint64_t indexes_size = (uint64_t)indexes.size();
        READWRITE(COMPACTSIZE(indexes_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            while (indexes.size() < indexes_size) {
                indexes.resize(std::min((uint64_t)(1000 + indexes.size()), indexes_size));
                for (; i < indexes.size(); i++) {
                    uint64_t index = 0;
                    READWRITE(COMPACTSIZE(index));
                    if (index > std::numeric_limits<uint16_t>::max())
                        throw std::ios_base::failure("index overflowed 16 bits");
                    indexes[i] = index;
                }
            }

            int32_t offset = 0;
            for (size_t j = 0; j < indexes.size(); j++) {
                if (int32_t(indexes[j]) + offset > std::numeric_limits<uint16_t>::max())
                    throw std::ios_base::failure("indexes overflowed 16 bits");
                indexes[j] = indexes[j] + offset;
                offset = int32_t(indexes[j]) + 1;
            }
        } else {
            for (size_t i = 0; i < indexes.size(); i++) {
                uint64_t index = indexes[i] - (i == 0 ? 0 : (indexes[i - 1] + 1));
                READWRITE(COMPACTSIZE(index));
            }
        }
    }
};

class BlockTransactions {
public:
    // A BlockTransactions message
    uint256 blockhash;
    std::vector<CTransactionRef> txn;

    BlockTransactions() {}
    explicit BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockhash);
        uint64_t txn_size = (uint64_t)txn.size();
        READWRITE(COMPACTSIZE(txn_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            while (txn.size() < txn_size) {
                txn.resize(std::min((uint64_t)(1000 + txn.size()), txn_size));
                for (; i < txn.size(); i++)
                    READWRITE(TransactionCompressor(txn[i]));
            }
        } else {
            for (size_t i = 0; i < txn.size(); i++)
                READWRITE(TransactionCompressor(txn[i]));
        }
    }
};

// Dumb serialization/storage-helper for CBlockHeaderAndShortTxIDs and PartiallyDownloadedBlock
struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransactionRef tx;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint64_t idx = index;
        READWRITE(COMPACTSIZE(idx));
        if (idx > std::numeric_limits<uint16_t>::max())
            throw std::ios_base::failure("index overflowed 16-bits");
        index = idx;
        READWRITE(TransactionCompressor(tx));
    }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
    READ_STATUS_CHECKBLOCK_FAILED, // Used only by FillBlock to indicate a
                                   // failure in CheckBlock.
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

    static const int SHORTTXIDS_LENGTH = 6;
protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndShortTxIDs() {}

    CBlockHeaderAndShortTxIDs(const CBlock& block, bool fUseWTXID);

    uint64_t GetShortID(const uint256& txhash) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(nonce);

        uint64_t shorttxids_size = (uint64_t)shorttxids.size();
        READWRITE(COMPACTSIZE(shorttxids_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            shorttxids.clear();
            while (shorttxids.size() < shorttxids_size) {
                size_t target = std::min((uint64_t)(5000 + shorttxids.size()), shorttxids_size);
                shorttxids.reserve(target);
                for (; i < target; i++) {
                    uint32_t lsb = 0; uint16_t msb = 0;
                    READWRITE(lsb);
                    READWRITE(msb);
                    shorttxids.emplace_back((uint64_t(msb) << 32) | uint64_t(lsb));
                    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids serialization assumes 6-byte shorttxids");
                }
            }
        } else {
            for (size_t i = 0; i < shorttxids.size(); i++) {
                uint32_t lsb = shorttxids[i] & 0xffffffff;
                uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
                READWRITE(lsb);
                READWRITE(msb);
            }
        }

        READWRITE(prefilledtxn);

        if (BlockTxCount() > std::numeric_limits<uint16_t>::max())
            throw std::ios_base::failure("indexes overflowed 16 bits");

        if (ser_action.ForRead())
            FillShortTxIDSelector();
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<CTransactionRef> txn_available;
    size_t prefilled_count = 0, mempool_count = 0, extra_count = 0;
    CTxMemPool* pool;
public:
    CBlockHeader header;
    explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing);
};

// FEC-Supporting extensions

class CBlockHeaderAndLengthShortTxIDs : public CBlockHeaderAndShortTxIDs {
private:
    std::vector<uint32_t> txlens; // size by TransactionCompressor
    friend class PartiallyDownloadedChunkBlock;
public:
    CBlockHeaderAndLengthShortTxIDs(const CBlock& block);

    // Dummy for deserialization
    CBlockHeaderAndLengthShortTxIDs() {}

    // Fills a map from offset within a FEC-coded block to the tx index in the block
    // Returns false if this object is invalid (txlens.size() != shortxids.size())
    template<typename F>
    ReadStatus FillIndexOffsetMap(F& callback) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeaderAndShortTxIDs*)this);
        if (ser_action.ForRead()) {
            txlens.clear();
            txlens.reserve(shorttxids.size());
            for (size_t i = 0; i < shorttxids.size(); i++) {
                uint32_t len;
                READWRITE(VARINT(len));
                txlens.emplace_back(len);
            }
        } else {
            for (size_t i = 0; i < txlens.size(); i++)
                READWRITE(VARINT(txlens[i]));
        }
    }
};

// Valid options for the SIZE_FACTOR are 1 or 2, see cpp for more info
#define MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR 1

class ChunkCodedBlock {
private:
    std::vector<unsigned char> codedBlock;
public:
    ChunkCodedBlock(const CBlock& block, const CBlockHeaderAndLengthShortTxIDs& headerAndIDs);
    // Note that the coded block may be empty (ie prefilled txn in the header was full)
    const std::vector<unsigned char>& GetCodedBlock() const { return codedBlock; }
};

class VectorOutputStream;
class PartiallyDownloadedChunkBlock : private PartiallyDownloadedBlock {
private:
    std::map<size_t, size_t> index_offsets; // offset -> txindex
    std::vector<unsigned char> codedBlock;
    std::vector<bool> chunksAvailable;
    uint32_t remainingChunks;
    bool allTxnFromMempool;
    bool block_finalized = false;
    std::shared_ptr<CBlock> decoded_block;

    // Things used in the iterative fill-from-mempool:
    std::map<size_t, size_t>::iterator fill_coding_index_offsets_it;
    std::map<uint16_t, uint16_t> txn_prefilled; // index -> number of prefilled txn at or below index
    bool haveChunk = true;

    mutable uint256 block_hash; // Cached because its called in critical-path by udpnet

    bool SerializeTransaction(VectorOutputStream& stream, std::map<size_t, size_t>::iterator it);
public:
    PartiallyDownloadedChunkBlock(CTxMemPool* poolIn) : PartiallyDownloadedBlock(poolIn), decoded_block(std::make_shared<CBlock>()) {}

    // extra_txn is a list of extra transactions to look at, in <witness hash, reference> form
    ReadStatus InitData(const CBlockHeaderAndLengthShortTxIDs& comprblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
    ReadStatus DoIterativeFill(size_t& firstChunkProcessed);
    bool IsIterativeFillDone() const;

    bool IsBlockAvailable() const;
    ReadStatus FinalizeBlock();
    std::shared_ptr<const CBlock> GetBlock() const { assert(block_finalized); return decoded_block; }
    const std::vector<unsigned char>& GetCodedBlock() const { assert(AreChunksAvailable() && IsBlockAvailable()); return codedBlock; }
    uint256& GetBlockHash() const;

    // Chunk-based methods are only callable if AreChunksAvailable()
    bool AreChunksAvailable() const;
    size_t GetChunkCount() const;
    bool IsChunkAvailable(size_t chunk) const;

    // To provide a chunk, write it to GetChunk and call MarkChunkAvailable
    // The unavailable chunk pointer must be written to before GetBlock,
    // but can happen after MarkChunkAvailable
    unsigned char* GetChunk(size_t chunk);
    void MarkChunkAvailable(size_t chunk);
};

#endif // BITCOIN_BLOCKENCODINGS_H
