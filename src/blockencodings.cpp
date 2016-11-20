// Copyright (c) 2016-2018 The Bitcoin Core developers
// Copyright (c) 2018 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <blockencodings.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <random.h>
#include <streams.h>
#include <txmempool.h>
#include <validation.h>
#include <util/system.h>
#include <open_hash_set.h>

#include <unordered_map>

#include <chrono>
#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block, bool fUseWTXID, bool fDeterministic) :
        nonce(fDeterministic ? block.GetHash().GetUint64(0) : GetRand(std::numeric_limits<uint64_t>::max())),
        shorttxids(block.vtx.size() - 1), prefilledtxn(1), header(block) {
    FillShortTxIDSelector();
    //TODO: Use our mempool prior to block acceptance to predictively fill more than just the coinbase
    prefilledtxn[0] = {0, block.vtx[0]};
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];
        shorttxids[i - 1] = GetShortID(fUseWTXID ? tx.GetWitnessHash() : tx.GetHash());
    }
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream.reserve(80 + 8);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*stream.begin()), stream.size());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}

namespace
{
    struct ShortIdIndexPair {
        uint64_t shortid : 48;
        uint64_t index : 16;
        ShortIdIndexPair(uint64_t shortid_in=0, uint16_t index_in=0) : shortid(shortid_in), index(index_in) {}
    };
    static_assert(sizeof(ShortIdIndexPair) == 8, "");

    struct ShortIdIndexPairHasher {
        uint64_t operator()(const ShortIdIndexPair& elem) const {
            return elem.shortid;
        }
    };

    struct ShortIdIndexPairEqual {
        bool operator()(const ShortIdIndexPair& a, const ShortIdIndexPair& b) const {
            return a.shortid == b.shortid;
        }
    };

    struct ShortIdIndexPairIsNull {
        bool operator()(const ShortIdIndexPair& elem) const {
            return elem.shortid == 0 && elem.index == 0;
        }
    };
} // anonymous namespace

ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn) {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    if (cmpctblock.header.IsNull() || (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
        return READ_STATUS_INVALID;

    assert(header.IsNull() && txn_available.empty());
    header = cmpctblock.header;
    txn_available.resize(cmpctblock.BlockTxCount());

    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
        if (cmpctblock.prefilledtxn[i].tx->IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1; //index is a uint16_t, so can't overflow here
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txn_available[lastprefilledindex] = cmpctblock.prefilledtxn[i].tx;
    }
    prefilled_count = cmpctblock.prefilledtxn.size();

    if (cmpctblock.shorttxids.empty()) {
        return READ_STATUS_OK;
    }

    // Calculate map of txids -> positions and check mempool to see what we have (or don't)
    std::chrono::steady_clock::time_point prefilled_filled;
    if (fBench)
        prefilled_filled = std::chrono::steady_clock::now();

    // Because well-formed cmpctblock messages will have a (relatively) uniform distribution
    // of short IDs, any highly-uneven distribution of elements can be safely treated as a
    // READ_STATUS_FAILED.
    open_hash_set<ShortIdIndexPair, ShortIdIndexPairIsNull, ShortIdIndexPairHasher, ShortIdIndexPairEqual> shorttxids(cmpctblock.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctblock.shorttxids.size(); i++) {
        while (txn_available[i + index_offset])
            index_offset++;
        auto i_res = shorttxids.insert(ShortIdIndexPair(cmpctblock.shorttxids[i], i + index_offset));
        if (!i_res.second) {
            return READ_STATUS_FAILED;
        }
    }
    // TODO: in the shortid-collision case, we should instead request both transactions
    // which collided. Falling back to full-block-request here is overkill.
    if (shorttxids.size() != cmpctblock.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    std::vector<bool> have_txn(txn_available.size());

    std::chrono::steady_clock::time_point shortids_mapped;
    if (fBench)
        shortids_mapped = std::chrono::steady_clock::now();

    {
    LOCK(pool->cs);
    const std::vector<uint256>& vTxHashes = pool->vTxHashes;
    const std::vector<CTxMemPool::txiter>& vTxnUnordered = pool->vTxnUnordered;
    uint64_t shortid = vTxHashes.size() > 0 ? cmpctblock.GetShortID(vTxHashes[0]) : 0;
    for (size_t i = 0; i < vTxHashes.size(); i++) {
        uint64_t next_shortid = 0;
        __builtin_prefetch(vTxHashes.data() + ((i + 2) * sizeof(decltype(pool->vTxHashes)::value_type)), 0);
        if (i + 1 < vTxHashes.size()) {
            next_shortid = cmpctblock.GetShortID(vTxHashes[i + 1]);
        }
        const ShortIdIndexPair *p = shorttxids.find_fast(ShortIdIndexPair(shortid));
        if (p) {
            if (!have_txn[p->index]) {
                txn_available[p->index] = vTxnUnordered[i]->GetSharedTx();
                have_txn[p->index] = true;
                mempool_count++;
            } else {
                // If we find two mempool txn that match the short id, just request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBlock failure would be annoying
                if (txn_available[p->index]) {
                    txn_available[p->index].reset();
                    mempool_count--;
                }
            }
        }
        shortid = next_shortid;
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (mempool_count == shorttxids.size())
            break;
    }
    }

    uint64_t shortid = extra_txn.size() > 0 ? cmpctblock.GetShortID(extra_txn[0].first) : 0;
    for (size_t i = 0; i < extra_txn.size(); i++) {
        uint64_t next_shortid = 0;
        if (i + 1 < extra_txn.size()) {
            next_shortid = cmpctblock.GetShortID(extra_txn[i + 1].first);
        }
        const ShortIdIndexPair *p = shorttxids.find_fast(ShortIdIndexPair(shortid));
        if (p) {
            if (!have_txn[p->index]) {
                txn_available[p->index] = extra_txn[i].second;
                have_txn[p->index]  = true;
                mempool_count++;
                extra_count++;
            } else {
                // If we find two mempool/extra txn that match the short id, just
                // request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBlock failure would be annoying
                // Note that we don't want duplication between extra_txn and mempool to
                // trigger this case, so we compare witness hashes first
                if (txn_available[p->index] &&
                        txn_available[p->index]->GetWitnessHash() != extra_txn[i].second->GetWitnessHash()) {
                    txn_available[p->index].reset();
                    mempool_count--;
                    extra_count--;
                }
            }
        }
        shortid = next_shortid;
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (mempool_count == shorttxids.size())
            break;
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("PartiallyDownloadedBlock::InitData took %lf %lf %lf ms\n", to_millis_double(prefilled_filled - start), to_millis_double(shortids_mapped - prefilled_filled), to_millis_double(finished - shortids_mapped));
    }

    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock, PROTOCOL_VERSION));

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    assert(index < txn_available.size());
    return txn_available[index] != nullptr;
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing) {
    assert(!header.IsNull());
    uint256 hash = header.GetHash();
    block = header;
    block.vtx.resize(txn_available.size());

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            block.vtx[i] = vtx_missing[tx_missing_offset++];
        } else
            block.vtx[i] = std::move(txn_available[i]);
    }

    // Make sure we can't call FillBlock again.
    header.SetNull();
    txn_available.clear();

    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_INVALID;

    CValidationState state;
    if (!CheckBlock(block, state, Params().GetConsensus())) {
        // TODO: We really want to just check merkle tree manually here,
        // but that is expensive, and CheckBlock caches a block's
        // "checked-status" (in the CBlock?). CBlock should be able to
        // check its own merkle root and cache that check.
        if (state.GetReason() == ValidationInvalidReason::BLOCK_MUTATED)
            return READ_STATUS_FAILED; // Possible Short ID collision
        return READ_STATUS_CHECKBLOCK_FAILED;
    }

    LogPrint(BCLog::CMPCTBLOCK, "Successfully reconstructed block %s with %lu txn prefilled, %lu txn from mempool (incl at least %lu from extra pool) and %lu txn requested\n", hash.ToString(), prefilled_count, mempool_count, extra_count, vtx_missing.size());
    if (vtx_missing.size() < 5) {
        for (const auto& tx : vtx_missing) {
            LogPrint(BCLog::CMPCTBLOCK, "Reconstructed block %s required tx %s\n", hash.ToString(), tx->GetHash().ToString());
        }
    }

    return READ_STATUS_OK;
}


CBlockHeaderAndLengthShortTxIDs::CBlockHeaderAndLengthShortTxIDs(const CBlock& block, bool fDeterministic) :
        CBlockHeaderAndShortTxIDs(block, true, fDeterministic), txlens(shorttxids.size()) {
    int32_t lastprefilledindex = -1;
    uint16_t index_offset = 0;
    std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
    for (size_t i = 0; i < block.vtx.size(); i++) {
        if (prefilledit != prefilledtxn.end() && (uint32_t)(lastprefilledindex + prefilledit->index + 1) == i + index_offset) {
            lastprefilledindex += prefilledit->index + 1;
            prefilledit++;
            index_offset++;
        } else
            txlens[i - index_offset] = GetSerializeSize(TransactionCompressor(const_cast<CTransactionRef&>(block.vtx[i])), PROTOCOL_VERSION);
    }
}

template<typename F>
ReadStatus CBlockHeaderAndLengthShortTxIDs::FillIndexOffsetMap(F& callback) const {
    if (txlens.size() != shorttxids.size())
        return READ_STATUS_INVALID;

    // The first version is much faster, but for a 0.5-1ms hit, the second
    // version is much smarter about avoiding crossing chunk boundaries.
#if MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR == 1
    size_t current_index = 0;
    int32_t lastprefilledindex = -1;
    uint16_t index_offset = 0;
    std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
    for (size_t i = 0; i < txlens.size(); i++) {
        while (prefilledit != prefilledtxn.end() &&
                (uint32_t)(lastprefilledindex + prefilledit->index + 1) == i + index_offset) {
            lastprefilledindex += prefilledit->index + 1;
            prefilledit++;
            index_offset++;
        }
        callback(current_index, i + index_offset);
        current_index += txlens[i];
    }

    return READ_STATUS_OK;
#elif MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR == 2
    std::multimap<size_t, size_t> indexes_left; // size -> index
    int32_t lastprefilledindex = -1;
    uint16_t index_offset = 0;
    std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
    for (size_t i = 0; i < txlens.size(); i++) {
        while (prefilledit != prefilledtxn.end() &&
                (uint32_t)(lastprefilledindex + prefilledit->index + 1) == i + index_offset) {
            lastprefilledindex += prefilledit->index + 1;
            prefilledit++;
            index_offset++;
        }
        indexes_left.insert(std::make_pair(txlens[i], i + index_offset));
    }

    size_t current_index = 0;
    while (!indexes_left.empty()) {
        std::multimap<size_t, size_t>::reverse_iterator lastit = indexes_left.rbegin();
        callback(current_index, lastit->second);
        current_index += lastit->first;
        lastit++; // base() returns next (ie prev of reverse) element
        indexes_left.erase(lastit.base());

        size_t size_left = FEC_CHUNK_SIZE - (current_index % FEC_CHUNK_SIZE);
        while (!indexes_left.empty() && size_left > indexes_left.begin()->first) {
            std::multimap<size_t, size_t>::iterator it = indexes_left.upper_bound(size_left);
            assert(it != indexes_left.begin()); it--; assert(it->first <= size_left);

            callback(current_index, it->second);
            current_index += it->first;
            size_left -= it->first;
            indexes_left.erase(it);
        }

        if (current_index > MAX_BLOCK_SERIALIZED_SIZE)
            return READ_STATUS_INVALID;
    }

    return READ_STATUS_OK;
#else
#error Need size factor of 1 or 2
#endif
}


#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

struct FillIndexOffsetMapSerializer {
    VectorOutputStream& stream;
    const CBlock& block;
    void operator()(size_t offset, size_t index) {
        if (stream.pos() < offset)
            stream.skip_bytes(offset - stream.pos());
        assert(stream.pos() == offset);
        stream << TransactionCompressor(const_cast<CTransactionRef&>(block.vtx[index]));
    }
};

ChunkCodedBlock::ChunkCodedBlock(const CBlock& block, const CBlockHeaderAndLengthShortTxIDs& headerAndIDs) {
    codedBlock.reserve(MAX_BLOCK_SERIALIZED_SIZE * 1.2);
    VectorOutputStream stream(&codedBlock, SER_NETWORK, PROTOCOL_VERSION);

    {
        FillIndexOffsetMapSerializer ser{stream, block};
        assert(headerAndIDs.FillIndexOffsetMap<FillIndexOffsetMapSerializer>(ser) == READ_STATUS_OK);
    }
    codedBlock.resize(DIV_CEIL(codedBlock.size() + 80, FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE);
    // Append the block header at the end of the last chunk. We dont currently
    // use this in decode, but this should allow us to decode a block without
    // ever having fully received the header-and-short-ids.
    if (stream.pos() < codedBlock.size() - 80)
        stream.skip_bytes(codedBlock.size() - 80 - stream.pos());
    assert(stream.pos() == codedBlock.size() - 80);
    stream << headerAndIDs.header;
}


static inline uint16_t get_txlens_index(const std::map<uint16_t, uint16_t>& txn_prefilled, uint16_t real_index) {
    if (txn_prefilled.empty())
        return real_index;
    std::map<uint16_t, uint16_t>::const_iterator it = txn_prefilled.upper_bound(real_index);
    it--;
    return real_index - it->second;
}

struct FillIndexOffsetMapCallback {
    std::map<size_t, size_t>& index_offsets;
    void operator()(size_t offset, size_t index) {
        index_offsets[offset] = index;
    }
};
ReadStatus PartiallyDownloadedChunkBlock::InitData(const CBlockHeaderAndLengthShortTxIDs& comprblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn) {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    if (comprblock.txlens.size() != comprblock.shorttxids.size())
        return READ_STATUS_INVALID;
    ReadStatus status;
    // We limit number of mempool txn iterated over because it costs a lot of time,
    // and a few extra transactions missed is just fine.
    status = PartiallyDownloadedBlock::InitData(comprblock, extra_txn);
    if (status != READ_STATUS_OK)
        return status;

    std::chrono::steady_clock::time_point base_data_initd;
    if (fBench)
        base_data_initd = std::chrono::steady_clock::now();

    *decoded_block = header;

    allTxnFromMempool = true;
    for (const std::shared_ptr<const CTransaction>& tx : txn_available)
        allTxnFromMempool &= tx ? true : false;
    if (allTxnFromMempool)
        return READ_STATUS_OK;

    FillIndexOffsetMapCallback fiomCallback{index_offsets};
    status = comprblock.FillIndexOffsetMap<FillIndexOffsetMapCallback>(fiomCallback);
    if (status != READ_STATUS_OK)
        return status;

    std::chrono::steady_clock::time_point index_offset_mapped;
    if (fBench)
        index_offset_mapped = std::chrono::steady_clock::now();

    int32_t prefilled_txn_offset = -1;
    for (size_t i = 0; i < comprblock.prefilledtxn.size(); i++) {
        prefilled_txn_offset += comprblock.prefilledtxn[i].index + 1;
        assert(txn_prefilled.insert(std::make_pair(prefilled_txn_offset, i + 1)).second);
    }

    if (index_offsets.size()) {
        size_t codedBlockSize = DIV_CEIL(
                                index_offsets.rbegin()->first +
                                comprblock.txlens[get_txlens_index(txn_prefilled, index_offsets.rbegin()->second)] + 80,
                            FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE;
        chunksAvailable.resize(codedBlockSize / FEC_CHUNK_SIZE);
        remainingChunks = codedBlockSize / FEC_CHUNK_SIZE;
        codedBlock.resize(codedBlockSize);
    }

    fill_coding_index_offsets_it = index_offsets.begin();

    if (fBench) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("PartiallyDownloadedChunkBlock::InitData took %lf %lf %lf ms\n", to_millis_double(base_data_initd - start), to_millis_double(index_offset_mapped - base_data_initd), to_millis_double(finished - index_offset_mapped));
    }

    return READ_STATUS_OK;
}

bool PartiallyDownloadedChunkBlock::SerializeTransaction(VectorOutputStream& stream, std::map<size_t, size_t>::iterator it) {
    if (stream.pos() < it->first)
        stream.skip_bytes(it->first - stream.pos());
    assert(stream.pos() == it->first);

    // We're fine blindly serializing tx -> either it came from mempool and is fully valid,
    // or it was received over the wire, so it shouldn't be able to eat all our memory.
    const CTransactionRef& tx = PartiallyDownloadedBlock::txn_available[it->second];
    stream << TransactionCompressor(const_cast<CTransactionRef&>(tx));

    it++;
    if (it == index_offsets.end())
        return true;
    else
        return stream.pos() <= it->first;
}

ReadStatus PartiallyDownloadedChunkBlock::DoIterativeFill(size_t& firstChunkProcessed) {
    std::map<size_t, size_t>::iterator current_it = fill_coding_index_offsets_it;
    size_t current_index = current_it->first;

    VectorOutputStream stream(&codedBlock, SER_NETWORK, PROTOCOL_VERSION, current_index);

    firstChunkProcessed = current_index / FEC_CHUNK_SIZE;

    for (; fill_coding_index_offsets_it != index_offsets.end(); fill_coding_index_offsets_it++) {
        if (fill_coding_index_offsets_it->first / FEC_CHUNK_SIZE == current_index / FEC_CHUNK_SIZE)
            haveChunk &= IsTxAvailable(fill_coding_index_offsets_it->second);
        else
            break;
    }

    // First process the chunk we were most recently in
    if (haveChunk) {
        for (; current_it != fill_coding_index_offsets_it; current_it++) {
            if (!SerializeTransaction(stream, current_it))
                return READ_STATUS_FAILED; // Could be a shorttxid collision
        }
        for (size_t i = current_index / FEC_CHUNK_SIZE; i < fill_coding_index_offsets_it->first / FEC_CHUNK_SIZE; i++) {
            if (i == chunksAvailable.size() - 1) {
                // Write the header to the last 80 bytes of the last chunk
                size_t header_pos = chunksAvailable.size() * FEC_CHUNK_SIZE - 80;
                if (stream.pos() < header_pos)
                    stream.skip_bytes(header_pos - stream.pos());
                assert(stream.pos() == header_pos);
                stream << header;
            }
            if (!chunksAvailable[i])
                remainingChunks--;
            chunksAvailable[i] = true;
        }
    }//TODO else if (haveMostRecentlyCheckedTx && mostRecentlyCheckedTxFillsChunk(s)OnItsOwn
        //TODO: Handle chunk that spanned a border and filled up at least one chunk on its own
        // Note that the current FillIndexOffsetMap implementation will never use this

    haveChunk = true; // Next chunk gets a fresh start

    // If we're gonna try to process this chunk later...
    if (fill_coding_index_offsets_it != index_offsets.end() && IsTxAvailable(fill_coding_index_offsets_it->second)) {
        current_index = fill_coding_index_offsets_it->first;
        if (current_index % FEC_CHUNK_SIZE != 0) {
            // If we don't start on a chunk boundry, we assume the previous transaction
            // came into our chunk, as otherwise our packing algorithm is braindead
            assert(fill_coding_index_offsets_it != index_offsets.begin());
            std::map<size_t, size_t>::iterator previt = fill_coding_index_offsets_it; previt--;
            if (IsTxAvailable(previt->second)) {
                if (stream.pos() <= previt->first) { // If previt was not already encoded...
                    if (!SerializeTransaction(stream, previt))
                        return READ_STATUS_FAILED; // Could be a shorttxid collision
                }
            } else
                haveChunk = false; // I'm sorry, but its just not gonna work out - its not you, its me
        }
    }

    return READ_STATUS_OK;
}

bool PartiallyDownloadedChunkBlock::IsIterativeFillDone() const {
    return allTxnFromMempool || fill_coding_index_offsets_it == index_offsets.end();
}

uint256& PartiallyDownloadedChunkBlock::GetBlockHash() const {
    assert(!header.IsNull());
    if (block_hash.IsNull())
        block_hash = header.GetHash();
    return block_hash;
}

bool PartiallyDownloadedChunkBlock::IsBlockAvailable() const {
    assert(!header.IsNull());
    return allTxnFromMempool || !remainingChunks;
}

bool PartiallyDownloadedChunkBlock::AreChunksAvailable() const {
    return !header.IsNull() && !allTxnFromMempool;
}

ReadStatus PartiallyDownloadedChunkBlock::FinalizeBlock() {
    const bool fBench = LogAcceptCategory(BCLog::BENCH);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    assert(!header.IsNull());
    assert(IsBlockAvailable());

    CBlock& block = *decoded_block;
    block.vtx.clear();
    block.vtx.reserve(txn_available.size());

    for (size_t i = 0; i < txn_available.size(); i++) {
        if (txn_available[i]) {
            block.vtx.emplace_back(std::move(txn_available[i]));
        } else {
            assert(!allTxnFromMempool);
            block.vtx.emplace_back();
        }
    }
    txn_available.clear();
    if (allTxnFromMempool) {
        block_finalized = true;
        return READ_STATUS_OK;
    }

    std::chrono::steady_clock::time_point mempool_filled;
    if (fBench)
        mempool_filled = std::chrono::steady_clock::now();

    // TODO: This is really slow (like several ms)
    // We should migrate to keeping the partially-decoded block as a unique_ptr
    // and decode transactions as we go...this will not only save the deserialize
    // time we spend here, but by calling GetHash() at that time, save the
    // hashing time we'll spend later to check the hash of each transaction.
    VectorInputStream stream(&codedBlock, SER_NETWORK, PROTOCOL_VERSION);
    for (std::map<size_t, size_t>::const_iterator it = index_offsets.begin(); it != index_offsets.end(); it++) {
        if (block.vtx[it->second])
            continue;
        try {
            if (it->first < stream.pos()) // Last transaction was longer than expected
                return READ_STATUS_FAILED; // Could be a shorttxid collision
            stream.seek(it->first);
            stream >> REF(TransactionCompressor(block.vtx[it->second]));
        } catch (const std::ios_base::failure& e) {
            return READ_STATUS_FAILED; // Could be a shorttxid collision
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("PartiallyDownloadedChunkBlock::FinalizeBlock took %lf %lf ms\n", to_millis_double(mempool_filled - start), to_millis_double(finished - mempool_filled));
    }

    block_finalized = true;

    return READ_STATUS_OK;
}

size_t PartiallyDownloadedChunkBlock::GetChunkCount() const {
    assert(AreChunksAvailable());
    return chunksAvailable.size();
}

bool PartiallyDownloadedChunkBlock::IsChunkAvailable(size_t chunk) const {
    assert(chunk < GetChunkCount());
    return chunksAvailable[chunk];
}

unsigned char* PartiallyDownloadedChunkBlock::GetChunk(size_t chunk) {
    assert(chunk < GetChunkCount());
    return &codedBlock[chunk * FEC_CHUNK_SIZE];
}

void PartiallyDownloadedChunkBlock::MarkChunkAvailable(size_t chunk) {
    assert(chunk < GetChunkCount());
    if (!chunksAvailable[chunk])
        remainingChunks--;
    chunksAvailable[chunk] = true;
}
