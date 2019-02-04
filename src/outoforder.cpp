// Copyright (c) 2018 Blockstream

#include <chain.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>
#include <util.h>
#include <validation.h>

#include <deque>
#include <map>
#include <memory>
#include <utility>
#include <vector>

static int ExtractHeightFromBlock(const Consensus::Params& consensusParams, const std::shared_ptr<const CBlock> pblock)
{
    if (pblock->nBits > consensusParams.BIP34AssumedBits) {
        // We can't be sure BIP34 is active, and without that we can't figure out the height yet
        return -1;
    }

    if (pblock->vtx.size() < 1) return -1;
    if (pblock->vtx[0]->vin.size() < 1) return -1;

    const auto& scriptSig = pblock->vtx[0]->vin[0].scriptSig;
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!scriptSig.GetOp(pc, opcode, data)) return -1;
    try {
        CScriptNum bn(data, /*require minimal encoding=*/true);
        return bn.getint();
    }
    catch (scriptnum_error) {
        return -1;
    }
}

static const char DB_SUBSEQUENT_BLOCK = 'S';

static CCriticalSection cs_ooob;

static CDBWrapper* GetOoOBlockDB() EXCLUSIVE_LOCKS_REQUIRED(cs_ooob)
{
    static CDBWrapper *ooob_db = nullptr;
    if (!ooob_db) ooob_db = new CDBWrapper(GetDataDir() / "future_blocks", /*cache size=*/1024);
    return ooob_db;
}

bool StoreOoOBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    LOCK(cs_ooob);
    CDBWrapper * const ooob_db = GetOoOBlockDB();
    auto key = std::make_pair(DB_SUBSEQUENT_BLOCK, pblock->hashPrevBlock);
    std::map<uint256, CDiskBlockPos> successors;

    ooob_db->Read(key, successors);
    if (successors.count(pblock->GetHash())) {
        // Already have it stored, so nothing to do
        return true;
    }

    // Figure out the block's height from BIP34
    const Consensus::Params& consensusParams = chainparams.GetConsensus();
    const int height = ExtractHeightFromBlock(consensusParams, pblock);
    if (height < consensusParams.BIP34Height) return false;  // nonsensical

    // Don't save blocks too far in the future, to prevent a DoS on pruning
    if (height > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP)) return false;

    LogPrintf("Adding block %s (height %u) to out-of-order disk cache\n", pblock->GetHash().GetHex(), height);
    CDiskBlockPos diskpos = SaveBlockToDisk(*pblock, height, chainparams, nullptr);
    successors.emplace(pblock->GetHash(), diskpos);
    if (!ooob_db->Write(key, successors)) {
        LogPrintf("ERROR adding block %s to out-of-order disk cache\n", pblock->GetHash().GetHex());
        return false;
    }
    return true;
}

void ProcessSuccessorOoOBlocks(const CChainParams& chainparams, const uint256& prev_block_hash)
{
    CDBWrapper *ooob_db = nullptr;
    std::deque<uint256> queue;
    queue.push_back(prev_block_hash);
    for ( ; !queue.empty(); queue.pop_front()) {
        uint256 head = queue.front();
        auto key = std::make_pair(DB_SUBSEQUENT_BLOCK, head);

        LOCK(cs_ooob);
        std::map<uint256, CDiskBlockPos> successors;
        {
            LOCK(cs_main);
            if (!ooob_db) ooob_db = GetOoOBlockDB();

            ooob_db->Read(key, successors);
        }

        if (successors.empty()) continue;

        for (const auto& successor : successors) {
            std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
            CBlock& block = *pblock;
            if (!ReadBlockFromDisk(block, successor.second, chainparams.GetConsensus())) {
                continue;
            }
            LogPrintf("Accepting deferred block %s from out-of-order disk cache\n", block.GetHash().GetHex());
            ProcessNewBlock(chainparams, pblock, /*force processing=*/false, /*is new block?=*/nullptr, &successor.second, /*do_ooob=*/false);
            queue.push_back(pblock->GetHash());
        }

        ooob_db->Erase(key);
    }
}

void CheckForOoOBlocks(const CChainParams& chainparams)
{
    std::vector<uint256> to_process;
    {
        LOCK(cs_ooob);
        CDBWrapper * const ooob_db = GetOoOBlockDB();

        std::unique_ptr<CDBIterator> pcursor(ooob_db->NewIterator());

        LOCK(cs_main);
        for (pcursor->Seek(std::make_pair(DB_SUBSEQUENT_BLOCK, uint256())); pcursor->Valid(); pcursor->Next()) {
            std::pair<char, uint256> key;
            if (!(pcursor->GetKey(key) && key.first == DB_SUBSEQUENT_BLOCK)) break;

            const uint256& prev_block_hash = key.second;
            if (mapBlockIndex.count(prev_block_hash)) {
                to_process.push_back(prev_block_hash);
            }
        }
    }

    for (const auto& prev_block_hash : to_process) {
        ProcessSuccessorOoOBlocks(chainparams, prev_block_hash);
    }
}
