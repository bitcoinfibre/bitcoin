// You probably want:
// cd src && make secp256k1/libsecp256k1.la &&
// g++ -std=c++11 -march=native -mtune=native -Wall -O2 -flto -o smart-proxy -DHAVE_CONFIG_H -I. -Iconfig -Isecp256k1/include -lpthread -levent -lcrypto -lboost_system -lboost_program_options -lboost_thread -lboost_filesystem -lrt -lanl smart-proxy.cpp udpnet.cpp udprelay.cpp netbase.cpp primitives/transaction.cpp util.cpp fec.cpp crypto/sha256.cpp crypto/sha256_sse4.cpp crypto/sha512.cpp wh256/src/wirehair_codec_8.cpp wh256/src/cm256.cpp wh256/src/gf256.cpp wh256/src/wh256.cpp random.cpp netaddress.cpp utiltime.cpp blockencodings.cpp primitives/block.cpp uint256.cpp utilstrencodings.cpp txmempool.cpp chainparams.cpp chainparamsbase.cpp support/cleanse.cpp coins.cpp policy/fees.cpp hash.cpp policy/policy.cpp consensus/merkle.cpp consensus/tx_verify.cpp pow.cpp crypto/hmac_sha512.cpp script/interpreter.cpp  script/script.cpp utilmoneystr.cpp script/standard.cpp arith_uint256.cpp crypto/ripemd160.cpp crypto/sha1.cpp pubkey.cpp sync.cpp chain.cpp secp256k1/.libs/libsecp256k1.a

#include "chainparams.h"
#include "netbase.h"
#include "udpapi.h"
#include "util.h"
#include "txmempool.h"
#include "validation.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"

#include <assert.h>


// Assorted validation.cpp deps

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;
bool fIsBareMultisigStd = false;

CTxMemPool mempool(nullptr);
CCriticalSection cs_main;
CChain chainActive;

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock) {
	if (fNewBlock)
		*fNewBlock = true;
	UDPRelayBlock(*pblock);
	return true;
}

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, false))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight) { assert(false); }
bool TestLockPointValidity(const LockPoints* lp)  { assert(false); return false; }
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints) { assert(false); return false; }
bool CheckFinalTx(const CTransaction &tx, int flags) { assert(false); return false; }
int GetSpendHeight(const CCoinsViewCache& inputs) { assert(false); return 0; }
bool IsInitialBlockDownload() { return false; }
bool ShutdownRequested() { return false; }
bool ReadBlockFromDisk(CBlock&, const CBlockIndex*, const Consensus::Params&) { assert(false); return false; }

int main(int argc, const char** argv) {
	gArgs.ParseParameters(argc, argv);
	gArgs.ForceSetArg("-printtoconsole", "1");
	fPrintToConsole = true;
	if (gArgs.IsArgSet("-debug"))
		logCategories = 0xffffffff;

	fLogTimestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
	fLogTimeMicros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);

	std::string sha256_algo = SHA256AutoDetect();
	LogPrintf("Using the '%s' SHA256 implementation\n", sha256_algo);

	if (!gArgs.IsArgSet("-udpport") || (!gArgs.IsArgSet("-addtrustedudpnode") && !gArgs.IsArgSet("-addudpnode"))) {
		fprintf(stderr, "USAGE: %s -udpport=bitcoind_syntax -add[trusted]udpnode=bitcoind_syntax*\n", argv[0]);
		return 1;
	}

	SelectParams(CBaseChainParams::MAIN);

	InitializeUDPConnections();

	while (true) {
		MilliSleep(1000);
	}

	return 1;
}
