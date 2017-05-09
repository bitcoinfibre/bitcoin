// You probably want:
// ./configure --disable-wallet && cd src && make secp256k1/.libs/libsecp256k1.a crypto/libbitcoin_crypto_sse41.a crypto/libbitcoin_crypto_avx2.a crypto/libbitcoin_crypto_shani.a &&
// Try this first:
// g++ -std=c++11 -march=native -mtune=native -Wall -O3 -flto -o smart-proxy -DHAVE_CONFIG_H -I. -Ileveldb/include -Iconfig -Isecp256k1/include -Wl,-start-group -lssl -lpthread -levent -lcrypto -lboost_system -lboost_date_time -lboost_chrono -lboost_thread -lboost_filesystem -lrt -lanl smart-proxy.cpp crypto/sha256_sse4.cpp clientversion.cpp udpnet.cpp udprelay.cpp netbase.cpp primitives/transaction.cpp fec.cpp crypto/sha256.cpp crypto/sha512.cpp wirehair/WirehairCodec.cpp wirehair/cm256.cpp wirehair/gf256.cpp wirehair/wirehair.cpp wirehair/WirehairTools.cpp random.cpp netaddress.cpp util/time.cpp util/threadnames.cpp blockencodings.cpp primitives/block.cpp uint256.cpp util/strencodings.cpp util/system.cpp fs.cpp logging.cpp txmempool.cpp chainparams.cpp chainparamsbase.cpp support/cleanse.cpp coins.cpp policy/fees.cpp hash.cpp policy/policy.cpp consensus/merkle.cpp consensus/tx_verify.cpp consensus/tx_check.cpp pow.cpp crypto/hmac_sha512.cpp crypto/siphash.cpp crypto/chacha20.cpp crypto/poly1305.cpp script/interpreter.cpp  script/script.cpp util/moneystr.cpp script/standard.cpp arith_uint256.cpp crypto/ripemd160.cpp crypto/sha1.cpp pubkey.cpp sync.cpp chain.cpp bloom.cpp support/lockedpool.cpp versionbitsinfo.cpp secp256k1/.libs/libsecp256k1.a crypto/libbitcoin_crypto_sse41.a crypto/libbitcoin_crypto_avx2.a crypto/libbitcoin_crypto_shani.a -Wl,-end-group

#include "chainparams.h"
#include "netbase.h"
#include "udpapi.h"
#include "txmempool.h"
#include "validation.h"
#include "consensus/consensus.h"
#include "consensus/tx_check.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "pow.h"

#include <assert.h>

// Assorted validation.cpp deps

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
bool fIsBareMultisigStd = false;

CTxMemPool mempool(nullptr);
CCriticalSection cs_main;
CChain g_chainActive;
CChain& ChainActive() { return g_chainActive; }
BlockManager g_blockman;
std::unique_ptr<CChainState> g_chainstate{new CChainState()};
CChainState& ChainstateActive() { return *g_chainstate; }
CBlockIndex* LookupBlockIndex(const uint256& hash) { return nullptr; }

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock) {
    if (fNewBlock)
        *fNewBlock = true;
    UDPRelayBlock(*pblock);
    return true;
}

static bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.Invalid(ValidationInvalidReason::BLOCK_INVALID_HEADER, false, REJECT_INVALID, "high-hash", "proof of work failed");

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
            return state.Invalid(ValidationInvalidReason::BLOCK_MUTATED, false, REJECT_INVALID, "bad-txnmrklroot", "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.Invalid(ValidationInvalidReason::BLOCK_MUTATED, false, REJECT_INVALID, "bad-txns-duplicate", "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-blk-length", "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-cb-multiple", "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, true))
            return state.Invalid(state.GetReason(), false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight) { assert(false); }
bool TestLockPointValidity(const LockPoints* lp)  { assert(false); return false; }
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints) { assert(false); return false; }
bool CheckFinalTx(const CTransaction &tx, int flags) { assert(false); return false; }
int GetSpendHeight(const CCoinsViewCache& inputs) { assert(false); return 0; }
CChainState::CChainState() : m_blockman(g_blockman) {}
bool CChainState::IsInitialBlockDownload() const { return false; }
bool ShutdownRequested() { return false; }
bool ReadBlockFromDisk(CBlock&, const CBlockIndex*, const Consensus::Params&) { assert(false); return false; }
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept)
{ return true; }

CDBWrapper::~CDBWrapper() {}
CCoinsViewDB::CCoinsViewDB(fs::path ldb_path, size_t nCacheSize, bool fMemory, bool fWipe) : db(ldb_path, nCacheSize, fMemory, fWipe, true) {}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const { return false; }
uint256 CCoinsViewDB::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return true; }
CCoinsViewCursor *CCoinsViewDB::Cursor() const { return nullptr; }
size_t CCoinsViewDB::EstimateSize() const { return 0; }



/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging()
{
    LogInstance().m_print_to_file = !gArgs.IsArgNegated("-debuglogfile");
    LogInstance().m_file_path = AbsPathForConfigVal(gArgs.GetArg("-debuglogfile", DEFAULT_DEBUGLOGFILE));
    LogInstance().m_print_to_console = gArgs.GetBoolArg("-printtoconsole", !gArgs.GetBoolArg("-daemon", false));
    LogInstance().m_print_to_file = !gArgs.GetBoolArg("-printtoconsole", !gArgs.GetBoolArg("-daemon", false));
    LogInstance().m_log_timestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    LogInstance().m_log_time_micros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    LogInstance().m_log_threadnames = gArgs.GetBoolArg("-logthreadnames", DEFAULT_LOGTHREADNAMES);

    fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);

    std::string version_string = FormatFullVersion();
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    LogPrintf(PACKAGE_NAME " version %s\n", version_string);
}

int main(int argc, const char** argv) {
	gArgs.AddArg("-debug=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-udpport=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-addtrustedudpnode=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-addudpnode=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-debuglogfile=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-printtoconsole=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-logtimestamps=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-logtimemicros=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-logthreadnames=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
	gArgs.AddArg("-logips=<n>", "", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

	std::string err;
	if (!gArgs.ParseParameters(argc, argv, err)) {
		fprintf(stderr, "Error parsing parameters: %s\n", err.c_str());
		return 1;
	}

	SelectParams(CBaseChainParams::MAIN);

	gArgs.ForceSetArg("-printtoconsole", "1");
	InitLogging();
	LogInstance().StartLogging();
	if (gArgs.IsArgSet("-debug"))
		LogInstance().EnableCategory(BCLog::LogFlags::ALL);

	std::string sha256_algo = SHA256AutoDetect();
	LogPrintf("Using the '%s' SHA256 implementation\n", sha256_algo);

	if (!gArgs.IsArgSet("-udpport") || (!gArgs.IsArgSet("-addtrustedudpnode") && !gArgs.IsArgSet("-addudpnode"))) {
		fprintf(stderr, "USAGE: %s -udpport=bitcoind_syntax -add[trusted]udpnode=bitcoind_syntax*\n", argv[0]);
		return 1;
	}

	InitializeUDPConnections();

	while (true) {
		MilliSleep(1000);
	}

	return 1;
}
