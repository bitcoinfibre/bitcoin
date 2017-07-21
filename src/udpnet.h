// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <atomic>
#include <stdint.h>
#include <vector>
#include <mutex>
#include <assert.h>

#include "udpapi.h"

#include "blockencodings.h"
#include "fec.h"
#include "netaddress.h"

// This is largely the API between udpnet and udprelay, see udpapi for the
// external-facing API

// 1 Gbps - DO NOT CHANGE, this determines encoding, see do_send_messages to actually change upload speed
#define NETWORK_TARGET_BYTES_PER_SECOND (1024 * 1024 * 1024 / 8)

// Local stuff only uses magic, net stuff only uses protocol_version,
// so both need to be changed any time wire format changes
static const unsigned char LOCAL_MAGIC_BYTES[] = { 0x7b, 0xad, 0xca, 0xfe };
static const uint32_t UDP_PROTOCOL_VERSION = (3 << 16) | 3; // Min version 3, current version 3

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
};

static const uint8_t UDP_MSG_TYPE_FLAGS_MASK = 0xf0;
static const uint8_t UDP_MSG_TYPE_TYPE_MASK = 0x0f;

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1;
    uint64_t chk2;
    uint8_t msg_type; // A UDPMessageType + flags
};
static_assert(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1168 bytes (1186 bytes in total UDP message contents, with a padding byte in message)
#define MAX_UDP_MESSAGE_LENGTH 1168

enum UDPBlockMessageFlags { // Put in the msg_type
    HAVE_BLOCK = (1 << 4),
};

struct __attribute__((packed)) UDPBlockMessage {
    uint64_t hash_prefix; // First 8 bytes of blockhash, interpreted in LE (note that this will not include 0s, those are at the end)
    uint32_t obj_length; // Size of full FEC-coded data
    uint16_t chunks_sent; // Total chunks including source and repair chunks
    uint16_t chunk_id;
    unsigned char data[FEC_CHUNK_SIZE];
};
static_assert(sizeof(UDPBlockMessage) == MAX_UDP_MESSAGE_LENGTH, "Messages must be == MAX_UDP_MESSAGE_LENGTH");

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
        struct UDPBlockMessage block;
    } msg;
};
static_assert(sizeof(UDPMessage) == 1186, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
static_assert(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
static_assert(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0, // Indicating the node was just added
    STATE_GOT_SYN = 1, // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1, // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
};

struct PartialBlockData {
    const int64_t timeHeaderRecvd;
    const CService nodeHeaderRecvd;

    std::atomic_bool in_header; // Indicates we are currently downloading header (or block txn)
    std::atomic_bool initialized; // Indicates Init has been called in current in_header state
    std::atomic_bool is_decodeable; // Indicates decoder.DecodeReady() && !in_header
    std::atomic_bool is_header_processing; // Indicates in_header && !initialized but header is ready

    std::mutex state_mutex;
    // Background thread is preparing to, and is submitting to core
    // This is set with state_mutex held, and afterwards block_data and
    // nodesWithChunksAvailableSet should be treated read-only.
    std::atomic_bool currentlyProcessing;

    uint32_t obj_length; // FEC-coded length of currently-being-download object
    uint32_t chunks_sent;
    std::vector<unsigned char> data_recvd;
    FECDecoder decoder; // Note that this may have been std::move()d if (currentlyProcessing)
    PartiallyDownloadedChunkBlock block_data;

    // nodes with chunks_avail set -> packets that were useful, packets provided
    std::map<CService, std::pair<uint32_t, uint32_t> > nodesWithChunksAvailableSet;

    bool Init(const UDPMessage& msg);
    ReadStatus ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header);
    PartialBlockData(const CService& node, const UDPMessage& header_msg); // Must be a MSG_TYPE_BLOCK_HEADER
    void ReconstructBlockFromDecoder();
};

class ChunksAvailableSet {
private:
    int32_t header_chunk_count;
    bool allSent;
    uint8_t bitset[496]; // We can only track a total of ~4MB of header+block data+fec chunks...should be plenty
public:
    ChunksAvailableSet(bool hasAllChunks) : header_chunk_count(-1), allSent(hasAllChunks) { if (!allSent) memset(bitset, 0, sizeof(bitset)); }
    bool IsHeaderChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (chunk_id / 8 > sizeof(bitset)) return false;
        return ((bitset[chunk_id / 8] >> (chunk_id & 7)) & 1);
    }
    void SetHeaderChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (chunk_id / 8 > sizeof(bitset)) return;
        bitset[chunk_id / 8]  |= 1 << (chunk_id & 7);
    }
    void SetHeaderDataAndFECChunkCount(uint16_t chunks_sent) { header_chunk_count = chunks_sent; }
    bool IsBlockChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (header_chunk_count == -1) return false;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return false;
        return ((bitset[bitset_id / 8] >> (bitset_id & 7)) & 1);
    }
    void SetBlockChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (header_chunk_count == -1) return;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return;
        bitset[bitset_id / 8]  |= 1 << (bitset_id & 7);
    }

    void SetAllAvailable() { allSent = true; }
    bool AreAllAvailable() const { return allSent; }
};

struct UDPConnectionInfo {
    uint64_t local_magic;  // Already LE
    uint64_t remote_magic; // Already LE
    size_t group;
    bool fTrusted;
    UDPConnectionType connection_type;
};

struct UDPConnectionState {
    UDPConnectionInfo connection;
    int state; // Flags from UDPState
    uint32_t protocolVersion;
    int64_t lastSendTime;
    int64_t lastRecvTime;
    int64_t lastPingTime;
    std::map<uint64_t, int64_t> ping_times;
    double last_pings[10];
    unsigned int last_ping_location;
    std::map<uint64_t, ChunksAvailableSet> chunks_avail;

    UDPConnectionState() : connection({}), state(0), protocolVersion(0), lastSendTime(0), lastRecvTime(0), lastPingTime(0), last_ping_location(0)
        { for (size_t i = 0; i < sizeof(last_pings) / sizeof(double); i++) last_pings[i] = -1; }
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

extern std::recursive_mutex cs_mapUDPNodes;
extern std::map<CService, UDPConnectionState> mapUDPNodes;
extern bool maybe_have_write_nodes;

void SendMessage(const UDPMessage& msg, const unsigned int length, const CService& service, const uint64_t magic, size_t group);
void SendMessage(const UDPMessage& msg, const unsigned int length, const std::map<CService, UDPConnectionState>::const_iterator& node);
void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it);

void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs);

#endif
