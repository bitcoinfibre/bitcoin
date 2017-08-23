// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <stdint.h>
#include <vector>
#include <mutex>
#include <assert.h>

#include "udpapi.h"
#include "netaddress.h"

// This is largely the API between udpnet and udprelay, see udpapi for the
// external-facing API

// Local stuff only uses magic, net stuff only uses protocol_version,
// so both need to be changed any time wire format changes
static const unsigned char LOCAL_MAGIC_BYTES[] = { 0xab, 0xad, 0xca, 0xfe };
static const uint32_t UDP_PROTOCOL_VERSION = (4 << 16) | 4; // Min version 3, current version 3

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
    MSG_TYPE_TX_CONTENTS = 7,
};

static const uint8_t UDP_MSG_TYPE_FLAGS_MASK = 0b11000000;
static const uint8_t UDP_MSG_TYPE_TYPE_MASK = 0b00111111;

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1;
    uint64_t chk2;
    uint8_t msg_type; // A UDPMessageType + flags
};
static_assert(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1167 bytes (1185 bytes in total UDP message contents, with a padding byte in message)
// Local send logic assumes this to be the size of block data packets in a few places!
#define MAX_UDP_MESSAGE_LENGTH 1167

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
    } msg;
};
static_assert(sizeof(UDPMessage) == 1185, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
static_assert(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
static_assert(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0, // Indicating the node was just added
    STATE_GOT_SYN = 1, // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1, // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
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
    // for speed calculations (mbps)
    int64_t rcvdBytes;
    int64_t lastAvgTime;

    UDPConnectionState() : connection({}), state(0), protocolVersion(0), lastSendTime(0), lastRecvTime(0), lastPingTime(0), last_ping_location(0),
        rcvdBytes(0), lastAvgTime(0)
        { for (size_t i = 0; i < sizeof(last_pings) / sizeof(double); i++) last_pings[i] = -1; }
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

extern std::recursive_mutex cs_mapUDPNodes;
extern std::map<CService, UDPConnectionState> mapUDPNodes;
extern std::atomic<uint64_t> min_per_node_mbps; // Used to determine header FEC chunk count
extern bool maybe_have_write_nodes;

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group);
void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::map<CService, UDPConnectionState>::const_iterator& node);
void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it);

#endif
