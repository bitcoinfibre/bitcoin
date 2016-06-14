// Copyright (c) 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

// This is the external API to FIBRE for use in RPC/validation/etc

#ifndef BITCOIN_UDPAPI_H
#define BITCOIN_UDPAPI_H

#include "netaddress.h"

class CBlock;

std::vector<std::pair<unsigned short, uint64_t> > GetUDPInboundPorts(); // port, outbound bandwidth for group
bool InitializeUDPConnections();
void StopUDPConnections();

// fUltimatelyTrusted means you trust them (ie whitelist) and ALL OF THEIR SUBSEQUENT WHITELISTED PEERS
void OpenUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, size_t group = 0);
void OpenPersistentUDPConnectionTo(const CService& remote_addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, size_t group = 0);

void CloseUDPConnectionTo(const CService& remote_addr);

struct UDPConnectionStats {
    CService remote_addr;
    size_t group;
    bool fUltimatelyTrusted;
    int64_t lastRecvTime;
    std::vector<double> last_pings;
};
void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list);

void UDPRelayBlock(const CBlock& block);

#endif
