// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include "udpnet.h"

void UDPRelayBlock(const CBlock& block);

void BlockRecvInit();

void BlockRecvShutdown();

bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state);

void ProcessDownloadTimerEvents();

#endif
