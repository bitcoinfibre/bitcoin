// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "udprelay.h"

void UDPRelayBlock(const CBlock& block) {

}

void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs) {
    msgs.clear();
}

void BlockRecvInit() {

}

void BlockRecvShutdown() {

}

bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state) {
    return true;
}

void ProcessDownloadTimerEvents() {

}

