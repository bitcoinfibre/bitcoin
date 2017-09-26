// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "udprelay.h"

void UDPRelayBlock(const CBlock& block) {

}

void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<UDPMessage>& msgs) {
    msgs.clear();
}

void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs) {
    msgs.clear();
}

void BlockRecvInit() {

}

void BlockRecvShutdown() {

}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start) {
    return true;
}

void ProcessDownloadTimerEvents() {

}

