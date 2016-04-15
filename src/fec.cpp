// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "fec.h"

#include <stdio.h>
#include <string.h>

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

#define FEC_CHUNK_COUNT_MAX (1 << 24)
#define CHUNK_COUNT_USES_CM256(chunks) ((chunks) < 28)

BlockChunkRecvdTracker::BlockChunkRecvdTracker(size_t chunk_count) :
        data_chunk_recvd_flags(CHUNK_COUNT_USES_CM256(chunk_count) ? 0xff : chunk_count),
        fec_chunks_recvd(CHUNK_COUNT_USES_CM256(chunk_count) ? 1 : chunk_count) { }

BlockChunkRecvdTracker& BlockChunkRecvdTracker::operator=(BlockChunkRecvdTracker&& other) {
    data_chunk_recvd_flags = std::move(other.data_chunk_recvd_flags);
    fec_chunks_recvd       = std::move(other.fec_chunks_recvd);
    return *this;
}

FECDecoder::FECDecoder(size_t data_size) :
        chunk_count(DIV_CEIL(data_size, FEC_CHUNK_SIZE)), chunks_recvd(0),
        chunk_tracker(chunk_count), decodeComplete(false) {
    if (chunk_count < 2)
        return;
    state = wirehair_decoder_create(NULL, data_size, FEC_CHUNK_SIZE);
    assert(state);
}

FECDecoder& FECDecoder::operator=(FECDecoder&& decoder) {
    chunk_count     = decoder.chunk_count;
    chunks_recvd    = decoder.chunks_recvd;
    decodeComplete  = decoder.decodeComplete;
    chunk_tracker   = std::move(decoder.chunk_tracker);
    memcpy(&tmp_chunk, &decoder.tmp_chunk, sizeof(tmp_chunk));
    state           = decoder.state;
    decoder.state   = NULL;
    return *this;
}

FECDecoder::~FECDecoder() {
    if (state)
        wirehair_free(state);
}

bool FECDecoder::ProvideChunk(const unsigned char* chunk, uint32_t chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    if (decodeComplete)
        return true;

    // wirehair breaks if we call it twice with the same packet
    if (chunk_tracker.CheckPresentAndMarkRecvd(chunk_id))
        return true;

    chunks_recvd++;
    if (chunk_count < 2) { // For 1-packet data, just send it repeatedly...
        memcpy(&tmp_chunk, chunk, FEC_CHUNK_SIZE);
        decodeComplete = true;
    } else if (!wirehair_decode(state, chunk_id, (void*)chunk, FEC_CHUNK_SIZE))
        decodeComplete = true;

    return true;
}

bool FECDecoder::HasChunk(uint32_t chunk_id) {
    if (CHUNK_COUNT_USES_CM256(chunk_count) ? chunk_id > 0xff : chunk_id > FEC_CHUNK_COUNT_MAX)
        return false;

    return decodeComplete || chunk_tracker.CheckPresent(chunk_id);
}

bool FECDecoder::DecodeReady() const {
    return decodeComplete;
}

const void* FECDecoder::GetDataPtr(uint32_t chunk_id) {
    assert(DecodeReady());
    assert(chunk_id < chunk_count);
    uint32_t chunk_size = FEC_CHUNK_SIZE;
    if (chunk_count >= 2)
        assert(!wirehair_recover_block(state, chunk_id, (void*)&tmp_chunk, &chunk_size));
    return &tmp_chunk;
}


FECEncoder::FECEncoder(const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    if (DIV_CEIL(data->size(), FEC_CHUNK_SIZE) < 2)
        return;

    state = wirehair_encoder_create(NULL, data->data(), data->size(), FEC_CHUNK_SIZE);
    assert(state);
}

FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>* fec_chunksIn)
        : data(dataIn), fec_chunks(fec_chunksIn) {
    assert(!fec_chunks->second.empty());
    assert(!data->empty());

    if (DIV_CEIL(data->size(), FEC_CHUNK_SIZE) < 2)
        return;

    state = decoder.state;
    decoder.state = NULL;

    assert(!wirehair_decoder_becomes_encoder(state));
    assert(state);
}

FECEncoder::~FECEncoder() {
    if (state)
        wirehair_free(state);
}

bool FECEncoder::BuildChunk(size_t vector_idx) {
    assert(vector_idx < fec_chunks->second.size());

    if (fec_chunks->second[vector_idx])
        return true;

    size_t data_chunks = DIV_CEIL(data->size(), FEC_CHUNK_SIZE);
    if (data_chunks < 2) { // For 1-packet data, just send it repeatedly...
        memcpy(&fec_chunks->first[vector_idx], &(*data)[0], data->size());
        memset(((char*)&fec_chunks->first[vector_idx]) + data->size(), 0, FEC_CHUNK_SIZE - data->size());
        fec_chunks->second[vector_idx] = vector_idx + 1;
        return true;
    }

    uint32_t fec_chunk_id;
    // wh256 supports either unlimited chunks, or up to 256 incl data chunks
    // if data_chunks < 28 (as it switches to cm256 mode)
    if (CHUNK_COUNT_USES_CM256(data_chunks)) {
        if (cm256_start_idx == -1)
            cm256_start_idx = GetRand(0xff);
        fec_chunk_id = (cm256_start_idx + vector_idx) % (0xff - data_chunks);
    } else
        fec_chunk_id = rand.randrange(FEC_CHUNK_COUNT_MAX - data_chunks);
    size_t chunk_id = fec_chunk_id + data_chunks;

    uint32_t chunk_bytes;
    if (wirehair_encode(state, chunk_id, &fec_chunks->first[vector_idx], FEC_CHUNK_SIZE, &chunk_bytes))
        return false;

    if (chunk_bytes != FEC_CHUNK_SIZE)
        memset(((char*)&fec_chunks->first[vector_idx]) + chunk_bytes, 0, FEC_CHUNK_SIZE - chunk_bytes);

    fec_chunks->second[vector_idx] = chunk_id;
    return true;
}

bool FECEncoder::PrefillChunks() {
    bool fSuccess = true;
    for (size_t i = 0; i < fec_chunks->second.size() && fSuccess; i++) {
        fSuccess = BuildChunk(i);
    }
    return fSuccess;
}

bool BuildFECChunks(const std::vector<unsigned char>& data, std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>>& fec_chunks) {
    FECEncoder enc(&data, &fec_chunks);
    return enc.PrefillChunks();
}

class FECInit
{
public:
    FECInit() {
        assert(!wirehair_init());
    }
} instance_of_fecinit;
