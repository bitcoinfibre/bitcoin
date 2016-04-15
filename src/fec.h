// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_FEC_H
#define BITCOIN_FEC_H

#include <assert.h>
#include <memory>
#include <stdint.h>
#include <vector>

#include "wh256/src/wh256.h"

class FECDecoder;
class FECEncoder {
private:
    wh256_state state = NULL;
    const std::vector<unsigned char>* data;
    std::vector<unsigned char>* fec_chunks;
    std::vector<bool> chunks_built;

public:
    // dataIn/fec_chunksIn must not change during lifetime of this object
    FECEncoder(const std::vector<unsigned char>* dataIn, std::vector<unsigned char>* fec_chunksIn);
    FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::vector<unsigned char>* fec_chunksIn);
    ~FECEncoder();

    FECEncoder(const FECEncoder&) =delete;
    FECEncoder(FECEncoder&&) =delete;

    bool BuildChunk(size_t fec_chunk_id);
    bool PrefillChunks();
};

class FECDecoder {
private:
    size_t chunk_count, chunks_recvd, chunks_sent;
    mutable bool decodeComplete;
    std::vector<bool> chunk_recvd_flags;
    std::aligned_storage<FEC_CHUNK_SIZE, 16>::type tmp_chunk;

    wh256_state state = NULL;
    friend FECEncoder::FECEncoder(FECDecoder&& decoder, const std::vector<unsigned char>* dataIn, std::vector<unsigned char>* fec_chunksIn);
public:
    FECDecoder(size_t data_size, size_t chunks_provided);
    FECDecoder() {}
    ~FECDecoder();

    FECDecoder(const FECDecoder&) =delete;
    FECDecoder(FECDecoder&& decoder) =delete;
    FECDecoder& operator=(FECDecoder&& decoder);

    bool ProvideChunk(const unsigned char* chunk, size_t chunk_id);
    bool HasChunk(size_t chunk_id);
    bool DecodeReady() const;
    const void* GetDataPtr(size_t chunk_id); // Only valid until called again
};

bool BuildFECChunks(const std::vector<unsigned char>& data, std::vector<unsigned char>& fec_chunks);

#endif
