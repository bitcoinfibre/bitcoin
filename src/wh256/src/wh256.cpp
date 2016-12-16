/*
    Copyright (c) 2012-2016 Christopher A. Taylor.  All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of WH256 nor the names of its contributors may be
      used to endorse or promote products derived from this software without
      specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

#include "wh256.h"

#include "cm256.h"
#include "wirehair_codec_8.hpp"

static bool m_init = false;

// Number of input blocks N to start using Wirehair at instead of CM256
static const int WIREHAIR_THRESHOLD_N = 28;

int wh256_init_(int expected_version)
{
    // If version mismatch:
    if (expected_version != WH256_VERSION)
    {
        return -1;
    }

    if (gf256_init())
    {
        return -2;
    }
    if (cm256_init())
    {
        return -3;
    }
    m_init = true;

    return 0;
}


//-----------------------------------------------------------------------------
// Internal WH256 Codec State

struct CodecState
{
    bool UsingWirehair;
    wirehair::Codec* WirehairCodec;

    // CM256 state:
    cm256_encoder_params EncoderParams;
    const uint8_t* OriginalMessage;
    cm256_block_t Blocks[256];
    int BlocksReceived;
    int LastBlockSize;

    // Space allocated for the last block during encoding
    uint8_t* LastBlock;

    // Space allocated to store block data during decoding
    uint8_t* BlockWorkspace;

    void ResetCM256()
    {
        delete[] LastBlock;
        LastBlock = nullptr;

        delete[] BlockWorkspace;
        BlockWorkspace = nullptr;

        BlocksReceived = 0;
        LastBlockSize = 0;
    }

    CodecState()
    {
        UsingWirehair = false;
        for (int i = 0; i < 256; ++i)
        {
            Blocks[i].Data = nullptr;
        }
        WirehairCodec = nullptr;
        OriginalMessage = nullptr;
        BlocksReceived = 0;
        LastBlockSize = 0;

        LastBlock = nullptr;
        BlockWorkspace = nullptr;
    }
    ~CodecState()
    {
        delete WirehairCodec;

        ResetCM256();
    }
};


wh256_state wh256_encoder_init(wh256_state reuse_E, const void* message, int bytes, int block_bytes)
{
    // If input is invalid:
    if (!m_init || !message || bytes < 1 || block_bytes < 1)
    {
        return nullptr;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(reuse_E);

    // Allocate a new Codec object
    if (!codec)
    {
        codec = new CodecState;
    }

    // Use CM256 up to a number of input blocks
    int N = (bytes + block_bytes - 1) / block_bytes;
    codec->UsingWirehair = (N >= WIREHAIR_THRESHOLD_N);

    if (!codec->UsingWirehair)
    {
        codec->ResetCM256();
        codec->OriginalMessage = static_cast<const uint8_t*>(message);

        codec->EncoderParams.OriginalCount = N;
        codec->EncoderParams.RecoveryCount = 256 - N;
        codec->EncoderParams.BlockBytes = block_bytes;

        const uint8_t* block = codec->OriginalMessage;
        for (int i = 0; i < N; ++i, block += block_bytes)
        {
            codec->Blocks[i].Data = (void*)block;
        }

        // Note: The CM256 codec assumes the input blocks are all the same
        // length so sometimes we must pad the final input block with zeroes
        // out to the block length.

        // If there is no need to pad out the last block:
        codec->LastBlockSize = bytes - (N-1) * block_bytes;
        if (codec->LastBlockSize <= 0)
        {
            codec->LastBlockSize = block_bytes;
        }
        else
        {
            assert(!codec->LastBlock); // Should have been cleared by ResetCM256()
            codec->LastBlock = new uint8_t[block_bytes];

            // Copy the original data into the LastBlock workspace and pad it with zeroes
            memcpy(codec->LastBlock, block - block_bytes, codec->LastBlockSize);
            memset(codec->LastBlock + codec->LastBlockSize, 0, block_bytes - codec->LastBlockSize);

            codec->Blocks[N - 1].Data = codec->LastBlock;
        }
    }
    else
    {
        if (!codec->WirehairCodec)
        {
            codec->WirehairCodec = new wirehair::Codec;
        }

        // Initialize codec
        wirehair::Result r = codec->WirehairCodec->InitializeEncoder(bytes, block_bytes);

        if (r == wirehair::R_WIN)
        {
            // Feed message to codec
            r = codec->WirehairCodec->EncodeFeed(message);
        }

        // On failure:
        if (r != wirehair::R_WIN)
        {
            delete codec;
            codec = nullptr;
        }
    }

    return codec;
}

int wh256_count(wh256_state E)
{
    // If input is invalid:
    if (!E)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        return codec->WirehairCodec->BlockCount();
    }
    else
    {
        return codec->EncoderParams.OriginalCount;
    }
}

static inline int WH256IndexToCM256Index(const cm256_encoder_params& params, int wh256Index)
{
    if (wh256Index < params.OriginalCount)
        return wh256Index;

    const unsigned int recoveryCount = (unsigned int)params.RecoveryCount;

    // Cycle through the available recovery blocks
    unsigned int recoveryIndex = wh256Index - params.OriginalCount;
    if (recoveryIndex >= recoveryCount)
        recoveryIndex %= recoveryCount; // Uncommon

    return recoveryIndex + params.OriginalCount;
}

int wh256_encoder_write(wh256_state E, unsigned int id, void* block, int* bytes_written)
{
    // Initialize bytes written to zero:
    if (!bytes_written)
        return -1;
    *bytes_written = 0;

    // If input is invalid:
    if (!E || !block)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        const uint32_t wh_written = codec->WirehairCodec->Encode(id, block);
        if (wh_written <= 0)
            return -2;

        *bytes_written = (int)wh_written;
    }
    else
    {
        int written = codec->EncoderParams.BlockBytes;
        if (id < static_cast<unsigned int>(codec->EncoderParams.OriginalCount))
        {
            if (id == static_cast<unsigned int>(codec->EncoderParams.OriginalCount - 1))
                written = codec->LastBlockSize;

            memcpy(block, codec->Blocks[id].Data, written);
        }
        else
        {
            id = WH256IndexToCM256Index(codec->EncoderParams, id);

            cm256_encode_block(codec->EncoderParams, codec->Blocks, id, block);
        }

        *bytes_written = written;
    }

    return 0;
}

wh256_state wh256_decoder_init(wh256_state reuse_E, int bytes, int block_bytes)
{
    // If input is invalid:
    if (bytes < 1 || block_bytes < 1)
    {
        return nullptr;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(reuse_E);

    // Allocate a new Codec object
    if (!codec)
    {
        codec = new CodecState;
    }

    // Use CM256 up to a number of input blocks
    int N = (bytes + block_bytes - 1) / block_bytes;
    codec->UsingWirehair = (N >= WIREHAIR_THRESHOLD_N);

    if (codec->UsingWirehair)
    {
        if (!codec->WirehairCodec)
        {
            codec->WirehairCodec = new wirehair::Codec;
        }

        // Allocate memory for decoding
        wirehair::Result r = codec->WirehairCodec->InitializeDecoder(bytes, block_bytes);

        if (r != wirehair::R_WIN)
        {
            assert(false);
            delete codec;
            codec = nullptr;
        }
    }
    else
    {
        codec->ResetCM256();
        codec->OriginalMessage = nullptr;

        codec->EncoderParams.BlockBytes = block_bytes;
        codec->EncoderParams.OriginalCount = N;
        codec->EncoderParams.RecoveryCount = 256 - N; // Provide for as many unique recovery blocks as we can get

        codec->LastBlockSize = bytes - (N-1) * block_bytes;
        if (codec->LastBlockSize <= 0)
        {
            codec->LastBlockSize = block_bytes;
        }

        assert(!codec->BlockWorkspace); // Should have been cleared by ResetCM256()
        uint8_t* workspace = codec->BlockWorkspace = new uint8_t[N * block_bytes];
        for (int i = 0; i < N; ++i, workspace += block_bytes)
        {
            codec->Blocks[i].Data = workspace;
        }
    }

    return codec;
}

int wh256_decoder_read(wh256_state E, unsigned int id, const void *block)
{
    // If input is invalid:
    if (!E || !block)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        if (wirehair::R_WIN == codec->WirehairCodec->DecodeFeed(id, block))
        {
            return 0;
        }

        return -2;
    }

    id = WH256IndexToCM256Index(codec->EncoderParams, id);

    codec->Blocks[codec->BlocksReceived].Index = id;

    uint8_t* dest = reinterpret_cast<uint8_t*>(codec->Blocks[codec->BlocksReceived].Data);

    if (id == codec->EncoderParams.OriginalCount - 1)
    {
        // Copy partial last block and pad with zeroes
        memcpy(dest, block, codec->LastBlockSize);
        memset(dest + codec->LastBlockSize, 0, codec->EncoderParams.BlockBytes - codec->LastBlockSize);
    }
    else
    {
        memcpy(dest, block, codec->EncoderParams.BlockBytes);
    }

    if (++codec->BlocksReceived == codec->EncoderParams.OriginalCount)
    {
        if (0 == cm256_decode(codec->EncoderParams, codec->Blocks))
        {
            return 0;
        }
        else
        {
            // Perhaps invalid input; dump it all and start over
            assert(false);
            codec->BlocksReceived = 0;
        }
    }

    return -3;
}

int wh256_decoder_reconstruct(wh256_state E, void *message)
{
    // If input is invalid:
    if (!E || !message)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        if (wirehair::R_WIN == codec->WirehairCodec->ReconstructOutput(message))
        {
            return 0;
        }

        return -2; // Decoding hasn't completed yet
    }

    if (codec->BlocksReceived < codec->EncoderParams.OriginalCount)
    {
        return -3; // Decoding hasn't completed yet
    }

    uint8_t* blockOut = reinterpret_cast<uint8_t*>(message);
    int copySizeBytes = codec->EncoderParams.BlockBytes;

    // For each original block to copy:
    for (int i = 0; i < codec->EncoderParams.OriginalCount; ++i, blockOut += codec->EncoderParams.BlockBytes)
    {
        // Block indices after cm256 decoding completes should be in order
        int index = codec->Blocks[i].Index;
        if (index != i)
        {
            assert(false);
            return -4; // Software bug?
        }

        // The last block can be smaller than the rest
        if (index == codec->EncoderParams.OriginalCount - 1)
        {
            copySizeBytes = codec->LastBlockSize;
        }

        const void* src = codec->Blocks[i].Data;
        memcpy(blockOut, src, copySizeBytes);
    }

    return 0;
}

int wh256_decoder_reconstruct_block(wh256_state E, unsigned int id, void *blockOut)
{
    // If input is invalid:
    if (!E || !blockOut)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        if (wirehair::R_WIN == codec->WirehairCodec->ReconstructBlock(id, blockOut))
        {
            return 0;
        }

        return -2;
    }

    // Verify that the cm256 decoder has finished
    if (codec->BlocksReceived < codec->EncoderParams.OriginalCount)
    {
        return -3; // Called before enough data arrived
    }

    // Validate input is specifying original data and not recovery data
    if (id >= (unsigned int)codec->EncoderParams.OriginalCount)
    {
        return -4;
    }

    // Block indices after cm256 decoding completes should be in order
    const int index = codec->Blocks[id].Index;
    if (index != id)
    {
        assert(false);
        return -5; // Software bug?
    }

    // The last block may be smaller than the rest
    int copyBytes = codec->EncoderParams.BlockBytes;
    if (index == codec->EncoderParams.OriginalCount - 1)
        copyBytes = codec->LastBlockSize;

    memcpy(blockOut, codec->Blocks[index].Data, copyBytes);
    return 0;
}

int wh256_decoder_becomes_encoder(wh256_state E)
{
    // If input is invalid:
    if (!E)
    {
        return -1;
    }

    CodecState* codec = reinterpret_cast<CodecState*>(E);

    if (codec->UsingWirehair)
    {
        wirehair::Result r = codec->WirehairCodec->InitializeEncoderFromDecoder();
        return (r == wirehair::Result::R_WIN) ? 0 : -2;
    }

    // CM256 decoder is already initializing the Blocks[] array to what we need
    // for the encoder.
    return 0;
}

void wh256_free(wh256_state E)
{
    CodecState* codec = reinterpret_cast<CodecState*>(E);

    delete codec;
}
