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

#ifndef WH256_H
#define WH256_H

#define FEC_CHUNK_SIZE 1152

#ifdef __cplusplus
extern "C" {
#endif

#define WH256_VERSION 5

/*
 * Verify binary compatibility with the API on startup.
 *
 * Example:
 *     if (wh256_init()) exit(1);
 *
 * Returns non-zero on error.
 * Returns 0 on success.
 */
extern int wh256_init_(int expected_version);
#define wirehair_init() wh256_init_(WH256_VERSION)

typedef void* wh256_state;


/*
 * Encode the given message into blocks of size block_bytes.
 *
 * The number of blocks in the message N = CEIL(bytes / block_bytes).
 *
 * If N is too high or too low this function will fail.  In particular if N = 1, then
 * using this type of error correction does not make sense: Sending the same message
 * over and over is just as good.  And if N > 64000 then some internal variables will
 * start to overflow, so too many blocks is unsupported.  The most efficient values
 * for N are around 1000.
 *
 * Pass 0 for reuse_E if you do not want to reuse a state object.
 *
 * Preconditions:
 *     N >= 1
 *     N <= 64000
 *
 * Returns a valid state object on success.
 * Returns nullptr(0) on failure.
 */
extern wh256_state wh256_encoder_init(wh256_state reuse_E, const void* message, int bytes, int block_bytes);

/*
 * Returns the number of blocks N in the encoded message.
 */
extern int wh256_count(wh256_state E);

/*
 * Write an error correction block.
 *
 * The first id < N blocks are the same as the input data.  This can be
 * used to run the encoder in parallel with normal data transmission.
 *
 * Preconditions:
 *    Block pointer has block_bytes of space available to store data
 *
 * Returns 0 on success and sets bytes_written to the number of bytes written.
 * Returns non-zero on invalid input and bytes_written is set to 0.
 */
extern int wh256_encoder_write(wh256_state E, unsigned int id, void* block, int* bytes_written);

/*
 * Initialize a decoder for a message of size bytes with block_bytes bytes
 * per received block.
 *
 * Pass 0 for reuse_E if you do not want to reuse a state object.
 *
 * Returns a valid state object on success.
 * Returns nullptr(0) on failure.
 */
extern wh256_state wh256_decoder_init(wh256_state reuse_E, int bytes, int block_bytes);

/*
 * Feed a block to the decoder.
 *
 * This function will return non-zero when reading is complete.
 *
 * Preconditions:
 *    Block pointer has block_bytes of space available to store data
 *    Must not call wh256_decoder_read twice with the same packet ID
 *
 * Returns 0 when decoding is complete.
 * Returns non-zero on invalid input or not enough data received yet.
 */
extern int wh256_decoder_read(wh256_state E, unsigned int id, const void* block);

/*
 * Reconstruct the message after reading is complete.
 *
 * Preconditions:
 *    Message contains enough space to store the entire decoded message (bytes)
 *
 * May return non-zero to indicate a failure.
 */
extern int wh256_decoder_reconstruct(wh256_state E, void* message);

/*
 * Reconstruct a single block of the message after reading is complete.
 *
 * This version is more suitable for a packet error correction scheme
 * rather than for file transfer.
 *
 * Preconditions:
 *    Block ptr buffer contains enough space to hold the block (block_bytes)
 *
 * May return non-zero to indicate a failure.
 */
extern int wh256_decoder_reconstruct_block(wh256_state E, unsigned int id, void* block);

/*
* Convert a decoder wh256_state into an encoder wh256_state after decoding
* completes.  This enables you to receive a message and then retransmit it
* without reinitializing the encoder.
*
* Preconditions:
*    wh256_decoder_reconstruct() has returned 0 indicating success
*
* May return non-zero to indicate a failure.
*/
extern int wh256_decoder_becomes_encoder(wh256_state E);

/*
 * Free memory associated with a state object
 */
extern void wh256_free(wh256_state E);

#ifdef __cplusplus
}
#endif

#endif // WH256_H
