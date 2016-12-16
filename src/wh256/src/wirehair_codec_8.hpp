/*
    Copyright (c) 2012-2015 Christopher A. Taylor.  All rights reserved.

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

#ifndef WIREHAIR_CODEC_8_HPP
#define WIREHAIR_CODEC_8_HPP

#include "gf256.h"

// Debugging:
//#define CAT_DUMP_CODEC_DEBUG    /* Turn on debug output for decoder */
//#define CAT_DUMP_ROWOP_COUNTERS /* Dump row operations counters to console */
//#define CAT_DUMP_PIVOT_FAIL     /* Dump pivot failure to console */
//#define CAT_DUMP_GE_MATRIX      /* Dump GE matrix to console */

// Limits:
#define CAT_REF_LIST_MAX 32      /* Tune to be as small as possible and still succeed */
#define CAT_MAX_DENSE_ROWS 500   /* Maximum check row count */
#define CAT_MAX_EXTRA_ROWS 32    /* Maximum number of extra rows to support before reusing existing rows */
#define CAT_WIREHAIR_MAX_N 64000 /* Largest N value to allow */
#define CAT_WIREHAIR_MIN_N 2     /* Smallest N value to allow */

// Optimization options:
#define CAT_COPY_FIRST_N      /* Copy the first N rows from the input (faster) */
#define CAT_HEAVY_WIN_MULT    /* Use 4-bit table and multiplication optimization (faster) */
#define CAT_WINDOWED_BACKSUB  /* Use window optimization for back-substitution (faster) */
#define CAT_WINDOWED_LOWERTRI /* Use window optimization for lower triangle elimination (faster) */
//#define CAT_ALL_ORIGINAL      /* Avoid doing calculations for 0 losses -- Requires CAT_COPY_FIRST_N (faster) */

// Heavy rows:
#define CAT_HEAVY_ROWS 6      /* Number of heavy rows to add - Tune for desired overhead / performance trade-off */
#define CAT_HEAVY_MAX_COLS 18 /* Number of heavy columns that are non-zero */

namespace wirehair {


//// Result object

enum Result
{
    R_WIN,              // Operation: Success!
    R_MORE_BLOCKS,      // Codec wants more blocks.  Om nom nom.

    R_ERROR,            // Return codes higher than this one are errors:
    R_BAD_DENSE_SEED,   // Encoder needs a better dense seed
    R_BAD_PEEL_SEED,    // Encoder needs a better peel seed
    R_BAD_INPUT,        // Input parameters were incorrect
    R_TOO_SMALL,        // message_bytes / block_size is too small.  Try reducing block_size or use a larger message
    R_TOO_LARGE,        // message_bytes / block_size is too large.  Try increasing block_size or use a smaller message
    R_NEED_MORE_EXTRA,  // Not enough extra rows to solve it, must give up
    R_OUT_OF_MEMORY,    // Out of memory, try reducing the message size
};

// Get Result String function
const char *GetResultString(Result r);

extern GF256_ALIGNED gf256_ctx GF256Ctx;


//// Encoder/Decoder Combined Implementation

class Codec
{
    // Parameters
    //uint32_t _block_bytes;                      // Number of bytes in a block
    uint16_t _block_count;                      // Number of blocks in the message
    uint16_t _block_next_prime;                 // Next prime number at or above block count
    uint16_t _extra_count;                      // Number of extra rows to allocate
    uint32_t _p_seed;                           // Seed for peeled rows of check matrix
    uint32_t _d_seed;                           // Seed for dense rows of check matrix
    uint16_t _row_count;                        // Number of stored rows
    uint16_t _mix_count;                        // Number of mix columns
    uint16_t _mix_next_prime;                   // Next prime number at or above dense count
    uint16_t _dense_count;                      // Number of added dense code rows
    uint8_t * GF256_RESTRICT _recovery_blocks;  // Recovery blocks
    uint8_t * GF256_RESTRICT _input_blocks;     // Input message blocks
    uint32_t _input_final_bytes;                // Number of bytes in final block of input
    uint32_t _output_final_bytes;               // Number of bytes in final block of output
    uint32_t _input_allocated;                  // Number of bytes allocated for input, or 0 if referenced
#if defined(CAT_ALL_ORIGINAL)
    bool _all_original;                         // Boolean: Only seen original data block identifiers
#endif
    bool _encoder_was_decoder;                  // Boolean: Encoder was originally a decoder

    // Peeling state
    struct PeelRow;
    struct PeelColumn;
    struct PeelRefs;
    PeelRow * GF256_RESTRICT _peel_rows;        // Array of N peeling matrix rows
    PeelColumn * GF256_RESTRICT _peel_cols;     // Array of N peeling matrix columns
    PeelRefs * GF256_RESTRICT _peel_col_refs;   // List of column references
    PeelRow * GF256_RESTRICT _peel_tail_rows;   // Tail of peeling solved rows list
    uint32_t _workspace_allocated;              // Number of bytes allocated for workspace
    static const uint16_t LIST_TERM = 0xffff;
    uint16_t _peel_head_rows;                   // Head of peeling solved rows list
    uint16_t _defer_head_columns;               // Head of peeling deferred columns list
    uint16_t _defer_head_rows;                  // Head of peeling deferred rows list
    uint16_t _defer_count;                      // Count of deferred rows

    // Gaussian elimination state
    uint64_t * GF256_RESTRICT _ge_matrix;       // Gaussian elimination matrix
    uint32_t _ge_allocated;                     // Number of bytes allocated to GE matrix
    uint64_t * GF256_RESTRICT _compress_matrix; // Gaussian elimination compression matrix
    int _ge_pitch;                              // Words per row of GE matrix and compression matrix
    uint16_t * GF256_RESTRICT _pivots;          // Pivots for each column of the GE matrix
    uint16_t _pivot_count;                      // Number of pivots in the pivot list
    uint16_t * GF256_RESTRICT _ge_col_map;      // Map of GE columns to conceptual matrix columns
    uint16_t * GF256_RESTRICT _ge_row_map;      // Map of GE rows to conceptual matrix rows
    uint16_t _next_pivot;                       // Pivot to resume Triangle() on after it fails

    // Heavy rows
    uint8_t * GF256_RESTRICT _heavy_matrix;     // Heavy rows of GE matrix
    int _heavy_pitch;                           // Bytes per heavy matrix row
    uint16_t _heavy_columns;                    // Number of heavy matrix columns
    uint16_t _first_heavy_column;               // First heavy column that is non-zero
    uint16_t _first_heavy_pivot;                // First heavy pivot in the list

#if defined(CAT_DUMP_CODEC_DEBUG) || defined(CAT_DUMP_GE_MATRIX)
    void PrintGEMatrix();
    void PrintExtraMatrix();
    void PrintCompressMatrix();
    void PrintPeeled();
    void PrintDeferredRows();
    void PrintDeferredColumns();
#endif


    //// (1) Peeling

    // Avalanche peeling from the newly solved column to others
    void PeelAvalanche(uint16_t column_i);

    // Peel a row using the given column
    void Peel(uint16_t row_i, PeelRow * GF256_RESTRICT row, uint16_t column_i);

    // If a peel reference list overflows at fail_column_i, this function will unreference the row for previous columns
    void FixPeelFailure(PeelRow * GF256_RESTRICT row, uint16_t fail_column_i);

    // Walk forward through rows and solve as many as possible before deferring any
    bool OpportunisticPeeling(uint32_t row_i, uint32_t id);

    // Greedy algorithm to select columns to defer and resume peeling until all columns are marked
    void GreedyPeeling();


    //// (2) Compression

    // Set deferred column bits in compression matrix
    void SetDeferredColumns();

    // Set mixing columns for deferred rows
    void SetMixingColumnsForDeferredRows();

    // Diagonalize the peeling matrix, generating compression matrix
    void PeelDiagonal();

    // Copy deferred rows from the compress matrix to the GE matrix
    void CopyDeferredRows();

    // Multiply dense rows by peeling matrix to generate GE rows, but no row values yet
    void MultiplyDenseRows();

    // Initialize heavy submatrix
    void SetHeavyRows();


    //// (3) Gaussian Elimination

    // Initialize for triangularization routine
    void SetupTriangle();

    // Insert heavy rows into pivot list
    void InsertHeavyRows();

    // Handle non-heavy pivot finding
    bool TriangleNonHeavy();

    // Triangularize the GE matrix (may fail if pivot cannot be found)
    bool Triangle();

    // Initialize column values for GE matrix
    void InitializeColumnValues();

    // Multiply diagonalized peeling column values into dense rows
    void MultiplyDenseValues();

    // Add values for GE matrix positions under the diagonal
    void AddSubdiagonalValues();


    //// (4) Substitution

    // Back-substitute to diagonalize the GE matrix
    void BackSubstituteAboveDiagonal();

    // Regenerate all of the sparse peeled rows to diagonalize them
    void Substitute();


    //// Main Driver

    // Choose matrix to use based on message bytes
    Result ChooseMatrix(int message_bytes, int block_bytes);

    // Solve matrix so that recovery blocks can be generated
    Result SolveMatrix();

    // Resume solver with a new block
    Result ResumeSolveMatrix(uint32_t id, const void * GF256_RESTRICT block);

#if defined(CAT_ALL_ORIGINAL)
    // Verify that all data is from the original N, meaning no computations are needed
    bool IsAllOriginalData();
#endif


    //// Memory Management

    void SetInput(const void * GF256_RESTRICT message_in);
    bool AllocateInput();
    void FreeInput();

    bool AllocateMatrix();
    void FreeMatrix();

    bool AllocateWorkspace();
    void FreeWorkspace();

public:
    Codec();
    Codec(const Codec& c); // Copy constructor to use for pre-calced matrix storage
    ~Codec();


    //// Wipes a bunch of state to make this object suitable for use as pre-calculated matrix storage
    void FreeDataSpecificStorage();


    //// Accessors

    GF256_FORCE_INLINE uint32_t PSeed() { return _p_seed; }
    GF256_FORCE_INLINE uint32_t CSeed() { return _d_seed; }
    GF256_FORCE_INLINE uint32_t BlockCount() { return _block_count; }


    //// Encoder Mode

    // Initialize encoder mode
    Result InitializeEncoder(int message_bytes, int block_bytes);

    // Feed encoder a message
    Result EncodeFeed(const void * GF256_RESTRICT message_in);

    // Encode a block, returning number of bytes written
    uint32_t Encode(uint32_t id, void * GF256_RESTRICT block_out);


    //// Decoder Mode

    // Initialize decoder mode
    Result InitializeDecoder(int message_bytes, int block_bytes);

    // Feed decoder a block
    Result DecodeFeed(uint32_t id, const void * GF256_RESTRICT block_in);

    // Use matrix solution to generate recovery blocks
    void GenerateRecoveryBlocks();

    // Generate output blocks from the recovery blocks
    Result ReconstructOutput(void * GF256_RESTRICT message_out);

    // Reconstruct a single original block from the recovery blocks
    Result ReconstructBlock(uint16_t id, void * GF256_RESTRICT block_out);

    // Transition from decoder to encoder mode
    // Precondition: DecodeFeed() succeeded with R_WIN
    Result InitializeEncoderFromDecoder();
};


} // namespace wirehair

#endif // WIREHAIR_CODEC_8_HPP
