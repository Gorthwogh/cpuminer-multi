/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <stdint.h>
#include <string.h>
//#include "simd-utils.h"
#include "hmac-sha256-hash.h"
#include "compat.h"

/**
 * SHA256_Buf(in, len, digest):
 * Compute the SHA256 hash of ${len} bytes from ${in} and write it to ${digest}.
 */
void
SHA256_Buf( const void * in, size_t len, uint8_t digest[32] )
{
	SHA256_CTX ctx;
   SHA256_Init( &ctx );
   SHA256_Update( &ctx, in, len );
   SHA256_Final( digest, &ctx );
}

/**
 * HMAC_SHA256_Buf(K, Klen, in, len, digest):
 * Compute the HMAC-SHA256 of ${len} bytes from ${in} using the key ${K} of
 * length ${Klen}, and write the result to ${digest}.
 */
void
HMAC_SHA256_Buf( const void *K, size_t Klen, const void *in, size_t len,
                 uint8_t digest[32])
{
   HMAC_SHA256_CTX ctx;
   HMAC_SHA256_Init( &ctx, K, Klen );
   HMAC_SHA256_Update( &ctx, in, len );
   HMAC_SHA256_Final( digest, &ctx );
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
HMAC_SHA256_Init( HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen )
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char * K = _K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if ( Klen > 64 )
   {
		SHA256_Init( &ctx->ictx );
		SHA256_Update( &ctx->ictx, K, Klen );
		SHA256_Final( khash, &ctx->ictx );
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
   SHA256_Init( &ctx->ictx );


   for ( i = 0; i < Klen; i++ )  pad[i] = K[i] ^ 0x36;
   memset( pad + Klen, 0x36, 64 - Klen );
	SHA256_Update( &ctx->ictx, pad, 64 );

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init( &ctx->octx );

   for ( i = 0; i < Klen; i++ )  pad[i] = K[i] ^ 0x5c;
   memset( pad + Klen, 0x5c, 64 - Klen );
	SHA256_Update( &ctx->octx, pad, 64 );
}

/* Add bytes to the HMAC-SHA256 operation. */
void
HMAC_SHA256_Update( HMAC_SHA256_CTX *ctx, const void *in, size_t len )
{
	/* Feed data to the inner SHA256 operation. */
	SHA256_Update( &ctx->ictx, in, len );
}

/* Finish an HMAC-SHA256 operation. */
void
HMAC_SHA256_Final( unsigned char digest[32], HMAC_SHA256_CTX *ctx )
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final( ihash, &ctx->ictx );

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update( &ctx->octx, ihash, 32 );

	/* Finish the outer SHA256 operation. */
	SHA256_Final( digest, &ctx->octx );
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
