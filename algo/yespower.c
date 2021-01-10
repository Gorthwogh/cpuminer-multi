#include "miner.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdlib.h>

#include "yespower-1.0.1/yespower.h"

// YESPOWER

yespower_params_t yespower_params;

//SHA256_CTX sha256_prehash_ctx;
__thread SHA256_CTX sha256_prehash_ctx;

int yespower_hash(const uint8_t *input, yespower_binary_t *output, uint32_t len, int thrid, int version)
{
	
	if (version == 1)
	{
		static const yespower_params_t v1 = { YESPOWER_1_0, 2048, 32, NULL, 0 };
		yespower_tls((const uint8_t*)input, len, &v1, (yespower_binary_t*)output, thrid);
	}
	if (version == 2)
	{
		static const yespower_params_t v2 = { YESPOWER_1_0, 4096, 16, NULL, 0 };
		yespower_tls((const uint8_t*)input, len, &v2, (yespower_binary_t*)output, thrid);
	}
	if (version == 3)
	{
		static const yespower_params_t v3 = { YESPOWER_1_0, 2048, 32, "CPUpower: The number of CPU working or available for proof-of-work mining", 73 };
		yespower_tls((const uint8_t*)input, len, &v3, (yespower_binary_t*)output, thrid);
	}
	if (version == 4)
	{
		static const yespower_params_t v4 = { YESPOWER_1_0, 2048, 32, (const uint8_t *)"UraniumX", 8 };
		yespower_tls((const uint8_t*)input, len, &v4, (yespower_binary_t*)output, thrid);
	}
	if (version == 5)
	{
		static const yespower_params_t v5 = { YESPOWER_1_0, 2048, 32, "LITBpower: The number of LITB working or available for proof-of-work mining", 73 };
		yespower_tls((const uint8_t*)input, len, &v5, (yespower_binary_t*)output, thrid);
	}
	if (version == 6)
	{
		static const yespower_params_t v6 = { YESPOWER_1_0, 2048, 32, "InterITC", 8 };
		yespower_tls((const uint8_t*)input, len, &v6, (yespower_binary_t*)output, thrid);
	}
	if (version == 7)
	{
		static const yespower_params_t v7 = { YESPOWER_1_0, 2048, 32, "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote", 74 };
		return yespower_tls((const uint8_t*)input, len, &v7, (yespower_binary_t*)output, thrid);
	}
	if (version == 8)
	{
		static const yespower_params_t v8 = { YESPOWER_1_0, 2048, 8, "Tidecoin: Post Quantum Security.", 32 };
		return yespower_tls((const uint8_t*)input, len, &v8, (yespower_binary_t*)output, thrid);
	}
	
	return 0;
	//return yespower_tls(input, len, &yespower_params,
	//	(yespower_binary_t*)output, thrid);
}


static int pretest(const uint32_t *hash, const uint32_t *target)
{
	return hash[7] < target[7];
}

/*
int scanhash_yespower(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, int version)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		yespower_hash((char*)endiandata, (char*)vhash, 80, thr_id, version);
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio(work, vhash);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return 1;
		}
		n++;
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}*/


int scanhash_yespower(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, int version)
{
	/*static const yespower_params_t params = {
		.version = YESPOWER_1_0,
		.N = 4096,
		.r = 16,
		.pers = NULL,
		.perslen = 0
	};*/

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	union {
		uint8_t u8[8];
		uint32_t u32[20];
	} data;
	union {
		yespower_binary_t yb;
		uint32_t u32[7];
	} hash;
	uint32_t n = pdata[19] - 1;
	const uint32_t Htarg = ptarget[7];
	int i;

	for (i = 0; i < 19; i++)
		be32enc(&data.u32[i], pdata[i]);

	// do sha256 prehash
	SHA256_Init(&sha256_prehash_ctx);
	SHA256_Update(&sha256_prehash_ctx, data.u32, 64);

	do {
		be32enc(&data.u32[19], ++n);

		//if (yespower_tls(data.u8, 80, &params, &hash.yb))
		//	abort();
		if (yespower_hash(data.u8, &hash.yb, 80, thr_id, version))
			abort();

		if (le32dec(&hash.u32[7]) <= Htarg) {
			for (i = 0; i < 7; i++)
				hash.u32[i] = le32dec(&hash.u32[i]);
			if (unlikely(fulltest(hash.u32, ptarget))) {
				*hashes_done = n - pdata[19] + 1;
				pdata[19] = n;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - pdata[19] + 1;
	pdata[19] = n;
	return 0;
}

// YESPOWER-B2B
/*
int yespower_b2b_hash(const char *input, char *output, uint32_t len, int thrid)
{
	return yespower_b2b_tls(input, len, &yespower_params, (yespower_binary_t*)output, thrid);
}

int scanhash_yespower_b2b(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) vhash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;
	const uint32_t last_nonce = max_nonce;
	//const int thr_id = mythr->id;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);
	endiandata[19] = n;

	// do sha256 prehash
	SHA256_Init(&sha256_prehash_ctx);
	SHA256_Update(&sha256_prehash_ctx, endiandata, 64);

	do {
		if (yespower_b2b_hash((char*)endiandata, (char*)vhash, 80, thr_id))
			if unlikely(fulltest(vhash, ptarget) && !opt_benchmark)
			{
				be32enc(pdata + 19, n);
				work_set_target_ratio(work, vhash);
			}
		endiandata[19] = ++n;
	} while (n < last_nonce && !work_restart[thr_id].restart);
	*hashes_done = n - first_nonce;
	pdata[19] = n;
	return 0;
}*/