#ifdef __SSE2__
#include "yescrypt-simd.c"
#elif defined __ARM_NEON
#include "yescrypt-neon.c"
#else
#include "yescrypt-opt.c"
#endif
