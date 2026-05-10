#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "api.h"
#include "crypto_hash.h"

#define NUM_LENGTHS 7
#define NUM_TRIALS 7
#define MAX_LEN (1 << 15)
#define TARGET_BYTES (1 << 22)

static const unsigned long long mlens[NUM_LENGTHS] = {1, 8, 16, 32, 64, 1536,
                                                      16384};

static unsigned char msg[MAX_LEN];
static unsigned char out[CRYPTO_BYTES];

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_double(const void *a, const void *b) {
  double da = *(const double *)a;
  double db = *(const double *)b;
  if (da < db) return -1;
  if (da > db) return 1;
  return 0;
}

static void init_inputs(void) {
  for (size_t i = 0; i < sizeof(msg); ++i)
    msg[i] = (unsigned char)((i * 11u) & 0xffu);
}

static double time_hash(unsigned long long mlen, unsigned long long reps) {
  uint64_t start = now_ns();
  for (unsigned long long i = 0; i < reps; ++i) {
    if (crypto_hash(out, msg, mlen) != 0) return -1.0;
  }
  uint64_t stop = now_ns();
  return (double)(stop - start) / (double)(mlen * reps);
}

int main(void) {
  double vals[NUM_TRIALS];

  init_inputs();
  puts("message_len,operation,min_ns_per_byte,median_ns_per_byte,min_MBps,median_MBps");
  for (size_t i = 0; i < NUM_LENGTHS; ++i) {
    unsigned long long mlen = mlens[i];
    unsigned long long reps = TARGET_BYTES / mlen;
    if (reps < 1) reps = 1;

    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
      vals[trial] = time_hash(mlen, reps);
    }

    qsort(vals, NUM_TRIALS, sizeof(double), cmp_double);
    double min = vals[0];
    double med = vals[NUM_TRIALS / 2];

    printf("%llu,hash,%.3f,%.3f,%.2f,%.2f\n", mlen, min, med, 1000.0 / min,
           1000.0 / med);
  }
  return 0;
}
