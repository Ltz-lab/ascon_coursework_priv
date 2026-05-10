#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "crypto_aead.h"

#define NUM_LENGTHS 7
#define NUM_TRIALS 7
#define MAX_LEN (1 << 15)
#define TARGET_BYTES (1 << 22)

static const unsigned long long mlens[NUM_LENGTHS] = {1, 8, 16, 32, 64, 1536,
                                                      16384};

static unsigned char ad[MAX_LEN];
static unsigned char msg[MAX_LEN];
static unsigned char ct[MAX_LEN + CRYPTO_ABYTES];
static unsigned char dec[MAX_LEN];
static unsigned char nonce[CRYPTO_NPUBBYTES];
static unsigned char key[CRYPTO_KEYBYTES];

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
  for (size_t i = 0; i < sizeof(ad); ++i) ad[i] = (unsigned char)(i & 0xffu);
  for (size_t i = 0; i < sizeof(msg); ++i)
    msg[i] = (unsigned char)((i * 7u) & 0xffu);
  for (size_t i = 0; i < sizeof(nonce); ++i)
    nonce[i] = (unsigned char)(0xa0u + i);
  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)(0x50u + i);
}

static void set_nonce_counter(unsigned long long counter) {
  for (size_t j = 0; j < sizeof(nonce); ++j) {
    nonce[j] = (unsigned char)(0xa0u + j);
  }
  for (size_t j = 0; j < sizeof(nonce) && counter != 0; ++j) {
    nonce[j] = (unsigned char)(nonce[j] + (counter & 0xffu));
    counter >>= 8;
  }
}

static double time_encrypt(unsigned long long mlen, unsigned long long adlen,
                           unsigned long long reps) {
  unsigned long long clen = 0;
  uint64_t start = now_ns();
  for (unsigned long long i = 0; i < reps; ++i) {
    set_nonce_counter(i);
    if (crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce,
                            key) != 0) {
      return -1.0;
    }
  }
  uint64_t stop = now_ns();
  return (double)(stop - start) / (double)(mlen * reps);
}

static double time_decrypt(unsigned long long mlen, unsigned long long adlen,
                           unsigned long long reps) {
  unsigned long long clen = 0;
  unsigned long long dlen = 0;

  if (crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) !=
      0) {
    return -1.0;
  }

  uint64_t start = now_ns();
  for (unsigned long long i = 0; i < reps; ++i) {
    if (crypto_aead_decrypt(dec, &dlen, NULL, ct, clen, ad, adlen, nonce,
                            key) != 0) {
      return -1.0;
    }
  }
  uint64_t stop = now_ns();

  if (dlen != mlen || memcmp(dec, msg, mlen) != 0) return -1.0;
  return (double)(stop - start) / (double)(mlen * reps);
}

int main(void) {
  double enc[NUM_TRIALS];
  double decv[NUM_TRIALS];

  init_inputs();
  puts("message_len,operation,min_ns_per_byte,median_ns_per_byte,min_MBps,median_MBps");
  for (size_t i = 0; i < NUM_LENGTHS; ++i) {
    unsigned long long mlen = mlens[i];
    unsigned long long adlen = mlen < 64 ? mlen : 64;
    unsigned long long reps = TARGET_BYTES / mlen;
    if (reps < 1) reps = 1;

    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
      enc[trial] = time_encrypt(mlen, adlen, reps);
      decv[trial] = time_decrypt(mlen, adlen, reps);
    }

    qsort(enc, NUM_TRIALS, sizeof(double), cmp_double);
    qsort(decv, NUM_TRIALS, sizeof(double), cmp_double);

    double enc_min = enc[0];
    double enc_med = enc[NUM_TRIALS / 2];
    double dec_min = decv[0];
    double dec_med = decv[NUM_TRIALS / 2];

    printf("%llu,encrypt,%.3f,%.3f,%.2f,%.2f\n", mlen, enc_min, enc_med,
           1000.0 / enc_min, 1000.0 / enc_med);
    printf("%llu,decrypt,%.3f,%.3f,%.2f,%.2f\n", mlen, dec_min, dec_med,
           1000.0 / dec_min, 1000.0 / dec_med);
  }
  return 0;
}
