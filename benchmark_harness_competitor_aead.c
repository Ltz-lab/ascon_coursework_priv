#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_LENGTHS 7
#define NUM_TRIALS 7
#define MAX_LEN (1 << 15)
#define TARGET_BYTES (1 << 22)
#define TAG_LEN 16
#define NONCE_LEN 12

static const unsigned long long mlens[NUM_LENGTHS] = {1, 8, 16, 32, 64, 1536,
                                                      16384};

static unsigned char ad[MAX_LEN];
static unsigned char msg[MAX_LEN];
static unsigned char ct[MAX_LEN + TAG_LEN];
static unsigned char dec[MAX_LEN];
static unsigned char tag[TAG_LEN];
static unsigned char nonce[NONCE_LEN];
static unsigned char key[32];

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

static int encrypt_once(const EVP_CIPHER *cipher, unsigned long long mlen,
                        unsigned long long adlen) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int outlen = 0;
  int tmplen = 0;
  int ok = 0;

  if (ctx == NULL) goto out;
  if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto out;
  if (EVP_CIPHER_get_nid(cipher) == EVP_CIPHER_nid(EVP_aes_128_gcm())) {
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
      goto out;
  }
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
  if (adlen > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &outlen, ad, (int)adlen) != 1)
    goto out;
  if (EVP_EncryptUpdate(ctx, ct, &outlen, msg, (int)mlen) != 1) goto out;
  if (EVP_EncryptFinal_ex(ctx, ct + outlen, &tmplen) != 1) goto out;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1)
    goto out;
  ok = 1;

out:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static int decrypt_once(const EVP_CIPHER *cipher, unsigned long long mlen,
                        unsigned long long adlen) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int outlen = 0;
  int tmplen = 0;
  int ok = 0;

  if (ctx == NULL) goto out;
  if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto out;
  if (EVP_CIPHER_get_nid(cipher) == EVP_CIPHER_nid(EVP_aes_128_gcm())) {
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
      goto out;
  }
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;
  if (adlen > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &outlen, ad, (int)adlen) != 1)
    goto out;
  if (EVP_DecryptUpdate(ctx, dec, &outlen, ct, (int)mlen) != 1) goto out;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) != 1)
    goto out;
  if (EVP_DecryptFinal_ex(ctx, dec + outlen, &tmplen) != 1) goto out;
  if (memcmp(dec, msg, mlen) != 0) goto out;
  ok = 1;

out:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

static double time_encrypt(const EVP_CIPHER *cipher, unsigned long long mlen,
                           unsigned long long adlen,
                           unsigned long long reps) {
  uint64_t start = now_ns();
  for (unsigned long long i = 0; i < reps; ++i) {
    set_nonce_counter(i);
    if (!encrypt_once(cipher, mlen, adlen)) return -1.0;
  }
  uint64_t stop = now_ns();
  return (double)(stop - start) / (double)(mlen * reps);
}

static double time_decrypt(const EVP_CIPHER *cipher, unsigned long long mlen,
                           unsigned long long adlen,
                           unsigned long long reps) {
  nonce[0] = 0xa0u;
  if (!encrypt_once(cipher, mlen, adlen)) return -1.0;

  uint64_t start = now_ns();
  for (unsigned long long i = 0; i < reps; ++i) {
    if (!decrypt_once(cipher, mlen, adlen)) return -1.0;
  }
  uint64_t stop = now_ns();
  return (double)(stop - start) / (double)(mlen * reps);
}

static void run_algorithm(const char *name, const EVP_CIPHER *cipher) {
  double enc[NUM_TRIALS];
  double decv[NUM_TRIALS];

  for (size_t i = 0; i < NUM_LENGTHS; ++i) {
    unsigned long long mlen = mlens[i];
    unsigned long long adlen = mlen < 64 ? mlen : 64;
    unsigned long long reps = TARGET_BYTES / mlen;
    if (reps < 1) reps = 1;

    for (size_t trial = 0; trial < NUM_TRIALS; ++trial) {
      enc[trial] = time_encrypt(cipher, mlen, adlen, reps);
      decv[trial] = time_decrypt(cipher, mlen, adlen, reps);
    }

    qsort(enc, NUM_TRIALS, sizeof(double), cmp_double);
    qsort(decv, NUM_TRIALS, sizeof(double), cmp_double);

    printf("%s,%llu,encrypt,%.3f,%.3f,%.2f,%.2f\n", name, mlen, enc[0],
           enc[NUM_TRIALS / 2], 1000.0 / enc[0], 1000.0 / enc[NUM_TRIALS / 2]);
    printf("%s,%llu,decrypt,%.3f,%.3f,%.2f,%.2f\n", name, mlen, decv[0],
           decv[NUM_TRIALS / 2], 1000.0 / decv[0],
           1000.0 / decv[NUM_TRIALS / 2]);
  }
}

int main(void) {
  init_inputs();
  puts("algorithm,message_len,operation,min_ns_per_byte,median_ns_per_byte,min_MBps,median_MBps");
  run_algorithm("AES-128-GCM_OpenSSL", EVP_aes_128_gcm());
  run_algorithm("ChaCha20-Poly1305_OpenSSL", EVP_chacha20_poly1305());
  return 0;
}
