#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"

static unsigned char ad[64];
static unsigned char msg[64];
static unsigned char ct[64 + CRYPTO_ABYTES];
static unsigned char dec[64];
static unsigned char nonce[CRYPTO_NPUBBYTES];
static unsigned char key[CRYPTO_KEYBYTES];

struct decrypt_result {
  int rc;
  unsigned long long dlen;
  int plaintext_ok;
  int output_buffer_unchanged;
};

static void init_inputs(void) {
  for (size_t i = 0; i < sizeof(ad); ++i) ad[i] = (unsigned char)(i & 0xffu);
  for (size_t i = 0; i < sizeof(msg); ++i)
    msg[i] = (unsigned char)((i * 7u) & 0xffu);
  for (size_t i = 0; i < sizeof(nonce); ++i)
    nonce[i] = (unsigned char)(0xa0u + i);
  for (size_t i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)(0x50u + i);
}

static int make_ciphertext(unsigned long long *clen) {
  return crypto_aead_encrypt(ct, clen, msg, sizeof(msg), ad, sizeof(ad), NULL,
                             nonce, key);
}

static struct decrypt_result decrypt_current(unsigned long long clen) {
  unsigned char before[sizeof(dec)];
  unsigned long long dlen = 0;
  memset(dec, 0xa5, sizeof(dec));
  memcpy(before, dec, sizeof(dec));

  int rc = crypto_aead_decrypt(dec, &dlen, NULL, ct, clen, ad, sizeof(ad),
                               nonce, key);
  struct decrypt_result r = {
      .rc = rc,
      .dlen = dlen,
      .plaintext_ok =
          rc == 0 && dlen == sizeof(msg) && memcmp(dec, msg, sizeof(msg)) == 0,
      .output_buffer_unchanged = memcmp(dec, before, sizeof(dec)) == 0,
  };
  return r;
}

static void print_decrypt_case(const char *name, int passed,
                               struct decrypt_result r,
                               const char *expected) {
  printf("%s,%s,%d,%llu,%d,%d,%s\n", name, passed ? "pass" : "fail", r.rc,
         r.dlen, r.plaintext_ok, r.output_buffer_unchanged, expected);
}

static void print_api_case(const char *name, int passed, int rc,
                           const char *expected) {
  printf("%s,%s,%d,n/a,n/a,n/a,%s\n", name, passed ? "pass" : "fail", rc,
         expected);
}

int main(void) {
  unsigned long long clen = 0;
  init_inputs();

  puts("case,result,api_rc,decrypted_len,plaintext_ok,output_buffer_unchanged,expected");
  if (make_ciphertext(&clen) != 0) {
    print_api_case("valid_decrypt", 0, -1, "valid ciphertext decrypts");
    return 1;
  }
  struct decrypt_result r = decrypt_current(clen);
  print_decrypt_case("valid_decrypt", r.plaintext_ok, r,
                     "valid ciphertext decrypts");

  ct[0] ^= 0x01u;
  r = decrypt_current(clen);
  print_decrypt_case("tampered_ciphertext_rejected", r.rc != 0, r,
                     "modified ciphertext must be rejected");
  ct[0] ^= 0x01u;

  ct[clen - 1] ^= 0x01u;
  r = decrypt_current(clen);
  print_decrypt_case("tampered_tag_rejected", r.rc != 0, r,
                     "modified tag must be rejected");
  ct[clen - 1] ^= 0x01u;

  ad[0] ^= 0x01u;
  r = decrypt_current(clen);
  print_decrypt_case("wrong_associated_data_rejected", r.rc != 0, r,
                     "wrong associated data must be rejected");
  ad[0] ^= 0x01u;

  nonce[0] ^= 0x01u;
  r = decrypt_current(clen);
  print_decrypt_case("wrong_nonce_rejected", r.rc != 0, r,
                     "wrong nonce must be rejected");
  nonce[0] ^= 0x01u;

  key[0] ^= 0x01u;
  r = decrypt_current(clen);
  print_decrypt_case("wrong_key_rejected", r.rc != 0, r,
                     "wrong key must be rejected");
  key[0] ^= 0x01u;

  if (make_ciphertext(&clen) != 0) return 1;
  msg[0] ^= 0x55u;
  unsigned long long clen2 = 0;
  unsigned char ct2[64 + CRYPTO_ABYTES];
  int reuse_rc =
      crypto_aead_encrypt(ct2, &clen2, msg, sizeof(msg), ad, sizeof(ad), NULL,
                          nonce, key);
  print_api_case("nonce_reuse_second_encrypt_succeeds", reuse_rc == 0,
                 reuse_rc,
                 "second encryption with same nonce/key succeeds; caller must enforce nonce uniqueness");

  return 0;
}
