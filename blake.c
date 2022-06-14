#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define toRead 64

typedef struct
{
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[64];
} state256;

#define U8TO32_BIG(p)                                        \
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | \
   ((uint32_t)((p)[2]) << 8) | ((uint32_t)((p)[3])))

#define U32TO8_BIG(p, v)         \
  (p)[0] = (uint8_t)((v) >> 24); \
  (p)[1] = (uint8_t)((v) >> 16); \
  (p)[2] = (uint8_t)((v) >> 8);  \
  (p)[3] = (uint8_t)((v));

const uint8_t sigma[][16] =
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}};

const uint32_t constant[16] =
    {
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917};

static const uint8_t padding[129] =
    {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// initialization of states
void initialize(state256 *S)
{
  S->h[0] = 0x6a09e667;
  S->h[1] = 0xbb67ae85;
  S->h[2] = 0x3c6ef372;
  S->h[3] = 0xa54ff53a;
  S->h[4] = 0x510e527f;
  S->h[5] = 0x9b05688c;
  S->h[6] = 0x1f83d9ab;
  S->h[7] = 0x5be0cd19;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}

// core function
void core_function(state256 *S, const uint8_t *block)
{
  // states and message block - 32-bit each
  uint32_t v[16], m[16], i;
  // Shift
#define ROT(x, n) (((x) << (32 - n)) | ((x) >> (n)))
// core function
#define G(a, b, c, d, e)                                       \
  v[a] += (m[sigma[i][e]] ^ constant[sigma[i][e + 1]]) + v[b]; \
  v[d] = ROT(v[d] ^ v[a], 16);                                 \
  v[c] += v[d];                                                \
  v[b] = ROT(v[b] ^ v[c], 12);                                 \
  v[a] += (m[sigma[i][e + 1]] ^ constant[sigma[i][e]]) + v[b]; \
  v[d] = ROT(v[d] ^ v[a], 8);                                  \
  v[c] += v[d];                                                \
  v[b] = ROT(v[b] ^ v[c], 7);

  // convert take 8-bit blocks into 32-bit and big-endian format
  for (i = 0; i < 16; ++i)
    m[i] = U8TO32_BIG(block + i * 4);

  // initial states
  for (i = 0; i < 8; ++i)
    v[i] = S->h[i];

  // rest states
  v[8] = S->s[0] ^ constant[0];
  v[9] = S->s[1] ^ constant[1];
  v[10] = S->s[2] ^ constant[2];
  v[11] = S->s[3] ^ constant[3];
  v[12] = constant[4];
  v[13] = constant[5];
  v[14] = constant[6];
  v[15] = constant[7];

  // XOR with t is not required when the block has padding-bits
  if (!S->nullt)
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  // run the core function 14 times for blake 256-hash
  for (i = 0; i < 14; ++i)
  {
    // column step
    G(0, 4, 8, 12, 0);
    G(1, 5, 9, 13, 2);
    G(2, 6, 10, 14, 4);
    G(3, 7, 11, 15, 6);
    // diagonal step
    G(0, 5, 10, 15, 8);
    G(1, 6, 11, 12, 10);
    G(2, 7, 8, 13, 12);
    G(3, 4, 9, 14, 14);
  }

  // generating the hash with all updated states
  for (i = 0; i < 16; ++i)
    S->h[i % 8] ^= v[i];

  for (i = 0; i < 8; ++i)
    S->h[i] ^= S->s[i % 4];
}

// update the length of the block left and to fill
void add_padding(state256 *S, const uint8_t *in, uint64_t inlen)
{
  // space left
  int left = S->buflen;
  // printf("\nleft = %d\n", left);

  // space left
  int fill = 64 - left;
  // printf("fill = %d\n", fill);

  // data left is not null and length to be left is greater than available
  if (left && (inlen >= fill))
  {
    // printf("1st condition\n");
    memcpy((void *)(S->buf + left), (void *)in, fill);
    S->t[0] += 512;

    // printf("S->t[0] = %d\n", S->t[0]);

    if (S->t[0] == 0)
      S->t[1]++;

    // for (int j = 0; j < 64; j++)
    // {
    //   printf("S->buf[%d] = %d\n", j, S->buf[j]);
    // }
    // printf("\n");

    core_function(S, S->buf);
    in += fill;
    inlen -= fill;

    // printf("inlen = %d\n", inlen);
    left = 0;
  }

  // if meesage is greater than length of 64
  while (inlen >= 64)
  {
    // printf("Condition 2\n");
    S->t[0] += 512;

    if (S->t[0] == 0)
      S->t[1]++;

    core_function(S, in);
    in += 64;
    inlen -= 64;
  }

  // if the message when block is empty
  if (inlen > 0)
  {
    // printf("Condition 3\n");
    memcpy((void *)(S->buf + left), (void *)in, (size_t)inlen);
    S->buflen = left + (int)inlen;
    // printf("inlen = %d\n", inlen);
    // printf("buflen = %d\n", S->buflen);
    // for (int j = 0; j < 64; j++)
    // {
    //   printf("S->buf[%d] = %d\n", j, S->buf[j]);
    // }
  }
  else
    S->buflen = 0;
}

// finalize blake 256
void final(state256 *S, uint8_t *out)
{
  uint8_t msglen[8], zo = 0x01, oo = 0x81;
  uint32_t lo = S->t[0] + (S->buflen << 3), hi = S->t[1];
  // printf("lo = %d\n", lo);
  // printf("hi = %d\n", hi);

  // space fill is less than greater than 2^32 bits
  if (lo < (S->buflen << 3))
    hi++;

  // get the message in 8-bit big-endian format
  U32TO8_BIG(msglen + 0, hi);
  U32TO8_BIG(msglen + 4, lo);

  // print the message
  // for (int i = 0; i < 8; i++)
  // {
  //   printf("msglen[%d] = %d\n", i, msglen[i]);
  // }

  // only one byte for padding is fill
  if (S->buflen == 55)
  {
    S->t[0] -= 8;
    add_padding(S, &oo, 1);
  }
  else
  {
    // atleast 2 bytes are available for padding
    if (S->buflen < 55)
    {
      // if buflen is 0
      if (!S->buflen)
        S->nullt = 1;

      S->t[0] -= 440 - (S->buflen << 3);
      // printf("S[t[0]] = %d\n", S->t[0]);
      // printf("buflen = %d\n", S->buflen);
      add_padding(S, padding, 55 - S->buflen);
    }
    else
    {
      S->t[0] -= 512 - (S->buflen << 3);
      add_padding(S, padding, 64 - S->buflen);
      S->t[0] -= 440;
      add_padding(S, padding + 1, 55);
      S->nullt = 1;
    }

    // add one after padding 0 bits
    add_padding(S, &zo, 1);
    S->t[0] -= 8;
    // printf("S->t[0] = %d\n", S->t[0]);
  }

  S->t[0] -= 64;
  // printf("S->t[0] = %d\n", S->t[0]);
  // for (int j = 0; j < 64; j++)
  // {
  //   printf("S->buf[%d] = %d\n", j, S->buf[j]);
  // }

  add_padding(S, msglen, 8);

  // converting the 32-bit blocks into 8-bit hash output in big-endian
  U32TO8_BIG(out + 0, S->h[0]);
  U32TO8_BIG(out + 4, S->h[1]);
  U32TO8_BIG(out + 8, S->h[2]);
  U32TO8_BIG(out + 12, S->h[3]);
  U32TO8_BIG(out + 16, S->h[4]);
  U32TO8_BIG(out + 20, S->h[5]);
  U32TO8_BIG(out + 24, S->h[6]);
  U32TO8_BIG(out + 28, S->h[7]);
}

void blake_256(uint8_t *out, const uint8_t *in, uint64_t inlen)
{
  state256 S;
  initialize(&S);
  add_padding(&S, in, inlen);
  final(&S, out);
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    // take the message
    char *in = "ajay";

    // length of message
    size_t msg_len = strlen(in);

    // output array - this will contain the final hash
    uint8_t out[32];

    // invoke the hashing function
    blake_256(out, in, msg_len);

    // print the hash in hexadecimal form
    printf("BLAKE256 HASH for \"%s\" is: ", in);
    for (int i = 0; i < 32; ++i)
    {
      printf("%02x", out[i]);
    }
  }
  else
  {
    FILE *fp;
    int i, j, bytesread;
    uint8_t in[toRead], out[32];
    state256 S;

    // read until all the files are processed
    for (i = 1; i < argc; ++i)
    {
      fp = fopen(*(argv + i), "r");
      if (fp == NULL)
      {
        printf("Error: unable to open %s\n", *(argv + i));
        return 1;
      }

      // initialize a state with constants
      initialize(&S);

      // read the file given as input
      while (1)
      {
        // read in 64-bit blocks
        bytesread = fread(in, 1, toRead, fp);

        // if somethings is read update it else break
        if (bytesread)
          add_padding(&S, in, bytesread);
        else
          break;
      }

      // generate the hash digest
      final(&S, out);

      // print the hash digest
      printf("BLAKE-256 HASH for \"%s\" is: ", *(argv + i));
      for (j = 0; j < 32; ++j)
      {
        printf("%02x", out[j]);
      }

      // close the file pointer
      fclose(fp);
    }
  }
  return 0;
}