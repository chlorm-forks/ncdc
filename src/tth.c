/* ncdc - NCurses Direct Connect client

  Copyright (c) 2011-2016 Yoran Heling

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/


#include "ncdc.h"
#include "tth.h"



/* An implementation of Tiger Hash Function based on the article by
 * Ross Anderson and Eli Biham "Tiger: A Fast New Hash Function".
 *
 * This implementation is based on librhash/tiger.c, part of the RHash
 * utility, with modifications for better integration into ncdc.
 * RHash homepage: http://rhash.anz.ru/
 * RHash on sourceforge: http://sourceforge.net/projects/rhash/
 *
 * The following copyright statement was included in the original file:
 *
 * Implementation written by Alexei Kravchenko.
 *
 * Copyleft:
 * I hereby release this code into the public domain. This applies worldwide.
 * I grant any entity the right to use this work for ANY PURPOSE,
 * without any conditions, unless such conditions are required by law.
 */


#if INTERFACE

#define tiger_block_size 64

struct tiger_ctx_t {
  guint64 hash[3]; /* algorithm 192-bit state */
  char message[tiger_block_size]; /* 512-bit buffer for leftovers */
  guint64 length;  /* processed message length */
};

#endif


#if defined(_LP64) || defined(__LP64__) || defined(__x86_64) || \
     defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
# define CPU_X64
#endif

#define IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))

// S-boxes, defined below
static guint64 tiger_sboxes[4][256];
#define t1 tiger_sboxes[0]
#define t2 tiger_sboxes[1]
#define t3 tiger_sboxes[2]
#define t4 tiger_sboxes[3]


void tiger_init(tiger_ctx_t *ctx) {
  ctx->length = 0;

  /* initialize algorithm state */
  ctx->hash[0] = G_GUINT64_CONSTANT(0x0123456789ABCDEF);
  ctx->hash[1] = G_GUINT64_CONSTANT(0xFEDCBA9876543210);
  ctx->hash[2] = G_GUINT64_CONSTANT(0xF096A5B4C3B2E187);
}


#ifdef CPU_X64 /* for x86-64 */
#define round(a,b,c,x,mul) \
  c ^= x; \
  a -= t1[(guint8)(c)] ^ \
       t2[(guint8)((c) >> (2*8))] ^ \
       t3[(guint8)((c) >> (4*8))] ^ \
       t4[(guint8)((c) >> (6*8))] ; \
  b += t4[(guint8)((c) >> (1*8))] ^ \
       t3[(guint8)((c) >> (3*8))] ^ \
       t2[(guint8)((c) >> (5*8))] ^ \
       t1[(guint8)((c) >> (7*8))]; \
  b *= mul;

#else /* for IA32 */

#define round(a,b,c,x,mul) \
  c ^= x; \
  a -= t1[(guint8)(c)] ^ \
       t2[(guint8)(((guint32)(c)) >> (2*8))] ^ \
       t3[(guint8)((c) >> (4*8))] ^ \
       t4[(guint8)(((guint32)((c) >> (4*8))) >> (2*8))] ; \
  b += t4[(guint8)(((guint32)(c)) >> (1*8))] ^ \
       t3[(guint8)(((guint32)(c)) >> (3*8))] ^ \
       t2[(guint8)(((guint32)((c) >> (4*8))) >> (1*8))] ^ \
       t1[(guint8)(((guint32)((c) >> (4*8))) >> (3*8))]; \
  b *= mul;
#endif /* CPU_X64 */

#define pass(a,b,c,mul) \
  round(a,b,c,x0,mul) \
  round(b,c,a,x1,mul) \
  round(c,a,b,x2,mul) \
  round(a,b,c,x3,mul) \
  round(b,c,a,x4,mul) \
  round(c,a,b,x5,mul) \
  round(a,b,c,x6,mul) \
  round(b,c,a,x7,mul)

#define key_schedule { \
  x0 -= x7 ^ G_GUINT64_CONSTANT(0xA5A5A5A5A5A5A5A5); \
  x1 ^= x0; \
  x2 += x1; \
  x3 -= x2 ^ ((~x1)<<19); \
  x4 ^= x3; \
  x5 += x4; \
  x6 -= x5 ^ ((~x4)>>23); \
  x7 ^= x6; \
  x0 += x7; \
  x1 -= x0 ^ ((~x7)<<19); \
  x2 ^= x1; \
  x3 += x2; \
  x4 -= x3 ^ ((~x2)>>23); \
  x5 ^= x4; \
  x6 += x5; \
  x7 -= x6 ^ G_GUINT64_CONSTANT(0x0123456789ABCDEF); \
}


static void tiger_process_block(guint64 state[3], guint64 *block) {
  /* Optimized for GCC IA32.
     The order of declarations is important for compiler. */
  guint64 a, b, c;
  guint64 x0, x1, x2, x3, x4, x5, x6, x7;
#ifndef CPU_X64
  guint64 tmp;
  char i;
#endif

  x0=GUINT64_FROM_LE(block[0]); x1=GUINT64_FROM_LE(block[1]);
  x2=GUINT64_FROM_LE(block[2]); x3=GUINT64_FROM_LE(block[3]);
  x4=GUINT64_FROM_LE(block[4]); x5=GUINT64_FROM_LE(block[5]);
  x6=GUINT64_FROM_LE(block[6]); x7=GUINT64_FROM_LE(block[7]);

  a = state[0];
  b = state[1];
  c = state[2];

  /* passes and key shedules */
#ifndef CPU_X64
  for(i=0; i<3; i++) {
    if(i != 0)
      key_schedule;
    pass(a, b, c, (i==0 ? 5 : i==1 ? 7 : 9));
    tmp=a;
    a=c;
    c=b;
    b=tmp;
  }
#else
  pass(a, b, c, 5);
  key_schedule;
  pass(c, a, b, 7);
  key_schedule;
  pass(b, c, a, 9);
#endif

  /* feedforward operation */
  state[0] = a ^ state[0];
  state[1] = b - state[1];
  state[2] = c + state[2];
}


void tiger_update(tiger_ctx_t *ctx, const char *msg, size_t size) {
  size_t index = (size_t)ctx->length & 63;
  size_t left;
  ctx->length += size;

  /* Try to fill partial block */
  if(index) {
    left = tiger_block_size - index;
    if(size < left) {
      memcpy(ctx->message + index, msg, size);
      return;
    } else {
      memcpy(ctx->message + index, msg, left);
      tiger_process_block(ctx->hash, (guint64 *)ctx->message);
      msg += left;
      size -= left;
    }
  }
  while(size >= tiger_block_size) {
    if(IS_ALIGNED_64(msg)) {
      /* the most common case is processing of an already aligned message
         without copying it */
      tiger_process_block(ctx->hash, (guint64 *)msg);
    } else {
      memcpy(ctx->message, msg, tiger_block_size);
      tiger_process_block(ctx->hash, (guint64 *)ctx->message);
    }

    msg += tiger_block_size;
    size -= tiger_block_size;
  }
  if(size) {
    /* save leftovers */
    memcpy(ctx->message, msg, size);
  }
}


void tiger_final(tiger_ctx_t *ctx, char result[24]) {
  unsigned index = (unsigned)ctx->length & 63;
  guint64 *msg64 = (guint64 *)ctx->message;

  /* pad message and run for last block */

  /* append the byte 0x01 to the message */
  ctx->message[index++] = 0x01;

  /* if no room left in the message to store 64-bit message length */
  if(index > 56) {
    /* then fill the rest with zeros and process it */
    while(index < 64)
      ctx->message[index++] = 0;
    tiger_process_block(ctx->hash, msg64);
    index = 0;
  }
  while(index < 56)
    ctx->message[index++] = 0;
  msg64[7] = GUINT64_FROM_LE(ctx->length << 3);
  tiger_process_block(ctx->hash, msg64);

  /* save result hash */
  guint64 *res = (guint64 *)result;
  res[0] = GINT64_TO_LE(ctx->hash[0]);
  res[1] = GINT64_TO_LE(ctx->hash[1]);
  res[2] = GINT64_TO_LE(ctx->hash[2]);
}







/* This TTH implementation was written from scratch, and is designed to behave
 * similar to MerkleTree.h in DC++. The actual code has some inspiration from
 * both the DC++ and RHash implementations. (See the note on the tiger
 * implementation above for information about RHash) */


#if INTERFACE

struct tth_ctx_t {
  tiger_ctx_t tiger;
  int leafnum; // There can be 2^29 leafs. Fits in an integer.
  int gotfirst;
  // Stack used to calculate the hash.
  //  Max. size = 2^29 * 1024 = 512 GiB
  // When the stack starts with a leaf node, the position in the stack
  // determines the data size the hash represents:
  //   size = tth_base_block << pos
  // (pos being the index from 0)
  char stack[29][24];
};


// Calculate the number of blocks when the filesize and blocksize are known.
// = max(1, ceil(fs/bs))
#define tth_num_blocks(fs, bs) MAX(((fs)+(bs)-1)/(bs), 1)

#endif


#define tth_base_block 1024


#define tth_new_leaf(ctx) do {\
    tiger_init(&((ctx)->tiger));\
    tiger_update(&((ctx)->tiger), "\0", 1);\
  } while(0)


#define tth_combine(left, right, res) do {\
    tiger_ctx_t x;\
    tiger_init(&x);\
    tiger_update(&x, "\1", 1);\
    tiger_update(&x, left, 24);\
    tiger_update(&x, right, 24);\
    tiger_final(&x, res);\
  } while(0)


void tth_init(tth_ctx_t *ctx) {
  tth_new_leaf(ctx);
  ctx->leafnum = ctx->gotfirst = 0;
}


void tth_update_leaf(tth_ctx_t *ctx, const char *leaf) {
  int pos = 0;
  char tmp[24];
  int it;
  memcpy(tmp, leaf, 24);
  // This trick uses the leaf number to determine when it needs to combine
  // with a previous hash (idea borrowed from RHash)
  for(it=1; it & ctx->leafnum; it <<= 1) {
    tth_combine(ctx->stack[pos], tmp, tmp);
    pos++;
  }
  memcpy(ctx->stack[pos], tmp, 24);
  ctx->leafnum++;
  ctx->gotfirst = 1;
}


void tth_update(tth_ctx_t *ctx, const char *msg, size_t len) {
  char leaf[24];
  int left;
  if(len > 0)
    ctx->gotfirst = 1;
  while(len > 0) {
    left = MIN(tth_base_block - (ctx->tiger.length-1), len);
    tiger_update(&ctx->tiger, msg, left);
    len -= left;
    msg += left;
    g_assert(ctx->tiger.length-1 <= tth_base_block);
    // we've got a new base leaf
    if(ctx->tiger.length-1 == tth_base_block) {
      tiger_final(&ctx->tiger, leaf);
      tth_update_leaf(ctx, leaf);
      tth_new_leaf(ctx);
    }
  }
  g_assert(len == 0);
}


// combine everything on the stack to produce the last hash (based on RHash code)
static void tth_stack_final(tth_ctx_t *ctx, char *result) {
  guint64 it = 1;
  int pos = 0;
  char *last;
  for(it=1; it<ctx->leafnum && (it&ctx->leafnum)==0; it<<=1)
    pos++;
  last = ctx->stack[pos];
  for(it<<=1; it <= ctx->leafnum; it<<=1) {
    pos++;
    if(it & ctx->leafnum) {
      tth_combine(ctx->stack[pos], last, result);
      last = result;
    }
  }
  if(last != result)
    memcpy(result, last, 24);
}


void tth_final(tth_ctx_t *ctx, char *result) {
  // finish up last leaf
  if(!ctx->gotfirst || ctx->tiger.length > 1) {
    tiger_final(&ctx->tiger, result);
    tth_update_leaf(ctx, result);
  }

  // calculate final hash
  tth_stack_final(ctx, result);
}



// Calculate the root from a list of leaf/intermetiate hashes. All hashes must
// be at the same level.
void tth_root(char *blocks, int num, char *result) {
  tth_ctx_t t;
  tth_init(&t);
  int i;
  for(i=0; i<num; i++)
    tth_update_leaf(&t, blocks+(24*i));
  tth_final(&t, result);
}


// Calculate the blocksize when the filesize and number of blocks are known.
// To get the block size at a particular level, call with blocks = 1<<(level-1).
guint64 tth_blocksize(guint64 fs, int blocks) {
  guint64 r = tth_base_block;
  while((r * blocks) < fs)
    r <<= 1;
  return r;
}





/* And finally, the S-boxes used by the tiger function. */

#define _U G_GUINT64_CONSTANT

static guint64 tiger_sboxes[4][256] = {
  {
    _U(0x02AAB17CF7E90C5E), _U(0xAC424B03E243A8EC), _U(0x72CD5BE30DD5FCD3), _U(0x6D019B93F6F97F3A),
    _U(0xCD9978FFD21F9193), _U(0x7573A1C9708029E2), _U(0xB164326B922A83C3), _U(0x46883EEE04915870),
    _U(0xEAACE3057103ECE6), _U(0xC54169B808A3535C), _U(0x4CE754918DDEC47C), _U(0x0AA2F4DFDC0DF40C),
    _U(0x10B76F18A74DBEFA), _U(0xC6CCB6235AD1AB6A), _U(0x13726121572FE2FF), _U(0x1A488C6F199D921E),
    _U(0x4BC9F9F4DA0007CA), _U(0x26F5E6F6E85241C7), _U(0x859079DBEA5947B6), _U(0x4F1885C5C99E8C92),
    _U(0xD78E761EA96F864B), _U(0x8E36428C52B5C17D), _U(0x69CF6827373063C1), _U(0xB607C93D9BB4C56E),
    _U(0x7D820E760E76B5EA), _U(0x645C9CC6F07FDC42), _U(0xBF38A078243342E0), _U(0x5F6B343C9D2E7D04),
    _U(0xF2C28AEB600B0EC6), _U(0x6C0ED85F7254BCAC), _U(0x71592281A4DB4FE5), _U(0x1967FA69CE0FED9F),
    _U(0xFD5293F8B96545DB), _U(0xC879E9D7F2A7600B), _U(0x860248920193194E), _U(0xA4F9533B2D9CC0B3),
    _U(0x9053836C15957613), _U(0xDB6DCF8AFC357BF1), _U(0x18BEEA7A7A370F57), _U(0x037117CA50B99066),
    _U(0x6AB30A9774424A35), _U(0xF4E92F02E325249B), _U(0x7739DB07061CCAE1), _U(0xD8F3B49CECA42A05),
    _U(0xBD56BE3F51382F73), _U(0x45FAED5843B0BB28), _U(0x1C813D5C11BF1F83), _U(0x8AF0E4B6D75FA169),
    _U(0x33EE18A487AD9999), _U(0x3C26E8EAB1C94410), _U(0xB510102BC0A822F9), _U(0x141EEF310CE6123B),
    _U(0xFC65B90059DDB154), _U(0xE0158640C5E0E607), _U(0x884E079826C3A3CF), _U(0x930D0D9523C535FD),
    _U(0x35638D754E9A2B00), _U(0x4085FCCF40469DD5), _U(0xC4B17AD28BE23A4C), _U(0xCAB2F0FC6A3E6A2E),
    _U(0x2860971A6B943FCD), _U(0x3DDE6EE212E30446), _U(0x6222F32AE01765AE), _U(0x5D550BB5478308FE),
    _U(0xA9EFA98DA0EDA22A), _U(0xC351A71686C40DA7), _U(0x1105586D9C867C84), _U(0xDCFFEE85FDA22853),
    _U(0xCCFBD0262C5EEF76), _U(0xBAF294CB8990D201), _U(0xE69464F52AFAD975), _U(0x94B013AFDF133E14),
    _U(0x06A7D1A32823C958), _U(0x6F95FE5130F61119), _U(0xD92AB34E462C06C0), _U(0xED7BDE33887C71D2),
    _U(0x79746D6E6518393E), _U(0x5BA419385D713329), _U(0x7C1BA6B948A97564), _U(0x31987C197BFDAC67),
    _U(0xDE6C23C44B053D02), _U(0x581C49FED002D64D), _U(0xDD474D6338261571), _U(0xAA4546C3E473D062),
    _U(0x928FCE349455F860), _U(0x48161BBACAAB94D9), _U(0x63912430770E6F68), _U(0x6EC8A5E602C6641C),
    _U(0x87282515337DDD2B), _U(0x2CDA6B42034B701B), _U(0xB03D37C181CB096D), _U(0xE108438266C71C6F),
    _U(0x2B3180C7EB51B255), _U(0xDF92B82F96C08BBC), _U(0x5C68C8C0A632F3BA), _U(0x5504CC861C3D0556),
    _U(0xABBFA4E55FB26B8F), _U(0x41848B0AB3BACEB4), _U(0xB334A273AA445D32), _U(0xBCA696F0A85AD881),
    _U(0x24F6EC65B528D56C), _U(0x0CE1512E90F4524A), _U(0x4E9DD79D5506D35A), _U(0x258905FAC6CE9779),
    _U(0x2019295B3E109B33), _U(0xF8A9478B73A054CC), _U(0x2924F2F934417EB0), _U(0x3993357D536D1BC4),
    _U(0x38A81AC21DB6FF8B), _U(0x47C4FBF17D6016BF), _U(0x1E0FAADD7667E3F5), _U(0x7ABCFF62938BEB96),
    _U(0xA78DAD948FC179C9), _U(0x8F1F98B72911E50D), _U(0x61E48EAE27121A91), _U(0x4D62F7AD31859808),
    _U(0xECEBA345EF5CEAEB), _U(0xF5CEB25EBC9684CE), _U(0xF633E20CB7F76221), _U(0xA32CDF06AB8293E4),
    _U(0x985A202CA5EE2CA4), _U(0xCF0B8447CC8A8FB1), _U(0x9F765244979859A3), _U(0xA8D516B1A1240017),
    _U(0x0BD7BA3EBB5DC726), _U(0xE54BCA55B86ADB39), _U(0x1D7A3AFD6C478063), _U(0x519EC608E7669EDD),
    _U(0x0E5715A2D149AA23), _U(0x177D4571848FF194), _U(0xEEB55F3241014C22), _U(0x0F5E5CA13A6E2EC2),
    _U(0x8029927B75F5C361), _U(0xAD139FABC3D6E436), _U(0x0D5DF1A94CCF402F), _U(0x3E8BD948BEA5DFC8),
    _U(0xA5A0D357BD3FF77E), _U(0xA2D12E251F74F645), _U(0x66FD9E525E81A082), _U(0x2E0C90CE7F687A49),
    _U(0xC2E8BCBEBA973BC5), _U(0x000001BCE509745F), _U(0x423777BBE6DAB3D6), _U(0xD1661C7EAEF06EB5),
    _U(0xA1781F354DAACFD8), _U(0x2D11284A2B16AFFC), _U(0xF1FC4F67FA891D1F), _U(0x73ECC25DCB920ADA),
    _U(0xAE610C22C2A12651), _U(0x96E0A810D356B78A), _U(0x5A9A381F2FE7870F), _U(0xD5AD62EDE94E5530),
    _U(0xD225E5E8368D1427), _U(0x65977B70C7AF4631), _U(0x99F889B2DE39D74F), _U(0x233F30BF54E1D143),
    _U(0x9A9675D3D9A63C97), _U(0x5470554FF334F9A8), _U(0x166ACB744A4F5688), _U(0x70C74CAAB2E4AEAD),
    _U(0xF0D091646F294D12), _U(0x57B82A89684031D1), _U(0xEFD95A5A61BE0B6B), _U(0x2FBD12E969F2F29A),
    _U(0x9BD37013FEFF9FE8), _U(0x3F9B0404D6085A06), _U(0x4940C1F3166CFE15), _U(0x09542C4DCDF3DEFB),
    _U(0xB4C5218385CD5CE3), _U(0xC935B7DC4462A641), _U(0x3417F8A68ED3B63F), _U(0xB80959295B215B40),
    _U(0xF99CDAEF3B8C8572), _U(0x018C0614F8FCB95D), _U(0x1B14ACCD1A3ACDF3), _U(0x84D471F200BB732D),
    _U(0xC1A3110E95E8DA16), _U(0x430A7220BF1A82B8), _U(0xB77E090D39DF210E), _U(0x5EF4BD9F3CD05E9D),
    _U(0x9D4FF6DA7E57A444), _U(0xDA1D60E183D4A5F8), _U(0xB287C38417998E47), _U(0xFE3EDC121BB31886),
    _U(0xC7FE3CCC980CCBEF), _U(0xE46FB590189BFD03), _U(0x3732FD469A4C57DC), _U(0x7EF700A07CF1AD65),
    _U(0x59C64468A31D8859), _U(0x762FB0B4D45B61F6), _U(0x155BAED099047718), _U(0x68755E4C3D50BAA6),
    _U(0xE9214E7F22D8B4DF), _U(0x2ADDBF532EAC95F4), _U(0x32AE3909B4BD0109), _U(0x834DF537B08E3450),
    _U(0xFA209DA84220728D), _U(0x9E691D9B9EFE23F7), _U(0x0446D288C4AE8D7F), _U(0x7B4CC524E169785B),
    _U(0x21D87F0135CA1385), _U(0xCEBB400F137B8AA5), _U(0x272E2B66580796BE), _U(0x3612264125C2B0DE),
    _U(0x057702BDAD1EFBB2), _U(0xD4BABB8EACF84BE9), _U(0x91583139641BC67B), _U(0x8BDC2DE08036E024),
    _U(0x603C8156F49F68ED), _U(0xF7D236F7DBEF5111), _U(0x9727C4598AD21E80), _U(0xA08A0896670A5FD7),
    _U(0xCB4A8F4309EBA9CB), _U(0x81AF564B0F7036A1), _U(0xC0B99AA778199ABD), _U(0x959F1EC83FC8E952),
    _U(0x8C505077794A81B9), _U(0x3ACAAF8F056338F0), _U(0x07B43F50627A6778), _U(0x4A44AB49F5ECCC77),
    _U(0x3BC3D6E4B679EE98), _U(0x9CC0D4D1CF14108C), _U(0x4406C00B206BC8A0), _U(0x82A18854C8D72D89),
    _U(0x67E366B35C3C432C), _U(0xB923DD61102B37F2), _U(0x56AB2779D884271D), _U(0xBE83E1B0FF1525AF),
    _U(0xFB7C65D4217E49A9), _U(0x6BDBE0E76D48E7D4), _U(0x08DF828745D9179E), _U(0x22EA6A9ADD53BD34),
    _U(0xE36E141C5622200A), _U(0x7F805D1B8CB750EE), _U(0xAFE5C7A59F58E837), _U(0xE27F996A4FB1C23C),
    _U(0xD3867DFB0775F0D0), _U(0xD0E673DE6E88891A), _U(0x123AEB9EAFB86C25), _U(0x30F1D5D5C145B895),
    _U(0xBB434A2DEE7269E7), _U(0x78CB67ECF931FA38), _U(0xF33B0372323BBF9C), _U(0x52D66336FB279C74),
    _U(0x505F33AC0AFB4EAA), _U(0xE8A5CD99A2CCE187), _U(0x534974801E2D30BB), _U(0x8D2D5711D5876D90),
    _U(0x1F1A412891BC038E), _U(0xD6E2E71D82E56648), _U(0x74036C3A497732B7), _U(0x89B67ED96361F5AB),
    _U(0xFFED95D8F1EA02A2), _U(0xE72B3BD61464D43D), _U(0xA6300F170BDC4820), _U(0xEBC18760ED78A77A)
  }, {
    _U(0xE6A6BE5A05A12138), _U(0xB5A122A5B4F87C98), _U(0x563C6089140B6990), _U(0x4C46CB2E391F5DD5),
    _U(0xD932ADDBC9B79434), _U(0x08EA70E42015AFF5), _U(0xD765A6673E478CF1), _U(0xC4FB757EAB278D99),
    _U(0xDF11C6862D6E0692), _U(0xDDEB84F10D7F3B16), _U(0x6F2EF604A665EA04), _U(0x4A8E0F0FF0E0DFB3),
    _U(0xA5EDEEF83DBCBA51), _U(0xFC4F0A2A0EA4371E), _U(0xE83E1DA85CB38429), _U(0xDC8FF882BA1B1CE2),
    _U(0xCD45505E8353E80D), _U(0x18D19A00D4DB0717), _U(0x34A0CFEDA5F38101), _U(0x0BE77E518887CAF2),
    _U(0x1E341438B3C45136), _U(0xE05797F49089CCF9), _U(0xFFD23F9DF2591D14), _U(0x543DDA228595C5CD),
    _U(0x661F81FD99052A33), _U(0x8736E641DB0F7B76), _U(0x15227725418E5307), _U(0xE25F7F46162EB2FA),
    _U(0x48A8B2126C13D9FE), _U(0xAFDC541792E76EEA), _U(0x03D912BFC6D1898F), _U(0x31B1AAFA1B83F51B),
    _U(0xF1AC2796E42AB7D9), _U(0x40A3A7D7FCD2EBAC), _U(0x1056136D0AFBBCC5), _U(0x7889E1DD9A6D0C85),
    _U(0xD33525782A7974AA), _U(0xA7E25D09078AC09B), _U(0xBD4138B3EAC6EDD0), _U(0x920ABFBE71EB9E70),
    _U(0xA2A5D0F54FC2625C), _U(0xC054E36B0B1290A3), _U(0xF6DD59FF62FE932B), _U(0x3537354511A8AC7D),
    _U(0xCA845E9172FADCD4), _U(0x84F82B60329D20DC), _U(0x79C62CE1CD672F18), _U(0x8B09A2ADD124642C),
    _U(0xD0C1E96A19D9E726), _U(0x5A786A9B4BA9500C), _U(0x0E020336634C43F3), _U(0xC17B474AEB66D822),
    _U(0x6A731AE3EC9BAAC2), _U(0x8226667AE0840258), _U(0x67D4567691CAECA5), _U(0x1D94155C4875ADB5),
    _U(0x6D00FD985B813FDF), _U(0x51286EFCB774CD06), _U(0x5E8834471FA744AF), _U(0xF72CA0AEE761AE2E),
    _U(0xBE40E4CDAEE8E09A), _U(0xE9970BBB5118F665), _U(0x726E4BEB33DF1964), _U(0x703B000729199762),
    _U(0x4631D816F5EF30A7), _U(0xB880B5B51504A6BE), _U(0x641793C37ED84B6C), _U(0x7B21ED77F6E97D96),
    _U(0x776306312EF96B73), _U(0xAE528948E86FF3F4), _U(0x53DBD7F286A3F8F8), _U(0x16CADCE74CFC1063),
    _U(0x005C19BDFA52C6DD), _U(0x68868F5D64D46AD3), _U(0x3A9D512CCF1E186A), _U(0x367E62C2385660AE),
    _U(0xE359E7EA77DCB1D7), _U(0x526C0773749ABE6E), _U(0x735AE5F9D09F734B), _U(0x493FC7CC8A558BA8),
    _U(0xB0B9C1533041AB45), _U(0x321958BA470A59BD), _U(0x852DB00B5F46C393), _U(0x91209B2BD336B0E5),
    _U(0x6E604F7D659EF19F), _U(0xB99A8AE2782CCB24), _U(0xCCF52AB6C814C4C7), _U(0x4727D9AFBE11727B),
    _U(0x7E950D0C0121B34D), _U(0x756F435670AD471F), _U(0xF5ADD442615A6849), _U(0x4E87E09980B9957A),
    _U(0x2ACFA1DF50AEE355), _U(0xD898263AFD2FD556), _U(0xC8F4924DD80C8FD6), _U(0xCF99CA3D754A173A),
    _U(0xFE477BACAF91BF3C), _U(0xED5371F6D690C12D), _U(0x831A5C285E687094), _U(0xC5D3C90A3708A0A4),
    _U(0x0F7F903717D06580), _U(0x19F9BB13B8FDF27F), _U(0xB1BD6F1B4D502843), _U(0x1C761BA38FFF4012),
    _U(0x0D1530C4E2E21F3B), _U(0x8943CE69A7372C8A), _U(0xE5184E11FEB5CE66), _U(0x618BDB80BD736621),
    _U(0x7D29BAD68B574D0B), _U(0x81BB613E25E6FE5B), _U(0x071C9C10BC07913F), _U(0xC7BEEB7909AC2D97),
    _U(0xC3E58D353BC5D757), _U(0xEB017892F38F61E8), _U(0xD4EFFB9C9B1CC21A), _U(0x99727D26F494F7AB),
    _U(0xA3E063A2956B3E03), _U(0x9D4A8B9A4AA09C30), _U(0x3F6AB7D500090FB4), _U(0x9CC0F2A057268AC0),
    _U(0x3DEE9D2DEDBF42D1), _U(0x330F49C87960A972), _U(0xC6B2720287421B41), _U(0x0AC59EC07C00369C),
    _U(0xEF4EAC49CB353425), _U(0xF450244EEF0129D8), _U(0x8ACC46E5CAF4DEB6), _U(0x2FFEAB63989263F7),
    _U(0x8F7CB9FE5D7A4578), _U(0x5BD8F7644E634635), _U(0x427A7315BF2DC900), _U(0x17D0C4AA2125261C),
    _U(0x3992486C93518E50), _U(0xB4CBFEE0A2D7D4C3), _U(0x7C75D6202C5DDD8D), _U(0xDBC295D8E35B6C61),
    _U(0x60B369D302032B19), _U(0xCE42685FDCE44132), _U(0x06F3DDB9DDF65610), _U(0x8EA4D21DB5E148F0),
    _U(0x20B0FCE62FCD496F), _U(0x2C1B912358B0EE31), _U(0xB28317B818F5A308), _U(0xA89C1E189CA6D2CF),
    _U(0x0C6B18576AAADBC8), _U(0xB65DEAA91299FAE3), _U(0xFB2B794B7F1027E7), _U(0x04E4317F443B5BEB),
    _U(0x4B852D325939D0A6), _U(0xD5AE6BEEFB207FFC), _U(0x309682B281C7D374), _U(0xBAE309A194C3B475),
    _U(0x8CC3F97B13B49F05), _U(0x98A9422FF8293967), _U(0x244B16B01076FF7C), _U(0xF8BF571C663D67EE),
    _U(0x1F0D6758EEE30DA1), _U(0xC9B611D97ADEB9B7), _U(0xB7AFD5887B6C57A2), _U(0x6290AE846B984FE1),
    _U(0x94DF4CDEACC1A5FD), _U(0x058A5BD1C5483AFF), _U(0x63166CC142BA3C37), _U(0x8DB8526EB2F76F40),
    _U(0xE10880036F0D6D4E), _U(0x9E0523C9971D311D), _U(0x45EC2824CC7CD691), _U(0x575B8359E62382C9),
    _U(0xFA9E400DC4889995), _U(0xD1823ECB45721568), _U(0xDAFD983B8206082F), _U(0xAA7D29082386A8CB),
    _U(0x269FCD4403B87588), _U(0x1B91F5F728BDD1E0), _U(0xE4669F39040201F6), _U(0x7A1D7C218CF04ADE),
    _U(0x65623C29D79CE5CE), _U(0x2368449096C00BB1), _U(0xAB9BF1879DA503BA), _U(0xBC23ECB1A458058E),
    _U(0x9A58DF01BB401ECC), _U(0xA070E868A85F143D), _U(0x4FF188307DF2239E), _U(0x14D565B41A641183),
    _U(0xEE13337452701602), _U(0x950E3DCF3F285E09), _U(0x59930254B9C80953), _U(0x3BF299408930DA6D),
    _U(0xA955943F53691387), _U(0xA15EDECAA9CB8784), _U(0x29142127352BE9A0), _U(0x76F0371FFF4E7AFB),
    _U(0x0239F450274F2228), _U(0xBB073AF01D5E868B), _U(0xBFC80571C10E96C1), _U(0xD267088568222E23),
    _U(0x9671A3D48E80B5B0), _U(0x55B5D38AE193BB81), _U(0x693AE2D0A18B04B8), _U(0x5C48B4ECADD5335F),
    _U(0xFD743B194916A1CA), _U(0x2577018134BE98C4), _U(0xE77987E83C54A4AD), _U(0x28E11014DA33E1B9),
    _U(0x270CC59E226AA213), _U(0x71495F756D1A5F60), _U(0x9BE853FB60AFEF77), _U(0xADC786A7F7443DBF),
    _U(0x0904456173B29A82), _U(0x58BC7A66C232BD5E), _U(0xF306558C673AC8B2), _U(0x41F639C6B6C9772A),
    _U(0x216DEFE99FDA35DA), _U(0x11640CC71C7BE615), _U(0x93C43694565C5527), _U(0xEA038E6246777839),
    _U(0xF9ABF3CE5A3E2469), _U(0x741E768D0FD312D2), _U(0x0144B883CED652C6), _U(0xC20B5A5BA33F8552),
    _U(0x1AE69633C3435A9D), _U(0x97A28CA4088CFDEC), _U(0x8824A43C1E96F420), _U(0x37612FA66EEEA746),
    _U(0x6B4CB165F9CF0E5A), _U(0x43AA1C06A0ABFB4A), _U(0x7F4DC26FF162796B), _U(0x6CBACC8E54ED9B0F),
    _U(0xA6B7FFEFD2BB253E), _U(0x2E25BC95B0A29D4F), _U(0x86D6A58BDEF1388C), _U(0xDED74AC576B6F054),
    _U(0x8030BDBC2B45805D), _U(0x3C81AF70E94D9289), _U(0x3EFF6DDA9E3100DB), _U(0xB38DC39FDFCC8847),
    _U(0x123885528D17B87E), _U(0xF2DA0ED240B1B642), _U(0x44CEFADCD54BF9A9), _U(0x1312200E433C7EE6),
    _U(0x9FFCC84F3A78C748), _U(0xF0CD1F72248576BB), _U(0xEC6974053638CFE4), _U(0x2BA7B67C0CEC4E4C),
    _U(0xAC2F4DF3E5CE32ED), _U(0xCB33D14326EA4C11), _U(0xA4E9044CC77E58BC), _U(0x5F513293D934FCEF),
    _U(0x5DC9645506E55444), _U(0x50DE418F317DE40A), _U(0x388CB31A69DDE259), _U(0x2DB4A83455820A86),
    _U(0x9010A91E84711AE9), _U(0x4DF7F0B7B1498371), _U(0xD62A2EABC0977179), _U(0x22FAC097AA8D5C0E)
  }, {
    _U(0xF49FCC2FF1DAF39B), _U(0x487FD5C66FF29281), _U(0xE8A30667FCDCA83F), _U(0x2C9B4BE3D2FCCE63),
    _U(0xDA3FF74B93FBBBC2), _U(0x2FA165D2FE70BA66), _U(0xA103E279970E93D4), _U(0xBECDEC77B0E45E71),
    _U(0xCFB41E723985E497), _U(0xB70AAA025EF75017), _U(0xD42309F03840B8E0), _U(0x8EFC1AD035898579),
    _U(0x96C6920BE2B2ABC5), _U(0x66AF4163375A9172), _U(0x2174ABDCCA7127FB), _U(0xB33CCEA64A72FF41),
    _U(0xF04A4933083066A5), _U(0x8D970ACDD7289AF5), _U(0x8F96E8E031C8C25E), _U(0xF3FEC02276875D47),
    _U(0xEC7BF310056190DD), _U(0xF5ADB0AEBB0F1491), _U(0x9B50F8850FD58892), _U(0x4975488358B74DE8),
    _U(0xA3354FF691531C61), _U(0x0702BBE481D2C6EE), _U(0x89FB24057DEDED98), _U(0xAC3075138596E902),
    _U(0x1D2D3580172772ED), _U(0xEB738FC28E6BC30D), _U(0x5854EF8F63044326), _U(0x9E5C52325ADD3BBE),
    _U(0x90AA53CF325C4623), _U(0xC1D24D51349DD067), _U(0x2051CFEEA69EA624), _U(0x13220F0A862E7E4F),
    _U(0xCE39399404E04864), _U(0xD9C42CA47086FCB7), _U(0x685AD2238A03E7CC), _U(0x066484B2AB2FF1DB),
    _U(0xFE9D5D70EFBF79EC), _U(0x5B13B9DD9C481854), _U(0x15F0D475ED1509AD), _U(0x0BEBCD060EC79851),
    _U(0xD58C6791183AB7F8), _U(0xD1187C5052F3EEE4), _U(0xC95D1192E54E82FF), _U(0x86EEA14CB9AC6CA2),
    _U(0x3485BEB153677D5D), _U(0xDD191D781F8C492A), _U(0xF60866BAA784EBF9), _U(0x518F643BA2D08C74),
    _U(0x8852E956E1087C22), _U(0xA768CB8DC410AE8D), _U(0x38047726BFEC8E1A), _U(0xA67738B4CD3B45AA),
    _U(0xAD16691CEC0DDE19), _U(0xC6D4319380462E07), _U(0xC5A5876D0BA61938), _U(0x16B9FA1FA58FD840),
    _U(0x188AB1173CA74F18), _U(0xABDA2F98C99C021F), _U(0x3E0580AB134AE816), _U(0x5F3B05B773645ABB),
    _U(0x2501A2BE5575F2F6), _U(0x1B2F74004E7E8BA9), _U(0x1CD7580371E8D953), _U(0x7F6ED89562764E30),
    _U(0xB15926FF596F003D), _U(0x9F65293DA8C5D6B9), _U(0x6ECEF04DD690F84C), _U(0x4782275FFF33AF88),
    _U(0xE41433083F820801), _U(0xFD0DFE409A1AF9B5), _U(0x4325A3342CDB396B), _U(0x8AE77E62B301B252),
    _U(0xC36F9E9F6655615A), _U(0x85455A2D92D32C09), _U(0xF2C7DEA949477485), _U(0x63CFB4C133A39EBA),
    _U(0x83B040CC6EBC5462), _U(0x3B9454C8FDB326B0), _U(0x56F56A9E87FFD78C), _U(0x2DC2940D99F42BC6),
    _U(0x98F7DF096B096E2D), _U(0x19A6E01E3AD852BF), _U(0x42A99CCBDBD4B40B), _U(0xA59998AF45E9C559),
    _U(0x366295E807D93186), _U(0x6B48181BFAA1F773), _U(0x1FEC57E2157A0A1D), _U(0x4667446AF6201AD5),
    _U(0xE615EBCACFB0F075), _U(0xB8F31F4F68290778), _U(0x22713ED6CE22D11E), _U(0x3057C1A72EC3C93B),
    _U(0xCB46ACC37C3F1F2F), _U(0xDBB893FD02AAF50E), _U(0x331FD92E600B9FCF), _U(0xA498F96148EA3AD6),
    _U(0xA8D8426E8B6A83EA), _U(0xA089B274B7735CDC), _U(0x87F6B3731E524A11), _U(0x118808E5CBC96749),
    _U(0x9906E4C7B19BD394), _U(0xAFED7F7E9B24A20C), _U(0x6509EADEEB3644A7), _U(0x6C1EF1D3E8EF0EDE),
    _U(0xB9C97D43E9798FB4), _U(0xA2F2D784740C28A3), _U(0x7B8496476197566F), _U(0x7A5BE3E6B65F069D),
    _U(0xF96330ED78BE6F10), _U(0xEEE60DE77A076A15), _U(0x2B4BEE4AA08B9BD0), _U(0x6A56A63EC7B8894E),
    _U(0x02121359BA34FEF4), _U(0x4CBF99F8283703FC), _U(0x398071350CAF30C8), _U(0xD0A77A89F017687A),
    _U(0xF1C1A9EB9E423569), _U(0x8C7976282DEE8199), _U(0x5D1737A5DD1F7ABD), _U(0x4F53433C09A9FA80),
    _U(0xFA8B0C53DF7CA1D9), _U(0x3FD9DCBC886CCB77), _U(0xC040917CA91B4720), _U(0x7DD00142F9D1DCDF),
    _U(0x8476FC1D4F387B58), _U(0x23F8E7C5F3316503), _U(0x032A2244E7E37339), _U(0x5C87A5D750F5A74B),
    _U(0x082B4CC43698992E), _U(0xDF917BECB858F63C), _U(0x3270B8FC5BF86DDA), _U(0x10AE72BB29B5DD76),
    _U(0x576AC94E7700362B), _U(0x1AD112DAC61EFB8F), _U(0x691BC30EC5FAA427), _U(0xFF246311CC327143),
    _U(0x3142368E30E53206), _U(0x71380E31E02CA396), _U(0x958D5C960AAD76F1), _U(0xF8D6F430C16DA536),
    _U(0xC8FFD13F1BE7E1D2), _U(0x7578AE66004DDBE1), _U(0x05833F01067BE646), _U(0xBB34B5AD3BFE586D),
    _U(0x095F34C9A12B97F0), _U(0x247AB64525D60CA8), _U(0xDCDBC6F3017477D1), _U(0x4A2E14D4DECAD24D),
    _U(0xBDB5E6D9BE0A1EEB), _U(0x2A7E70F7794301AB), _U(0xDEF42D8A270540FD), _U(0x01078EC0A34C22C1),
    _U(0xE5DE511AF4C16387), _U(0x7EBB3A52BD9A330A), _U(0x77697857AA7D6435), _U(0x004E831603AE4C32),
    _U(0xE7A21020AD78E312), _U(0x9D41A70C6AB420F2), _U(0x28E06C18EA1141E6), _U(0xD2B28CBD984F6B28),
    _U(0x26B75F6C446E9D83), _U(0xBA47568C4D418D7F), _U(0xD80BADBFE6183D8E), _U(0x0E206D7F5F166044),
    _U(0xE258A43911CBCA3E), _U(0x723A1746B21DC0BC), _U(0xC7CAA854F5D7CDD3), _U(0x7CAC32883D261D9C),
    _U(0x7690C26423BA942C), _U(0x17E55524478042B8), _U(0xE0BE477656A2389F), _U(0x4D289B5E67AB2DA0),
    _U(0x44862B9C8FBBFD31), _U(0xB47CC8049D141365), _U(0x822C1B362B91C793), _U(0x4EB14655FB13DFD8),
    _U(0x1ECBBA0714E2A97B), _U(0x6143459D5CDE5F14), _U(0x53A8FBF1D5F0AC89), _U(0x97EA04D81C5E5B00),
    _U(0x622181A8D4FDB3F3), _U(0xE9BCD341572A1208), _U(0x1411258643CCE58A), _U(0x9144C5FEA4C6E0A4),
    _U(0x0D33D06565CF620F), _U(0x54A48D489F219CA1), _U(0xC43E5EAC6D63C821), _U(0xA9728B3A72770DAF),
    _U(0xD7934E7B20DF87EF), _U(0xE35503B61A3E86E5), _U(0xCAE321FBC819D504), _U(0x129A50B3AC60BFA6),
    _U(0xCD5E68EA7E9FB6C3), _U(0xB01C90199483B1C7), _U(0x3DE93CD5C295376C), _U(0xAED52EDF2AB9AD13),
    _U(0x2E60F512C0A07884), _U(0xBC3D86A3E36210C9), _U(0x35269D9B163951CE), _U(0x0C7D6E2AD0CDB5FA),
    _U(0x59E86297D87F5733), _U(0x298EF221898DB0E7), _U(0x55000029D1A5AA7E), _U(0x8BC08AE1B5061B45),
    _U(0xC2C31C2B6C92703A), _U(0x94CC596BAF25EF42), _U(0x0A1D73DB22540456), _U(0x04B6A0F9D9C4179A),
    _U(0xEFFDAFA2AE3D3C60), _U(0xF7C8075BB49496C4), _U(0x9CC5C7141D1CD4E3), _U(0x78BD1638218E5534),
    _U(0xB2F11568F850246A), _U(0xEDFABCFA9502BC29), _U(0x796CE5F2DA23051B), _U(0xAAE128B0DC93537C),
    _U(0x3A493DA0EE4B29AE), _U(0xB5DF6B2C416895D7), _U(0xFCABBD25122D7F37), _U(0x70810B58105DC4B1),
    _U(0xE10FDD37F7882A90), _U(0x524DCAB5518A3F5C), _U(0x3C9E85878451255B), _U(0x4029828119BD34E2),
    _U(0x74A05B6F5D3CECCB), _U(0xB610021542E13ECA), _U(0x0FF979D12F59E2AC), _U(0x6037DA27E4F9CC50),
    _U(0x5E92975A0DF1847D), _U(0xD66DE190D3E623FE), _U(0x5032D6B87B568048), _U(0x9A36B7CE8235216E),
    _U(0x80272A7A24F64B4A), _U(0x93EFED8B8C6916F7), _U(0x37DDBFF44CCE1555), _U(0x4B95DB5D4B99BD25),
    _U(0x92D3FDA169812FC0), _U(0xFB1A4A9A90660BB6), _U(0x730C196946A4B9B2), _U(0x81E289AA7F49DA68),
    _U(0x64669A0F83B1A05F), _U(0x27B3FF7D9644F48B), _U(0xCC6B615C8DB675B3), _U(0x674F20B9BCEBBE95),
    _U(0x6F31238275655982), _U(0x5AE488713E45CF05), _U(0xBF619F9954C21157), _U(0xEABAC46040A8EAE9),
    _U(0x454C6FE9F2C0C1CD), _U(0x419CF6496412691C), _U(0xD3DC3BEF265B0F70), _U(0x6D0E60F5C3578A9E)
  }, {
    _U(0x5B0E608526323C55), _U(0x1A46C1A9FA1B59F5), _U(0xA9E245A17C4C8FFA), _U(0x65CA5159DB2955D7),
    _U(0x05DB0A76CE35AFC2), _U(0x81EAC77EA9113D45), _U(0x528EF88AB6AC0A0D), _U(0xA09EA253597BE3FF),
    _U(0x430DDFB3AC48CD56), _U(0xC4B3A67AF45CE46F), _U(0x4ECECFD8FBE2D05E), _U(0x3EF56F10B39935F0),
    _U(0x0B22D6829CD619C6), _U(0x17FD460A74DF2069), _U(0x6CF8CC8E8510ED40), _U(0xD6C824BF3A6ECAA7),
    _U(0x61243D581A817049), _U(0x048BACB6BBC163A2), _U(0xD9A38AC27D44CC32), _U(0x7FDDFF5BAAF410AB),
    _U(0xAD6D495AA804824B), _U(0xE1A6A74F2D8C9F94), _U(0xD4F7851235DEE8E3), _U(0xFD4B7F886540D893),
    _U(0x247C20042AA4BFDA), _U(0x096EA1C517D1327C), _U(0xD56966B4361A6685), _U(0x277DA5C31221057D),
    _U(0x94D59893A43ACFF7), _U(0x64F0C51CCDC02281), _U(0x3D33BCC4FF6189DB), _U(0xE005CB184CE66AF1),
    _U(0xFF5CCD1D1DB99BEA), _U(0xB0B854A7FE42980F), _U(0x7BD46A6A718D4B9F), _U(0xD10FA8CC22A5FD8C),
    _U(0xD31484952BE4BD31), _U(0xC7FA975FCB243847), _U(0x4886ED1E5846C407), _U(0x28CDDB791EB70B04),
    _U(0xC2B00BE2F573417F), _U(0x5C9590452180F877), _U(0x7A6BDDFFF370EB00), _U(0xCE509E38D6D9D6A4),
    _U(0xEBEB0F00647FA702), _U(0x1DCC06CF76606F06), _U(0xE4D9F28BA286FF0A), _U(0xD85A305DC918C262),
    _U(0x475B1D8732225F54), _U(0x2D4FB51668CCB5FE), _U(0xA679B9D9D72BBA20), _U(0x53841C0D912D43A5),
    _U(0x3B7EAA48BF12A4E8), _U(0x781E0E47F22F1DDF), _U(0xEFF20CE60AB50973), _U(0x20D261D19DFFB742),
    _U(0x16A12B03062A2E39), _U(0x1960EB2239650495), _U(0x251C16FED50EB8B8), _U(0x9AC0C330F826016E),
    _U(0xED152665953E7671), _U(0x02D63194A6369570), _U(0x5074F08394B1C987), _U(0x70BA598C90B25CE1),
    _U(0x794A15810B9742F6), _U(0x0D5925E9FCAF8C6C), _U(0x3067716CD868744E), _U(0x910AB077E8D7731B),
    _U(0x6A61BBDB5AC42F61), _U(0x93513EFBF0851567), _U(0xF494724B9E83E9D5), _U(0xE887E1985C09648D),
    _U(0x34B1D3C675370CFD), _U(0xDC35E433BC0D255D), _U(0xD0AAB84234131BE0), _U(0x08042A50B48B7EAF),
    _U(0x9997C4EE44A3AB35), _U(0x829A7B49201799D0), _U(0x263B8307B7C54441), _U(0x752F95F4FD6A6CA6),
    _U(0x927217402C08C6E5), _U(0x2A8AB754A795D9EE), _U(0xA442F7552F72943D), _U(0x2C31334E19781208),
    _U(0x4FA98D7CEAEE6291), _U(0x55C3862F665DB309), _U(0xBD0610175D53B1F3), _U(0x46FE6CB840413F27),
    _U(0x3FE03792DF0CFA59), _U(0xCFE700372EB85E8F), _U(0xA7BE29E7ADBCE118), _U(0xE544EE5CDE8431DD),
    _U(0x8A781B1B41F1873E), _U(0xA5C94C78A0D2F0E7), _U(0x39412E2877B60728), _U(0xA1265EF3AFC9A62C),
    _U(0xBCC2770C6A2506C5), _U(0x3AB66DD5DCE1CE12), _U(0xE65499D04A675B37), _U(0x7D8F523481BFD216),
    _U(0x0F6F64FCEC15F389), _U(0x74EFBE618B5B13C8), _U(0xACDC82B714273E1D), _U(0xDD40BFE003199D17),
    _U(0x37E99257E7E061F8), _U(0xFA52626904775AAA), _U(0x8BBBF63A463D56F9), _U(0xF0013F1543A26E64),
    _U(0xA8307E9F879EC898), _U(0xCC4C27A4150177CC), _U(0x1B432F2CCA1D3348), _U(0xDE1D1F8F9F6FA013),
    _U(0x606602A047A7DDD6), _U(0xD237AB64CC1CB2C7), _U(0x9B938E7225FCD1D3), _U(0xEC4E03708E0FF476),
    _U(0xFEB2FBDA3D03C12D), _U(0xAE0BCED2EE43889A), _U(0x22CB8923EBFB4F43), _U(0x69360D013CF7396D),
    _U(0x855E3602D2D4E022), _U(0x073805BAD01F784C), _U(0x33E17A133852F546), _U(0xDF4874058AC7B638),
    _U(0xBA92B29C678AA14A), _U(0x0CE89FC76CFAADCD), _U(0x5F9D4E0908339E34), _U(0xF1AFE9291F5923B9),
    _U(0x6E3480F60F4A265F), _U(0xEEBF3A2AB29B841C), _U(0xE21938A88F91B4AD), _U(0x57DFEFF845C6D3C3),
    _U(0x2F006B0BF62CAAF2), _U(0x62F479EF6F75EE78), _U(0x11A55AD41C8916A9), _U(0xF229D29084FED453),
    _U(0x42F1C27B16B000E6), _U(0x2B1F76749823C074), _U(0x4B76ECA3C2745360), _U(0x8C98F463B91691BD),
    _U(0x14BCC93CF1ADE66A), _U(0x8885213E6D458397), _U(0x8E177DF0274D4711), _U(0xB49B73B5503F2951),
    _U(0x10168168C3F96B6B), _U(0x0E3D963B63CAB0AE), _U(0x8DFC4B5655A1DB14), _U(0xF789F1356E14DE5C),
    _U(0x683E68AF4E51DAC1), _U(0xC9A84F9D8D4B0FD9), _U(0x3691E03F52A0F9D1), _U(0x5ED86E46E1878E80),
    _U(0x3C711A0E99D07150), _U(0x5A0865B20C4E9310), _U(0x56FBFC1FE4F0682E), _U(0xEA8D5DE3105EDF9B),
    _U(0x71ABFDB12379187A), _U(0x2EB99DE1BEE77B9C), _U(0x21ECC0EA33CF4523), _U(0x59A4D7521805C7A1),
    _U(0x3896F5EB56AE7C72), _U(0xAA638F3DB18F75DC), _U(0x9F39358DABE9808E), _U(0xB7DEFA91C00B72AC),
    _U(0x6B5541FD62492D92), _U(0x6DC6DEE8F92E4D5B), _U(0x353F57ABC4BEEA7E), _U(0x735769D6DA5690CE),
    _U(0x0A234AA642391484), _U(0xF6F9508028F80D9D), _U(0xB8E319A27AB3F215), _U(0x31AD9C1151341A4D),
    _U(0x773C22A57BEF5805), _U(0x45C7561A07968633), _U(0xF913DA9E249DBE36), _U(0xDA652D9B78A64C68),
    _U(0x4C27A97F3BC334EF), _U(0x76621220E66B17F4), _U(0x967743899ACD7D0B), _U(0xF3EE5BCAE0ED6782),
    _U(0x409F753600C879FC), _U(0x06D09A39B5926DB6), _U(0x6F83AEB0317AC588), _U(0x01E6CA4A86381F21),
    _U(0x66FF3462D19F3025), _U(0x72207C24DDFD3BFB), _U(0x4AF6B6D3E2ECE2EB), _U(0x9C994DBEC7EA08DE),
    _U(0x49ACE597B09A8BC4), _U(0xB38C4766CF0797BA), _U(0x131B9373C57C2A75), _U(0xB1822CCE61931E58),
    _U(0x9D7555B909BA1C0C), _U(0x127FAFDD937D11D2), _U(0x29DA3BADC66D92E4), _U(0xA2C1D57154C2ECBC),
    _U(0x58C5134D82F6FE24), _U(0x1C3AE3515B62274F), _U(0xE907C82E01CB8126), _U(0xF8ED091913E37FCB),
    _U(0x3249D8F9C80046C9), _U(0x80CF9BEDE388FB63), _U(0x1881539A116CF19E), _U(0x5103F3F76BD52457),
    _U(0x15B7E6F5AE47F7A8), _U(0xDBD7C6DED47E9CCF), _U(0x44E55C410228BB1A), _U(0xB647D4255EDB4E99),
    _U(0x5D11882BB8AAFC30), _U(0xF5098BBB29D3212A), _U(0x8FB5EA14E90296B3), _U(0x677B942157DD025A),
    _U(0xFB58E7C0A390ACB5), _U(0x89D3674C83BD4A01), _U(0x9E2DA4DF4BF3B93B), _U(0xFCC41E328CAB4829),
    _U(0x03F38C96BA582C52), _U(0xCAD1BDBD7FD85DB2), _U(0xBBB442C16082AE83), _U(0xB95FE86BA5DA9AB0),
    _U(0xB22E04673771A93F), _U(0x845358C9493152D8), _U(0xBE2A488697B4541E), _U(0x95A2DC2DD38E6966),
    _U(0xC02C11AC923C852B), _U(0x2388B1990DF2A87B), _U(0x7C8008FA1B4F37BE), _U(0x1F70D0C84D54E503),
    _U(0x5490ADEC7ECE57D4), _U(0x002B3C27D9063A3A), _U(0x7EAEA3848030A2BF), _U(0xC602326DED2003C0),
    _U(0x83A7287D69A94086), _U(0xC57A5FCB30F57A8A), _U(0xB56844E479EBE779), _U(0xA373B40F05DCBCE9),
    _U(0xD71A786E88570EE2), _U(0x879CBACDBDE8F6A0), _U(0x976AD1BCC164A32F), _U(0xAB21E25E9666D78B),
    _U(0x901063AAE5E5C33C), _U(0x9818B34448698D90), _U(0xE36487AE3E1E8ABB), _U(0xAFBDF931893BDCB4),
    _U(0x6345A0DC5FBBD519), _U(0x8628FE269B9465CA), _U(0x1E5D01603F9C51EC), _U(0x4DE44006A15049B7),
    _U(0xBF6C70E5F776CBB1), _U(0x411218F2EF552BED), _U(0xCB0C0708705A36A3), _U(0xE74D14754F986044),
    _U(0xCD56D9430EA8280E), _U(0xC12591D7535F5065), _U(0xC83223F1720AEF96), _U(0xC3A0396F7363A51F)
  }
};

