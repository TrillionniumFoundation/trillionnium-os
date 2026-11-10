#ifndef HEPTA_SHA256_DISPATCH_HPP
#define HEPTA_SHA256_DISPATCH_HPP
/* Preserve full SHA-256 on every request. No digest or model verification cache.
 * Portable compression is the exact fixed worker-upstream.c implementation.
 * Arm rounds follow ACLE SHA256H/H2/SU0/SU1 semantics; dispatch follows Linux HWCAP.
 * https://arm-software.github.io/acle/main/acle.html
 * https://www.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if defined(__aarch64__) && defined(__linux__) && defined(__clang__) && defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HEPTA_SHA256_ARMV8_COMPILED 1
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <arm_neon.h>
#else
#define HEPTA_SHA256_ARMV8_COMPILED 0
#endif

typedef struct {
    uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used;
    bool hardware; uint64_t hardware_blocks, portable_blocks;
} Sha256;

static bool hepta_sha256_runtime_sha2(void) {
#if HEPTA_SHA256_ARMV8_COMPILED
    int saved=errno;
    unsigned long capabilities=getauxval(AT_HWCAP);
    errno=saved;
    return (capabilities & HWCAP_SHA2)!=0;
#else
    return false;
#endif
}

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }
static void hepta_sha256_portable_block(Sha256 *s, const unsigned char *p) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    uint32_t w[64], a,b,c,d,e,f,g,h;
    for (unsigned i=0;i<16;i++) w[i]=((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
    for (unsigned i=16;i<64;i++) {
        uint32_t x=w[i-15],y=w[i-2];
        w[i]=w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>10));
    }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for (unsigned i=0;i<64;i++) {
        uint32_t t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}

#if HEPTA_SHA256_ARMV8_COMPILED
static const uint32_t hepta_sha256_round_constants[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
#endif

#if HEPTA_SHA256_ARMV8_COMPILED
/* No SHA2 instructions may execute before the HWCAP gate. Keep this out of the
 * baseline dispatcher and do not enable +crypto on the whole translation unit. */
__attribute__((target("sha2"), noinline))
static void hepta_sha256_armv8_blocks(Sha256 *s,const unsigned char *p,size_t blocks) {
    uint32x4_t abcd=vld1q_u32(s->h),efgh=vld1q_u32(s->h+4);
    for(size_t block=0;block<blocks;block++,p+=64){
        uint32x4_t saved_abcd=abcd,saved_efgh=efgh;
        uint32x4_t message[4]={
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p+16))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p+32))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p+48)))};
#pragma clang loop unroll(full)
        for(unsigned group=0;group<16;group++){
            unsigned index=group&3u;
            uint32x4_t wk=vaddq_u32(message[index],vld1q_u32(hepta_sha256_round_constants+4u*group));
            uint32x4_t old_abcd=abcd;
            abcd=vsha256hq_u32(abcd,efgh,wk);
            efgh=vsha256h2q_u32(efgh,old_abcd,wk);
            if(group<12u){
                uint32x4_t partial=vsha256su0q_u32(message[index],message[(index+1u)&3u]);
                message[index]=vsha256su1q_u32(partial,message[(index+2u)&3u],message[(index+3u)&3u]);
            }
        }
        abcd=vaddq_u32(abcd,saved_abcd);efgh=vaddq_u32(efgh,saved_efgh);
    }
    vst1q_u32(s->h,abcd);vst1q_u32(s->h+4,efgh);
}
#endif

static void hepta_sha256_blocks(Sha256 *s,const unsigned char *p,size_t blocks) {
    if(!blocks)return;
#if HEPTA_SHA256_ARMV8_COMPILED
    if(s->hardware){hepta_sha256_armv8_blocks(s,p,blocks);s->hardware_blocks+=(uint64_t)blocks;return;}
#endif
    for(size_t i=0;i<blocks;i++)hepta_sha256_portable_block(s,p+64u*i);
    s->portable_blocks+=(uint64_t)blocks;
}

static void sha_init(Sha256 *s) {
    *s=Sha256{{0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u},
                0,{0},0,hepta_sha256_runtime_sha2(),0,0};
}
static void sha_update(Sha256 *s,const void *data,size_t n) {
    const unsigned char *p=static_cast<const unsigned char *>(data);s->bits+=(uint64_t)n*8u;
    if(!n)return;
    if(s->used){
        size_t take=64u-s->used;if(take>n)take=n;
        memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;
        if(s->used==64u){hepta_sha256_blocks(s,s->block,1);s->used=0;}
    }
    if(n>=64u){size_t blocks=n/64u,bytes=blocks*64u;hepta_sha256_blocks(s,p,blocks);p+=bytes;n-=bytes;}
    if(n){memcpy(s->block,p,n);s->used=n;}
}
static void sha_finish(Sha256 *s,char out[65]) {
    uint64_t bits=s->bits;unsigned char one=0x80,zero=0;sha_update(s,&one,1);
    while(s->used!=56)sha_update(s,&zero,1);
    unsigned char tail[8];for(unsigned i=0;i<8;i++)tail[7-i]=(unsigned char)(bits>>(8*i));sha_update(s,tail,8);
    for(unsigned i=0;i<8;i++)(void)snprintf(out+8*i,9,"%08" PRIx32,s->h[i]);
    out[64]='\0';
}
static void hash_bytes(const void *p,size_t n,char out[65]) {Sha256 s;sha_init(&s);sha_update(&s,p,n);sha_finish(&s,out);}
static const char *hepta_sha256_backend(const Sha256 *s){return s->hardware?"armv8-sha2":"portable";}
#endif
