/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)


typedef struct forti_config_aes_gcm
{
  u32 iv_buf[3];
  u32 garbage[5];
  u32 auth[4];
} forti_config_aes_gcm_t;

typedef struct forti_config_tmp
{
  u32 key[8];

} forti_config_tmp_t;

KERNEL_FQ void m33900_init (KERN_ATTR_TMPS_ESALT (forti_config_tmp_t, forti_config_aes_gcm_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;
  
  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);

  sha256_update_global_swap (&sha256_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&sha256_ctx);

  // set tmps:

  tmps[gid].key[0] = sha256_ctx.h[0];
  tmps[gid].key[1] = sha256_ctx.h[1];
  tmps[gid].key[2] = sha256_ctx.h[2];
  tmps[gid].key[3] = sha256_ctx.h[3];
  tmps[gid].key[4] = sha256_ctx.h[4];
  tmps[gid].key[5] = sha256_ctx.h[5];
  tmps[gid].key[6] = sha256_ctx.h[6];
  tmps[gid].key[7] = sha256_ctx.h[7];

}

KERNEL_FQ void m33900_loop (KERN_ATTR_TMPS_ESALT (forti_config_tmp_t, forti_config_aes_gcm_t))
{
  //sorry, no iteration, maybe next time
}

KERNEL_FQ void m33900_comp (KERN_ATTR_TMPS_ESALT (forti_config_tmp_t, forti_config_aes_gcm_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif


  if (gid >= GID_CNT) return;

  // key

  u32 ukey[8];

  ukey[0] = tmps[gid].key[0];
  ukey[1] = tmps[gid].key[1];
  ukey[2] = tmps[gid].key[2];
  ukey[3] = tmps[gid].key[3];
  ukey[4] = tmps[gid].key[4];
  ukey[5] = tmps[gid].key[5];
  ukey[6] = tmps[gid].key[6];
  ukey[7] = tmps[gid].key[7];

  // It is indeed AES GCM - but auth not used. so just encrypt iv with block cipher and xor with plaintext

  u32 ctr[4];

  ctr[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[0];
  ctr[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[1];
  ctr[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[2];
  ctr[3] = 0x00000002; //(0x00000001 + 1) (+1 b/c 1st cipherblock comes from counter 2 (counter 1 only for auth))

  //aes 256 encrypt the ctr
  u32 ks[60];
  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 ct[4] = { 0 };
  AES256_encrypt (ks, ctr, ct, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 gz_header[2] = { 0x1f8b0800,0x0 };

  ct[0] ^= gz_header[0];
  ct[1] ^= gz_header[1];

  const u32 r0 = ct[0];
  const u32 r1 = ct[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

