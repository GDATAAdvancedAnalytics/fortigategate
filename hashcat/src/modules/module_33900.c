
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4; 
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "FortiGate Backup";
static const u64   KERN_TYPE      = 33900;
//static const u32   OPTI_TYPE      = OPTI_TYPE_NOT_ITERATED;
//static const u64   OPTS_TYPE      = 0; 
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_LOWER;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED; 
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "234647424b7c347c4647564d36347c377c30347c323336307c0af6daa1d74547a3774f864120d4e86d481e466a44e004559c92495ae0f8c9391f406f7bdf";
u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

typedef struct forti_config_aes_gcm
{
  u32 iv_buf[3];
  u32 garbage_buf[5];
  u32 auth_buf[4];
} forti_config_aes_gcm_t;

typedef struct forti_config_tmp
{
  u32 key[8];

} forti_config_tmp_t;
static const char *SIGNATURE_FORTI_BACKUP = "234647424b7c347c";


u32 hex_to_u32_le (const u8 hex[8])
{
  u32 v = 0;

  v |= ((u32) hex_convert (hex[0]) <<  28);
  v |= ((u32) hex_convert (hex[1]) <<  24);
  v |= ((u32) hex_convert (hex[2]) <<  20);
  v |= ((u32) hex_convert (hex[3]) << 16);
  v |= ((u32) hex_convert (hex[4]) << 12);
  v |= ((u32) hex_convert (hex[5]) << 8);
  v |= ((u32) hex_convert (hex[6]) << 4);
  v |= ((u32) hex_convert (hex[7]) << 0);

  return (v);
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (forti_config_aes_gcm_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (forti_config_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{

  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_FORTI_BACKUP;

  token.len[0]  = 16;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 36; //garbage 
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 24; //iv 24 chars 
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH;
 
  token.len[3]  = 32; //auth, unnecessary
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[4]  = 16; //enc gz header
  token.attr[4] = TOKEN_ATTR_FIXED_LENGTH;  

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  forti_config_aes_gcm_t *fc_crypt = (forti_config_aes_gcm_t *) esalt_buf;

  // Important: No matter if you are going to use an esalt or not, you always need to fill the salt_buf[] array and set the salt_len for it.
  // fake salt
  const u8 *salt_pos = token.buf[4];
  salt->salt_len = 4;
  salt->salt_buf[0] = hex_to_u32_le (salt_pos);;
  salt->salt_iter = 1; 

  // Garbage - unused, just accessed in encoder

  const u8 *garbage_pos = token.buf[1];

  fc_crypt->garbage_buf[0] = hex_to_u32_le (garbage_pos +  0);
  fc_crypt->garbage_buf[1] = hex_to_u32_le (garbage_pos +  8);
  fc_crypt->garbage_buf[2] = hex_to_u32_le (garbage_pos +  16);
  fc_crypt->garbage_buf[3] = hex_to_u32_le (garbage_pos +  24);
  fc_crypt->garbage_buf[4] = hex_to_u32_le (garbage_pos +  32);  

  // Auth - unused, just accessed in encoder

  const u8 *auth_pos = token.buf[3];

  fc_crypt->auth_buf[0] = hex_to_u32_le (auth_pos +  0);
  fc_crypt->auth_buf[1] = hex_to_u32_le (auth_pos +  8);
  fc_crypt->auth_buf[2] = hex_to_u32_le (auth_pos +  16);
  fc_crypt->auth_buf[3] = hex_to_u32_le (auth_pos +  24);
  
  // IV

  const u8 *iv_pos = token.buf[2];

  fc_crypt->iv_buf[0] = hex_to_u32_le (iv_pos +  0);
  fc_crypt->iv_buf[1] = hex_to_u32_le (iv_pos +  8);
  fc_crypt->iv_buf[2] = hex_to_u32_le (iv_pos + 16);

  // CT 

  const u8 *ct_pos = token.buf[4];

  digest[0] = hex_to_u32_le (ct_pos +  0);
  digest[1] = hex_to_u32_le (ct_pos +  8);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  forti_config_aes_gcm_t *fc_crypt = (forti_config_aes_gcm_t *) esalt_buf;

  // IV

  #define IV_HEX_LEN 12 * 2 + 1

  char iv_buf[IV_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < 12 / 4; i += 1, j += 8) {
    snprintf (iv_buf + j, IV_HEX_LEN - j, "%08x", fc_crypt->iv_buf[i]);
  }

  // Garbage - copy from decode
  #define G_HEX_LEN 18 * 2 + 1

  char garbage_buf[G_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < 18 / 4; i += 1, j += 8) {
    snprintf (garbage_buf + j, G_HEX_LEN - j, "%08x", fc_crypt->garbage_buf[i]);
  }
  snprintf (garbage_buf + 32, G_HEX_LEN - 32, "%04x", fc_crypt->garbage_buf[4]);

  // Auth - copy from decode
  #define AUTH_HEX_LEN 16 * 2 + 1

  char auth_buf[AUTH_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < 16 / 4; i += 1, j += 8) {
    snprintf (auth_buf + j, AUTH_HEX_LEN - j, "%08x", fc_crypt->auth_buf[i]);
  }

  // output

  int line_len = snprintf (line_buf, line_size, "%s%s%s%s%08x%08x",
    SIGNATURE_FORTI_BACKUP,
    garbage_buf,
    iv_buf,
    auth_buf,
    digest[0],
    digest[1]);

  return line_len;

}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
