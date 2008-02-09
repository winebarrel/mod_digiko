#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_buckets.h"
#include "http_log.h"

#include "oniguruma.h"

static regex_t *reg_compile(request_rec *req, const char *pattern, OnigEncoding enc) {
  regex_t* reg;
  OnigErrorInfo einfo;
  int r;

  r = onig_new(&reg, (UChar *) pattern, (UChar *) (pattern + strlen(pattern)),
    ONIG_OPTION_DEFAULT, enc, ONIG_SYNTAX_DEFAULT, &einfo);

  if (r != ONIG_NORMAL) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r, &einfo);
    ap_log_error(APLOG_MARK,  APLOG_ERR, APR_SUCCESS, req->server, s);
    return NULL;
  }

  return reg;
}

static int reg_search_all(request_rec *req, regex_t *reg, const char *str, int len, void (*handler)(request_rec *req, const char *src, OnigRegion *region, apr_bucket_brigade *bb), apr_bucket_brigade *bb) {
  UChar *ustr;
  OnigRegion *region;
  int r, region_end = 0;
  unsigned char *start, *range, *end;

  ustr = (UChar *) str;
  region = onig_region_new();

  end = ustr + len;
  start = ustr;
  range = end;

  while ((r = onig_search(reg, ustr, end, start, range, region, ONIG_OPTION_NONE)) >= 0) {
    apr_brigade_write(bb, NULL, NULL, start, region->beg[0] - region_end);
    region_end = region->end[0];

    handler(req, str, region, bb);

    if (region_end >= len) {
      break;
    }

    onig_region_clear(region);
    start = ustr + region_end;
  }

  if (region_end < len) {
    start = ustr + region_end;
    apr_brigade_write(bb, NULL, NULL, start, len - region_end);
  }

  onig_region_free(region, 1);

  if (r < 0 && r != ONIG_MISMATCH) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str(s, r);
    ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, req->server, s);
    return 0;
  }

  return 1;
}

void digiko_handler(request_rec *req, const char *src, OnigRegion *region, apr_bucket_brigade *bb) {
  int i, len;
  const char *start;

  start = src + region->beg[0];
  len = region->end[0] - region->beg[0];

  for (i = 0; i < region->num_regs; i++) {
    apr_brigade_write(bb, NULL, NULL, "‚É‚å", 4);
    apr_brigade_write(bb, NULL, NULL, start, len);
  }
}

static apr_status_t digiko_filter(ap_filter_t *f, apr_bucket_brigade *bbin) {
  request_rec *r = f->r;
  apr_bucket_brigade *bbout;
  regex_t* reg;

  if (APR_BRIGADE_EMPTY(bbin)) {
    return APR_SUCCESS;
  }

  if (!r->content_type || strncmp(r->content_type, "text/html", 9) != 0) {
    return ap_pass_brigade(f->next, bbin);
  }

  apr_table_unset(r->headers_out, "Content-Length");
  bbout = apr_brigade_create(r->pool, f->c->bucket_alloc);

  if ((reg = reg_compile(r, "B", ONIG_ENCODING_SJIS)) == NULL) {
    return ap_pass_brigade(f->next, bbin);
  }

  while (!APR_BRIGADE_EMPTY(bbin)) {
    apr_bucket *e = APR_BRIGADE_FIRST(bbin);
    char *str;
    apr_size_t len;

    if (APR_BUCKET_IS_EOS(e)) {
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(bbout, e);
      break;
    }

    if (APR_BUCKET_IS_METADATA(e)) {
      APR_BUCKET_REMOVE(e);
      APR_BRIGADE_INSERT_TAIL(bbout, e);
      continue;
    }

    apr_bucket_read(e, &str, &len, APR_BLOCK_READ);

    if (!reg_search_all(r, reg, str, len, digiko_handler, bbout)) {
      apr_brigade_write(bbout, NULL, NULL, str, len);
    }

    apr_bucket_delete(e);
  }

  onig_free(reg);
  onig_end();
  return ap_pass_brigade(f->next, bbout);
}

static void digiko_register_hooks(apr_pool_t *p) {
  ap_register_output_filter("DIGIKO", digiko_filter, NULL, AP_FTYPE_CONTENT_SET);
}

module AP_MODULE_DECLARE_DATA digiko_module = {
  STANDARD20_MODULE_STUFF, 
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  digiko_register_hooks
};
