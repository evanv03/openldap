#include <unistd.h>
#include "lutil.h"
#include <lber.h>
#include <lber_pvt.h>
#include <ac/string.h>
#include "guardlib.h"
#include "assert.h"
#include <unistd.h>
#include "lutil_md5.h"
#include <stdio.h>
#include <string.h>
#include <portable.h>
#include <slap.h>
//#include "libtest.h"
static const struct berval scheme_guard = BER_BVC("{GUARD}");
static LUTIL_PASSWD_CHK_FUNC chk_guard;
static LUTIL_PASSWD_HASH_FUNC do_guard_hash;
static slap_overinst guard;
static void logger(char *str){
    FILE *f;
    f = fopen("/tmp/evango.log", "a");

    fprintf(f, "%s\n", str);
    fclose(f);
}


//Guard cleanup: essentially this program is to clean up the pointers after the usage of threads
static int guard_op_cleanup(Operation *op, SlapReply *rp) {
	logger("cleanup is working");
	slap_callback *cb;
	ldap_pvt_thread_pool_setkey(op->o_threadctx, guard_op_cleanup, NULL, 0, NULL, NULL);
	//callback handling
	cb = op->o_callback;
	op->o_callback = cb->sc_next;
	op->o_tmpfree(cb, op->o_tmpmemctx);
	logger("cleanup worked");
	return 0;
}

static int guard_bind(Operation *op, SlapReply *rs) {
	logger("bind is working");
	slap_callback *cb;
	ldap_pvt_thread_pool_setkey(op->o_threadctx, guard_op_cleanup, op, 0, NULL, NULL);
	cb = op->o_tmpcalloc( 1, sizeof(slap_callback), op->o_tmpmemctx );
	cb->sc_cleanup = guard_op_cleanup;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;
	logger("bind worked");
	return SLAP_CB_CONTINUE;
}

static int guard_ldappasswd(Operation *op, SlapReply *rs) {
	logger("add is working");
     slap_callback *cb;
     ldap_pvt_thread_pool_setkey(op->o_threadctx, guard_op_cleanup, op, 0, NULL, NULL);
     cb = op->o_tmpcalloc( 1, sizeof(slap_callback), op->o_tmpmemctx );
     cb->sc_next = op->o_callback;
     op->o_callback = cb;
     logger("add worked");
     return SLAP_CB_CONTINUE;
}

static int do_guard_hash(const struct berval *scheme, const struct berval *passwd, struct berval *hash, const char **text) {

	logger("hash");
	void *ctx;
	void *tmpopp;
	Operation *op;
	Attribute *a;
	Entry *e;
	int rc;
	slap_callback *cb;
	ctx = ldap_pvt_thread_pool_context();
	ldap_pvt_thread_pool_getkey( ctx, guard_op_cleanup, &tmpopp, NULL );
	op = tmpopp;
	cb = op->o_tmpcalloc( 1, sizeof(slap_callback), op->o_tmpmemctx );
    cb->sc_next = op->o_callback;
    op->o_callback = cb;

	logger("all the variables are initialized");
	rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
    if ( rc != LDAP_SUCCESS ) return LUTIL_PASSWD_ERR;
	logger("entry found");

	a = attr_find( e->e_attrs, slap_schema.si_ad_userPassword);
	logger("uid found");
	const struct berval *UID = a->a_vals;
	logger(UID->bv_val);
	int i = setpass(UID->bv_val, passwd->bv_val, hash->bv_val);
	logger(passwd->bv_val);
	logger("hash is done");
    unsigned char digest_buf[LUTIL_MD5_BYTES];
    struct berval digest;
    digest.bv_val = (char *) digest_buf;
    digest.bv_len = sizeof(digest_buf);
    FILE *f;
    f = fopen("/tmp/evango.log", "a");
    fprintf(f, "\n%d\n", lutil_passwd_string64(scheme, &digest, hash, passwd));
    cb->sc_cleanup = guard_op_cleanup;
	return lutil_passwd_string64(scheme, &digest, hash, passwd);
}

static int chk_guard(const struct berval *scheme, const struct berval *passwd, const struct berval *cred, const char **digest) {
	printf("\n The Code Is Running 2 \n");
	logger("guard");
	void *ctx;
    void *tmpopp;
    Operation *op;
    Attribute *a;
    ctx = ldap_pvt_thread_pool_context();
    ldap_pvt_thread_pool_getkey( ctx, guard_op_cleanup, &tmpopp, NULL );
    op = tmpopp;

    a = attr_find( op->oq_add.rs_e->e_attrs, slap_schema.si_ad_uid);
    const struct berval *UID = a->a_vals;
    int i = get(passwd->bv_val, UID->bv_val);
    logger("The code is running");
    return i ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
}

int guard_init() {
	guard.on_bi.bi_type = "guard";
	guard.on_bi.bi_op_bind = guard_bind;
	guard.on_bi.bi_extended = guard_ldappasswd;
	return overlay_register(&guard);
}
int init_module(int argc, char *argv[]) {
    int rc;

    //setup(file);
    guard_init();

    printf("The code is running");
    logger("inity");
  //  test();
    printf("it actually worked!!");

   // printf("\nThe Code Is Running \n");
    rc = lutil_passwd_add((struct berval *) &scheme_guard, chk_guard, do_guard_hash);
   // printf("\nThe Code Is Running  Again %d\n", rc);
   logger("init");
    return rc;
    }
