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
//#include "libtest.h"
static const struct berval scheme_guard = BER_BVC("{GUARD}");
static LUTIL_PASSWD_CHK_FUNC chk_guard;
static LUTIL_PASSWD_HASH_FUNC do_guard_hash;

static void logger(char *str){
    FILE *f;
    f = fopen("/tmp/evango.log", "a");

    fprintf(f, "%s\n", str);
    fclose(f);
}

static int do_guard_hash(const struct berval *scheme, const struct berval *passwd, struct berval *hash, const char **text) {
	char * thing = malloc(5);
	thing [0] = 'H';
	thing [1] = 'E';
	thing [2] = 'L';
	thing [3] = 'L';
	thing [4] = 'O';
	printf("\n The Code Is Running 1\n");
	logger("hash");
	int i = setpass(scheme->bv_val, passwd->bv_val, hash->bv_val);
	logger(passwd->bv_val);
	logger("hash is done");
    printf("The code is running");
 /*   LDAP_LUTIL_F( int ) it;
    it = 0;
    return it; */
   // LDAP_LUTIL_F( int ) out = ((LDAP_LUTIL_F( int ))0);
    unsigned char digest_buf[LUTIL_MD5_BYTES];
    struct berval digest;
    digest.bv_val = (char *) digest_buf;
    digest.bv_len = sizeof(digest_buf);
    FILE *f;
    f = fopen("/tmp/evango.log", "a");
    fprintf(f, "\n%d\n", lutil_passwd_string64(scheme, &digest, hash, passwd));
	return lutil_passwd_string64(scheme, &digest, hash, passwd);
}

static int chk_guard(const struct berval *scheme, const struct berval *passwd, const struct berval *cred, const char **digest) {
	printf("\n The Code Is Running 2 \n");
	logger("guard");
    int i = get(passwd->bv_val, cred->bv_val);
    logger("The code is running");
    return i ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
    int rc;
    //setup(file);

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