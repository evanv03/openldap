#include <unistd.h>
#include "lutil.h"
#include <lber.h>
#include <lber_pvt.h>
#include <ac/string.h>
#include "guardlib.h"
#include "assert.h"
#include <unistd.h>
#include <stdio.h>

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

static int do_guard_hash(const struct berval *passwd, const struct berval *salt, struct berval *cred, const char **digest) {
	char * thing = malloc(5);
	thing [0] = 'H';
	thing [1] = 'E';
	thing [2] = 'L';
	thing [3] = 'L';
	thing [4] = 'O';
	char fakeuser[5] = {'U', 'S', 'E', 'R'};
	char fakepass[5] = {'F', 'A', 'K', 'E', 'S'};
	printf("\n The Code Is Running 1\n");
	logger("hash");
	int i = setpass(cred->bv_val, passwd->bv_val, thing);
	logger(passwd->bv_val);
	logger("hashdone");
    printf("The code is running");
 /*   LDAP_LUTIL_F( int ) it;
    it = 0;
    return it; */
   // LDAP_LUTIL_F( int ) out = ((LDAP_LUTIL_F( int ))0);
    return LUTIL_PASSWD_ERR;
}

static int chk_guard(const struct berval *passwd, const struct berval *salt, const struct berval *cred, const char **digest) {
	printf("\n The Code Is Running 2 \n");
	logger("guard");
    int i = get(cred->bv_val, passwd->bv_val);
    printf("The code is running");
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