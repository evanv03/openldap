/* bind.c - shell backend bind function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "shell.h"

int
shell_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Entry e;
	FILE			*rfp, *wfp;
	int			rc;

	if ( si->si_bind == NULL ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
		    "bind not implemented" );
		return( -1 );
	}

	e.e_id = NOID;
	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;
	e.e_attrs = NULL;
	e.e_ocflags = 0;
	e.e_bv.bv_len = 0;
	e.e_bv.bv_val = NULL;
	e.e_private = NULL;

	if ( ! access_allowed( op, &e,
		entry, NULL, ACL_AUTH, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( forkandexec( si->si_bind, &rfp, &wfp ) == (pid_t)-1 ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not fork/exec" );
		return( -1 );
	}

	/* write out the request to the bind process */
	fprintf( wfp, "BIND\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, op->o_bd );
	fprintf( wfp, "dn: %s\n", op->o_req_dn.bv_val );
	fprintf( wfp, "method: %d\n", op->oq_bind.rb_method );
	fprintf( wfp, "credlen: %lu\n", op->oq_bind.rb_cred.bv_len );
	fprintf( wfp, "cred: %s\n", op->oq_bind.rb_cred.bv_val ); /* XXX */
	fclose( wfp );

	/* read in the results and send them along */
	rc = read_and_send_results( op, rs, rfp );
	fclose( rfp );

	return( rc );
}
