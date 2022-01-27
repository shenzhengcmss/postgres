#ifndef PG_USER_STATUS_H
#define PG_USER_STATUS_H

#include "catalog/genbki.h"
#include "catalog/pg_user_status_d.h"
CATALOG(pg_user_status,4760,UserStatusRelationId) BKI_SHARED_RELATION BKI_ROWTYPE_OID(4763,UserStatusRelation_Rowtype_Id) BKI_SCHEMA_MACRO
{
	Oid roloid;             /* role OID */
	int32 failcount;         /* failed num of login attampts */
#ifdef CATALOG_VARLEN
	timestamptz locktime;   /* role lock time */
#endif
	int16 rolstatus;         /* role status */
	int64 permspace;             /* perm space */
	int64 tempspace;         /* temp space */
	int16 passwordexpired;   /* password expired status */
} FormData_pg_user_status;

typedef FormData_pg_user_status *Form_pg_user_status;

DECLARE_UNIQUE_INDEX(pg_user_status_index, 4761, on pg_user_status using btree(roloid oid_ops));
#define UserStatusIndexId  4761

#endif      
