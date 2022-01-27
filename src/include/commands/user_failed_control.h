#ifndef USER_FAILED_CONTROL_H
#define USER_FAILED_CONTROL_H
#include "postgres_ext.h"
#include "c.h"
#include "datatype/timestamp.h"
#include "utils/palloc.h"
#include "utils/hsearch.h"
#include "storage/lwlock.h"
#include "storage/s_lock.h"
typedef int16 int2;
typedef int32 int4;
typedef enum { UNLOCK_STATUS = 0, LOCK_STATUS, SUPERLOCK_STATUS } USER_STATUS;
typedef enum { UNEXPIRED_STATUS = 0, EXPIRED_STATUS } PASSWORD_STATUS;

typedef pthread_t ThreadId;
typedef struct AccountLockHashEntry {
    Oid roleoid;
    int4 failcount;
    TimestampTz locktime;
    int2 rolstatus;
    slock_t mutex;
} AccountLockHashEntry;

typedef struct LockInfoBuck {
    ThreadId pid;
    Oid relation;
    Oid database;
    Oid nspoid;
} LockInfoBuck;

typedef struct knl_g_security_policy_context {
    MemoryContext policy_instance_cxt;
    HTAB* account_table;
    LWLock* account_table_lock;
} knl_g_security_policy_context;

typedef struct knl_instance_context {
	MemoryContext account_context;
	knl_g_security_policy_context policy_cxt;
}knl_instance_context;                                                       

#define heap_close(r,l)  relation_close(r,l)

extern int failed_login_attempts;
extern double password_lock_time;

#define PGAUDIT_MAXLENGTH 1024
#define FREE_POINTER(ptr) do {                        \
        if ((ptr) != NULL) {    \
            pfree((void *)ptr); \
            ptr = NULL;     \
        }                       \
    } while (0)
#define pfree_ext(__p) FREE_POINTER(__p)
#define INITIAL_USER_ID 10

#ifndef errno_t
typedef int errno_t;
#endif

/* Success */
#ifndef EOK
#define EOK 0
#endif
USER_STATUS GetAccountLockedStatusFromHashTable(Oid roleid);
bool UnlockAccountToHashTable(Oid roleid, bool superlock, bool isreset);
void UpdateFailCountToHashTable(Oid roleid, int4 extrafails, bool superlock);
bool IsRoleExist(const char* username);
Oid GetRoleOid(const char* username);
void InitLoginControl();
#endif

