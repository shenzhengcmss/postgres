#include "commands/user_failed_control.h"
#include "catalog/pg_user_status.h"
#include "utils/memutils.h"
#include "storage/lwlocknames.h"
#include "postgres.h"
#include "utils/relcache.h"
#include "access/tupdesc.h"
#include "access/heapam.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "common/hashfn.h"
#include "utils/fmgrprotos.h"
#include "catalog/pg_authid.h"
#include "utils/timestamp.h"
#include "miscadmin.h"

knl_instance_context g_instance;
int failed_login_attempts;
double password_lock_time;

void InitLoginControl() 
{
	g_instance.account_context = AllocSetContextCreate(CurrentMemoryContext,
								   "StandbyAccontContext",
								   ALLOCSET_DEFAULT_SIZES);
	g_instance.policy_cxt.account_table_lock = LoginControlLock;
}

static int64 SearchAllAccounts()
{
    Relation pg_user_status_rel = NULL;
    TupleDesc pg_user_status_dsc = NULL;
    HeapScanDesc scan = NULL;
    HeapTuple tuple = NULL;
    Datum roleid_datum;
    bool is_roleid_null = false;
    int64 num = 0;

    /* get the tuple of pg_user_status */
    pg_user_status_rel = RelationIdGetRelation(UserStatusRelationId);

    /* if the relation is valid, get the tuple of roleID*/
    if (RelationIsValid(pg_user_status_rel)) {
        LockRelationOid(UserStatusRelationId, RowExclusiveLock);
        pgstat_initstats(pg_user_status_rel);
        pg_user_status_dsc = RelationGetDescr(pg_user_status_rel);
        scan = (HeapScanDesc)heap_beginscan(pg_user_status_rel, &CatalogSnapshotData, 0, NULL, NULL, 0);

        while ((tuple = heap_getnext((TableScanDesc)scan, ForwardScanDirection)) != NULL) {
            /* Database Security: Support database audit */
            roleid_datum = heap_getattr(tuple, Anum_pg_user_status_roloid, pg_user_status_dsc, &is_roleid_null);
            if (!(is_roleid_null || (void*)roleid_datum == NULL)) {
                HeapTuple tupleForSeachCache = NULL;
                tupleForSeachCache = SearchSysCache1(AUTHOID, roleid_datum);
                /* if user was not found in AUTHOID,we just do nothing.Because*/
                if (!HeapTupleIsValid(tupleForSeachCache)) {
                    continue;
                }
                num++;
                ReleaseSysCache(tupleForSeachCache);
            }
        }

        heap_endscan((TableScanDesc)scan);
        AcceptInvalidationMessages();
        (void)GetCurrentCommandId(true);
        CommandCounterIncrement();
        heap_close(pg_user_status_rel, NoLock);
    } else {
        ereport(WARNING, (errmsg("the relation pg_user_status is invalid")));
    }
    return num;
}

static void InitAccountLockHashTable()
{
    HASHCTL hctl;
    int64 account_num = 0;
#define INIT_ACCOUNT_NUM 10

    LWLockAcquire(g_instance.policy_cxt.account_table_lock, LW_EXCLUSIVE);

    if (g_instance.policy_cxt.account_table != NULL) {
        LWLockRelease(g_instance.policy_cxt.account_table_lock);
        return;
    }

    account_num = SearchAllAccounts();
    if (account_num < INIT_ACCOUNT_NUM) {
        account_num = INIT_ACCOUNT_NUM;
    }

    memset(&hctl, 0, sizeof(HASHCTL));
    hctl.keysize = sizeof(Oid);
    hctl.entrysize = sizeof(AccountLockHashEntry);
    hctl.hash = oid_hash;
    hctl.hcxt = g_instance.account_context;
    g_instance.policy_cxt.account_table = hash_create("User login info",
        account_num,
        &hctl,
        HASH_ELEM | HASH_FUNCTION | HASH_SHRCTX);

    LWLockRelease(g_instance.policy_cxt.account_table_lock);
}

USER_STATUS GetAccountLockedStatusFromHashTable(Oid roleid)
{
    AccountLockHashEntry *account_entry = NULL;
    bool found = false;
    USER_STATUS rolestatus = UNLOCK_STATUS;

    if (g_instance.policy_cxt.account_table == NULL) {
        InitAccountLockHashTable();
    }

    account_entry = (AccountLockHashEntry *)hash_search(g_instance.policy_cxt.account_table, &roleid, HASH_FIND, &found);
    if (found == true) {
        SpinLockAcquire(&account_entry->mutex);
        rolestatus = (USER_STATUS)(account_entry->rolstatus);
        SpinLockRelease(&account_entry->mutex);
    }
    return rolestatus;
}

void FillAccountRecord(AccountLockHashEntry *account_entry, TupleDesc pg_user_status_dsc, HeapTuple tuple, 
                    Datum *user_status_record, bool *user_status_record_repl) {
    Datum userStatusDatum;
    bool userStatusIsNull = false;
    int32 failcount_in_catalog = account_entry->failcount;
    const char* locktime_in_catalog = NULL;
    bool catalog_superlock = false;
    bool catalog_lock = false;
    
    userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_failcount, pg_user_status_dsc, &userStatusIsNull);
    if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
        failcount_in_catalog += DatumGetInt32(userStatusDatum);
    }

    userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_rolstatus, pg_user_status_dsc, &userStatusIsNull);
    if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
        if (DatumGetInt16(userStatusDatum) == SUPERLOCK_STATUS) {
            catalog_superlock = true;
        } else if (DatumGetInt16(userStatusDatum) == LOCK_STATUS) {
            catalog_lock = true;
        }
    }

    if (catalog_superlock == false) {
        if (account_entry->rolstatus == SUPERLOCK_STATUS) {
            locktime_in_catalog = timestamptz_to_str(account_entry->locktime);
            user_status_record[Anum_pg_user_status_locktime - 1] = DirectFunctionCall3(
                timestamptz_in, CStringGetDatum(locktime_in_catalog), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
            user_status_record_repl[Anum_pg_user_status_locktime - 1] = true;
            user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(SUPERLOCK_STATUS);
            user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;
        } else if (catalog_lock == false) {
            if (account_entry->rolstatus == LOCK_STATUS) {
                locktime_in_catalog = timestamptz_to_str(account_entry->locktime);
                user_status_record[Anum_pg_user_status_locktime - 1] = DirectFunctionCall3(
                    timestamptz_in, CStringGetDatum(locktime_in_catalog), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
                user_status_record_repl[Anum_pg_user_status_locktime - 1] = true;
                user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(LOCK_STATUS);
                user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;
            } else if (failed_login_attempts > 0 && 
                failcount_in_catalog >= failed_login_attempts) {
                /* The sum of failcount in hash table and pg_user_status > Failed_login_attempts, update rolestatus*/
                user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(LOCK_STATUS);
                user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;
                TimestampTz nowTime = GetCurrentTimestamp();
                locktime_in_catalog = timestamptz_to_str(nowTime);
                user_status_record[Anum_pg_user_status_locktime - 1] = DirectFunctionCall3(
                    timestamptz_in, CStringGetDatum(locktime_in_catalog), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
                user_status_record_repl[Anum_pg_user_status_locktime - 1] = true;
            }
        }
    }

    user_status_record[Anum_pg_user_status_failcount - 1] = Int32GetDatum(failcount_in_catalog);
    user_status_record_repl[Anum_pg_user_status_failcount - 1] = true;
}


void UpdateAccountInfoFromHashTable()
{
    AccountLockHashEntry *account_entry = NULL;
    HASH_SEQ_STATUS hseq_status;

    Relation pg_user_status_rel = NULL;
    TupleDesc pg_user_status_dsc = NULL;
    HeapTuple tuple = NULL;
    HeapTuple new_tuple = NULL;

    /* get tuple of pg_user_status*/
    pg_user_status_rel = RelationIdGetRelation(UserStatusRelationId);
    /* if the relation is valid, get the tuple of roleID*/
    if (RelationIsValid(pg_user_status_rel)) {
        LockRelationOid(UserStatusRelationId, RowExclusiveLock);
        pgstat_initstats(pg_user_status_rel);
        pg_user_status_dsc = RelationGetDescr(pg_user_status_rel);

        hash_seq_init(&hseq_status, g_instance.policy_cxt.account_table);
        while ((account_entry = (AccountLockHashEntry*)hash_seq_search(&hseq_status)) != NULL) {
            tuple = SearchSysCache1(USERSTATUSROLEID, PointerGetDatum(account_entry->roleoid));
            if (HeapTupleIsValid(tuple)) {
                Datum user_status_record[Natts_pg_user_status] = {0};
                bool user_status_record_nulls[Natts_pg_user_status] = {false};
                bool user_status_record_repl[Natts_pg_user_status] = {false};
                FillAccountRecord(account_entry, pg_user_status_dsc, tuple, user_status_record, user_status_record_repl);
                new_tuple = (HeapTuple) heap_modify_tuple(
                    tuple, pg_user_status_dsc, user_status_record, user_status_record_nulls, user_status_record_repl);
                heap_inplace_update(pg_user_status_rel, new_tuple);
                CacheInvalidateHeapTuple(pg_user_status_rel, tuple, new_tuple);
                heap_freetuple(new_tuple);
                ReleaseSysCache(tuple);
            }
            hash_search(g_instance.policy_cxt.account_table, &(account_entry->roleoid), HASH_REMOVE, NULL);
        }
        AcceptInvalidationMessages();
        heap_close(pg_user_status_rel, NoLock);
    }
}

/* Get the status of account. */
USER_STATUS GetAccountLockedStatus(Oid roleID)
{
    uint16 status = 0;
    Datum userStatusDatum;
    bool userStatusIsNull = false;

    if (!OidIsValid(roleID)) {
        ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("getAccountLockedStyle: roleid is not valid.")));
    }

    if (g_instance.policy_cxt.account_table != NULL) {
        /* Update user status info from hash table to pg_user_status table. We only update once
         * when the first time user connect to get user lock status after dn became primary. To deal
         * with concurrent scenarios, check hash table not null again after we get hash table lock.
         */
        (void)LWLockAcquire(g_instance.policy_cxt.account_table_lock, LW_EXCLUSIVE);
        if (g_instance.policy_cxt.account_table != NULL) {
            UpdateAccountInfoFromHashTable();
            hash_destroy(g_instance.policy_cxt.account_table);
            g_instance.policy_cxt.account_table = NULL;
        }
        LWLockRelease(g_instance.policy_cxt.account_table_lock);
    }

    HeapTuple tuple = SearchSysCache1(USERSTATUSROLEID, PointerGetDatum(roleID));
    if (!HeapTupleIsValid(tuple)) {
        status = UNLOCK_STATUS;
    } else {
        userStatusDatum = SysCacheGetAttr(USERSTATUSROLEID, tuple, Anum_pg_user_status_rolstatus, &userStatusIsNull);
        if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
            status = DatumGetInt16(userStatusDatum);
        } else {
            status = UNLOCK_STATUS;
        }
        ReleaseSysCache(tuple);
    }

    return (USER_STATUS)status;
}

static bool LockAccountParaValid(Oid roleID, int extrafails, bool superlock)
{
#define INITUSER_OID 10

    if (!OidIsValid(roleID)) {
        ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("TryLockAccount(): roleid is not valid.")));
        return false;
    }

    if (INITUSER_OID == roleID) {
        if (superlock)
            ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("Permission denied.")));
        return false;
    }

    if (extrafails < 0) {
        ereport(ERROR,
            (errcode(ERRCODE_DATA_EXCEPTION), errmsg("TryLockAccount(): parameter extrafails is less than zero.")));
        return false;
    }
    return true;
}

/*
 * Brief            : void pgaudit_lock_or_unlock_user(bool islocked,const char* user_name)
 * Description  : audit lock or unlock user
 */
static void pgaudit_lock_or_unlock_user(bool islocked, const char* user_name)
{
    char details[PGAUDIT_MAXLENGTH] = {0};
    if (user_name == NULL) {
        user_name = "UNKOWN USER";
    }
    if (islocked) {
        pg_snprintf(details, sizeof(details), "the user(%s) has been locked", user_name);
    } else {
        pg_snprintf(details, sizeof(details), "the user(%s) has been unlocked", user_name);
    }
    //audit_report(audit_type, audit_result, user_name, details);
}

static void ReportLockAccountMessage(bool locked, const char *rolename)
{
    if (locked) {
        pgaudit_lock_or_unlock_user(true, rolename);
    }

    AcceptInvalidationMessages();
    (void)GetCurrentCommandId(true);
    CommandCounterIncrement();
}

void UpdateFailCountToHashTable(Oid roleid, int4 extrafails, bool superlock)
{
    AccountLockHashEntry *account_entry = NULL;
    bool found = false;
    /* Audit user locked or unlocked */
    bool lockflag = 0;
    char* rolename = NULL;

    if (!LockAccountParaValid(roleid, extrafails, superlock)) {
        return;
    }
    rolename = GetUserNameFromId(roleid,false);

    if (g_instance.policy_cxt.account_table == NULL) {
        InitAccountLockHashTable();
    }

    account_entry = (AccountLockHashEntry *)hash_search(g_instance.policy_cxt.account_table, &roleid, HASH_ENTER, &found);
    if (found == false) {
        SpinLockInit(&account_entry->mutex);
    }

    SpinLockAcquire(&account_entry->mutex);
    if (found == false) {
        account_entry->failcount = extrafails;
        account_entry->rolstatus = UNLOCK_STATUS;
    } else {
        account_entry->failcount += extrafails;
        if (failed_login_attempts > 0 && 
            account_entry->failcount >= failed_login_attempts) {
            lockflag = true;
        }
    }

    /* super lock account or exceed failed limit */
    if (extrafails == 0 || lockflag == true) {
        account_entry->rolstatus = superlock ? SUPERLOCK_STATUS : LOCK_STATUS;
        account_entry->locktime = GetCurrentTimestamp();
        lockflag = true;
        ereport(DEBUG2, (errmsg("%s locktime %s", rolename, timestamptz_to_str(account_entry->locktime))));
    }
    ereport(DEBUG2, (errmsg("%s failcount %d, rolstatus %d", rolename, account_entry->failcount, account_entry->rolstatus)));
    SpinLockRelease(&account_entry->mutex);

    ReportLockAccountMessage(lockflag, rolename);
}


/* Database Security: Support lock/unlock account */
/*
 * Brief			: try to lock the account, just update the pg_user_status
 * Description		: if the roleID is not exist in pg_user_status, then add the record
 *				: if the roleID is exist in pg_user_status, then update the record
 * Notes			:
 */
void TryLockAccount(Oid roleID, int extrafails, bool superlock)
{
    Relation pg_user_status_rel = NULL;
    TupleDesc pg_user_status_dsc = NULL;
    HeapTuple tuple = NULL;
    HeapTuple new_tuple = NULL;
    const char* currentTime = NULL;
    TimestampTz nowTime;
    int32 failedcount = 0;
    int16 status = 0;
    Datum userStatusDatum;
    bool userStatusIsNull = false;
    Datum user_status_record[Natts_pg_user_status];
    bool user_status_record_nulls[Natts_pg_user_status] = {false};
    bool user_status_record_repl[Natts_pg_user_status] = {false};

    /* Audit user locked or unlocked */
    bool lockflag = 0;
    char* rolename = NULL;

    /* We could not insert new xlog if recovery in process */
    if (RecoveryInProgress()) {
        return;
    }

    if (!LockAccountParaValid(roleID, extrafails, superlock)) {
        return;
    }

    rolename = GetUserNameFromId(roleID,false);

    /* get tuple of pg_user_status*/
    pg_user_status_rel = RelationIdGetRelation(UserStatusRelationId);

    /* if the relation is valid, get the tuple of roleID*/
    if (RelationIsValid(pg_user_status_rel)) {
        LockRelationOid(UserStatusRelationId, RowExclusiveLock);
        pgstat_initstats(pg_user_status_rel);
        pg_user_status_dsc = RelationGetDescr(pg_user_status_rel);
        tuple = SearchSysCache1(USERSTATUSROLEID, PointerGetDatum(roleID));

        /* insert/update a new login failed record into the pg_user_status */
        memset(user_status_record, 0, sizeof(user_status_record));
        memset(user_status_record_nulls, false, sizeof(user_status_record_nulls));
		memset(user_status_record_repl, false, sizeof(user_status_record_repl));

        /* if there is no record of the role, then add one record in the pg_user_status */
        if (HeapTupleIsValid(tuple)) {
            userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_failcount, pg_user_status_dsc, &userStatusIsNull);
            if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
                failedcount = DatumGetInt32(userStatusDatum);
            } else {
                failedcount = 0;
            }
            failedcount += extrafails;
            userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_rolstatus, pg_user_status_dsc, &userStatusIsNull);
            if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
                status = DatumGetInt16(userStatusDatum);
            } else {
                status = UNLOCK_STATUS;
            }

            /* if superuser try lock, just update the status */
            if (superlock && status != SUPERLOCK_STATUS) {
                nowTime = GetCurrentTimestamp();
                currentTime = timestamptz_to_str(nowTime);
                user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(SUPERLOCK_STATUS);
                user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;
                user_status_record[Anum_pg_user_status_locktime - 1] = DirectFunctionCall3(
                    timestamptz_in, CStringGetDatum(currentTime), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
                user_status_record_repl[Anum_pg_user_status_locktime - 1] = true;
                user_status_record[Anum_pg_user_status_failcount - 1] = Int32GetDatum(failedcount);
                user_status_record_repl[Anum_pg_user_status_failcount - 1] = true;
                lockflag = 1;
            } else {
                /* Update the failedcount, only when the account is not locked */
                if (status == UNLOCK_STATUS) {
                    user_status_record[Anum_pg_user_status_failcount - 1] = Int32GetDatum(failedcount);
                    user_status_record_repl[Anum_pg_user_status_failcount - 1] = true;
                }
                /* if account is not locked and the failedcount is larger than
                   u_sess->attr.attr_security.Failed_login_attempts, update the lock time and status */
                if (failed_login_attempts > 0 &&
                    failedcount >= failed_login_attempts && status == UNLOCK_STATUS) {
                    nowTime = GetCurrentTimestamp();
                    currentTime = timestamptz_to_str(nowTime);
                    user_status_record[Anum_pg_user_status_locktime - 1] = DirectFunctionCall3(
                        timestamptz_in, CStringGetDatum(currentTime), ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
                    user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(LOCK_STATUS);
                    user_status_record_repl[Anum_pg_user_status_locktime - 1] = true;
                    user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;
                    lockflag = 1;
                }
            }
						new_tuple = (HeapTuple) heap_modify_tuple(tuple, pg_user_status_dsc, user_status_record, user_status_record_nulls, user_status_record_repl);
            heap_inplace_update(pg_user_status_rel, new_tuple);
						CacheInvalidateHeapTuple(pg_user_status_rel, tuple, new_tuple);
            heap_freetuple(new_tuple);
            ReleaseSysCache(tuple);
        } else {
            /* if the record is already exist, update the record */
            ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("The tuple of pg_user_status not found")));
        }

        heap_close(pg_user_status_rel, RowExclusiveLock);

    } else {
        ereport(WARNING, (errmsg("the relation pg_user_status is invalid")));
        return;
    }

    ReportLockAccountMessage(lockflag, rolename);
}

static void UpdateUnlockAccountTuples(HeapTuple tuple, Relation rel, TupleDesc tupledesc)
{
    HeapTuple new_tuple = NULL;
    Datum user_status_record[Natts_pg_user_status];
    bool user_status_record_nulls[Natts_pg_user_status] = {false};
    bool user_status_record_repl[Natts_pg_user_status] = {false};
    
    memset(user_status_record, 0, sizeof(user_status_record));
    memset(user_status_record_nulls, 0, sizeof(user_status_record_nulls));
    memset(user_status_record_repl,0, sizeof(user_status_record_repl));

    user_status_record[Anum_pg_user_status_failcount - 1] = Int32GetDatum(0);
    user_status_record_repl[Anum_pg_user_status_failcount - 1] = true;
    user_status_record[Anum_pg_user_status_rolstatus - 1] = Int16GetDatum(UNLOCK_STATUS);
    user_status_record_repl[Anum_pg_user_status_rolstatus - 1] = true;

    new_tuple =
        (HeapTuple) heap_modify_tuple(tuple, tupledesc, user_status_record, user_status_record_nulls, user_status_record_repl);
    heap_inplace_update(rel, new_tuple);
    heap_freetuple(new_tuple);
}

static TimestampTz GetPasswordTimeOfTuple(TimestampTz nowTime, TimestampTz* fromTime, Datum userStatusDatum, HeapTuple tuple,
    TupleDesc pg_user_status_dsc, bool* userStatusIsNull)
{
    Datum fromTimeDatum;
    Interval tspan;
    TimestampTz lockTime = 0;

    /* we transform the u_sess->attr.attr_security.Password_lock_time to days and seconds */
    tspan.month = 0;
    tspan.day = (int)floor(password_lock_time);
#ifdef HAVE_INT64_TIMESTAMP
    tspan.time =
        (password_lock_time - tspan.day) * HOURS_PER_DAY * SECS_PER_HOUR * USECS_PER_SEC;
#else
    tspan.time = (password_lock_time - tspan.day) * HOURS_PER_DAY * SECS_PER_HOUR;
#endif

    /* get the fromTime */
    fromTimeDatum = DirectFunctionCall2(timestamptz_mi_interval, TimestampGetDatum(nowTime), PointerGetDatum(&tspan));
    *fromTime = DatumGetTimestampTz(fromTimeDatum);

    userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_locktime, pg_user_status_dsc, userStatusIsNull);
    /* get the passwordtime of tuple */
    if ((*userStatusIsNull) || (void*)userStatusDatum == NULL) {
        lockTime = 0;
    } else {
        lockTime = DatumGetTimestampTz(userStatusDatum);
    }

    return lockTime;
}


/*
 * Brief			: try to unlock the account
 * Description		: if satisfied unlock conditions, delete the record of the role
 * Notes			:
 */
bool TryUnlockAccount(Oid roleID, bool superunlock, bool isreset)
{
    Relation pg_user_status_rel = NULL;
    TupleDesc pg_user_status_dsc = NULL;
    TimestampTz nowTime;
    TimestampTz fromTime;
    TimestampTz lockTime;
    int16 status = 0;
    Datum userStatusDatum;
    bool userStatusIsNull = false;
    bool result = false;
    bool unlockflag = 0;
    char* rolename = NULL;

    if (!OidIsValid(roleID)) {
        ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("TryUnlockAccount(): roleid is not valid.")));
    }

#define INITUSER_OID 10
    if (roleID == INITUSER_OID) {
        if (superunlock) {
            ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("Permission denied.")));
        } else {
            return true;
        }
    }

    rolename = GetUserNameFromId(roleID,false);
    /* get the tuple of pg_user_status */
    pg_user_status_rel = RelationIdGetRelation(UserStatusRelationId);

    /* if the relation is valid, get the tuple of roleID */
    if (RelationIsValid(pg_user_status_rel)) {
        LockRelationOid(UserStatusRelationId, RowExclusiveLock);
        pgstat_initstats(pg_user_status_rel);
        pg_user_status_dsc = RelationGetDescr(pg_user_status_rel);

        HeapTuple tuple = SearchSysCache1(USERSTATUSROLEID, PointerGetDatum(roleID));

        /* if the record is not exist, it may be already unlocked by someone else */
        if (!HeapTupleIsValid(tuple)) {
            ereport(WARNING, (errmsg("Invalid roleid in pg_user_status.")));
        } else {
            /* if super user try to unlock, just delete the tuple */
            userStatusDatum = heap_getattr(tuple, Anum_pg_user_status_rolstatus, pg_user_status_dsc, &userStatusIsNull);
            if (!(userStatusIsNull || (void*)userStatusDatum == NULL)) {
                status = DatumGetInt16(userStatusDatum);
            } else {
                status = UNLOCK_STATUS;
            }

            if (superunlock) {
                if (status != UNLOCK_STATUS) {
                    UpdateUnlockAccountTuples(tuple, pg_user_status_rel, pg_user_status_dsc);
                    result = true;
                    unlockflag = 1;
                }
            } else {
                if (status == UNLOCK_STATUS) {
                    if (isreset) {
                        Datum failCountDatum;
                        int failCount = 0;

                        failCountDatum =
                            heap_getattr(tuple, Anum_pg_user_status_failcount, pg_user_status_dsc, &userStatusIsNull);
                        if (userStatusIsNull || (void*)failCountDatum == NULL) {
                            failCount = 0;
                        } else {
                            failCount = DatumGetTimestampTz(failCountDatum);
                        }

                        if (failCount > 0)
                            UpdateUnlockAccountTuples(tuple, pg_user_status_rel, pg_user_status_dsc);
                    }
                    result = true;
                } else if (status == SUPERLOCK_STATUS) {
                    result = false;
                } else {
                    /* get current time */
                    nowTime = GetCurrentTimestamp();
                    lockTime = GetPasswordTimeOfTuple(
                        nowTime, &fromTime, userStatusDatum, tuple, pg_user_status_dsc, &userStatusIsNull);
                    if (lockTime < fromTime) {
                        UpdateUnlockAccountTuples(tuple, pg_user_status_rel, pg_user_status_dsc);
                        result = true;
                        unlockflag = 1;
                    } else {
                        result = false;
                    }
                }
            }
            ReleaseSysCache(tuple);
        }
        AcceptInvalidationMessages();
        (void)GetCurrentCommandId(true);
        CommandCounterIncrement();
        heap_close(pg_user_status_rel, RowExclusiveLock);
        if (unlockflag) {
            pgaudit_lock_or_unlock_user(false, rolename);
        }
    } else {
        ereport(WARNING, (errmsg("the relation pg_user_status is invalid")));
    }

    return result;
}



/*

 * Report error according to the return value.
 * At the same time, we should free the space alloced by developers.
 */
static void freeSecurityFuncSpace(char* charList, ...)
{
    va_list argptr;

    /* if the first parameter is not empty */
    if (strcmp(charList, "\0") != 0) {
        /* free the first charList */
        pfree_ext(charList);

        /* if have move charList */
        va_start(argptr, charList);
        while (true) {
            char* szBuf = va_arg(argptr, char*);
            if (strcmp(szBuf, "\0") == 0) /* empty string */
                break;
            pfree_ext(szBuf);
        }
        va_end(argptr);
    }

    return;
}

/*
 * Brief			: Get the roleid through username
 * Description		:
 * Notes			:
 */
bool IsRoleExist(const char* username)
{
    bool result = false;
    HeapTuple tuple = NULL;
    HOLD_INTERRUPTS();
    tuple = SearchSysCache1(AUTHNAME, PointerGetDatum(username));
    RESUME_INTERRUPTS();
    CHECK_FOR_INTERRUPTS();
    if (HeapTupleIsValid(tuple)) {
        ReleaseSysCache(tuple);
        result = true;
    }
    return result;
}

/*
 * Brief			: Get the roleid through username
 * Description		:
 * Notes			:
 */
Oid GetRoleOid(const char* username)
{
    HeapTuple tuple = NULL;
    Oid roleID = 0;
    tuple = SearchSysCache1(AUTHNAME, PointerGetDatum(username));
    if (!HeapTupleIsValid(tuple)) {
        ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("Invalid username/password,login denied.")));
    }
	Form_pg_authid roleform;
	roleform = (Form_pg_authid) GETSTRUCT(tuple);
	roleID = roleform->oid;
    ReleaseSysCache(tuple);
    return roleID;
}

static bool CanUnlockAccount(TimestampTz locktime)
{
    TimestampTz now_time;
    TimestampTz from_time;
    Datum from_time_datum;
    Interval tspan;

    tspan.month = 0;
    tspan.day = (int)floor(password_lock_time);
#ifdef HAVE_INT64_TIMESTAMP
    tspan.time =
        (password_lock_time - tspan.day) * HOURS_PER_DAY * SECS_PER_HOUR * USECS_PER_SEC;
#else
    tspan.time = (password_lock_time - tspan.day) * HOURS_PER_DAY * SECS_PER_HOUR;
#endif

    now_time = GetCurrentTimestamp();
    from_time_datum = DirectFunctionCall2(timestamptz_mi_interval, TimestampGetDatum(now_time), PointerGetDatum(&tspan));
    from_time = DatumGetTimestampTz(from_time_datum);
    if (locktime < from_time) {
        return true;
    } else {
        return false;
    }
}

bool UnlockAccountToHashTable(Oid roleid, bool superlock, bool isreset)
{
    bool found = false;
    AccountLockHashEntry *account_entry = NULL;
    int2 status;

    /* user account has not been locked if account_table is null */
    if (g_instance.policy_cxt.account_table == NULL) {
        char* relName = NULL;
        relName = get_rel_name(roleid);
        if (relName != NULL) {
            ereport(NOTICE, (errmsg("user account %s has not been locked", relName)));
        }
        return true;
    }

    account_entry = (AccountLockHashEntry *)hash_search(g_instance.policy_cxt.account_table, &roleid, HASH_FIND, &found);
    if (found) {
        SpinLockAcquire(&account_entry->mutex);
        status = account_entry->rolstatus;
        if (superlock) {
            account_entry->rolstatus = UNLOCK_STATUS;
            account_entry->failcount = 0;
            SpinLockRelease(&account_entry->mutex);
            ereport(DEBUG2, (errmsg("super unlock account %u", roleid)));
            return true;
        } else {
            if (status == SUPERLOCK_STATUS) {
                SpinLockRelease(&account_entry->mutex);
                return false;
            }
            if (status == UNLOCK_STATUS) {
                if (isreset) {
                    account_entry->failcount = 0;
                }
                SpinLockRelease(&account_entry->mutex);
                return true;
            }
            if (CanUnlockAccount(account_entry->locktime)) {
                account_entry->failcount = 0;
                account_entry->rolstatus = UNLOCK_STATUS;
                SpinLockRelease(&account_entry->mutex);
                return true;
            }
            SpinLockRelease(&account_entry->mutex);
            return false;
        }
    }
    return true;
}

/*
 * Brief		    : void pgaudit_user_login(bool login_ok, char* object_name,const char* detaisinfo)
 * Description	: audit the user login
 */
static void pgaudit_user_login(bool login_ok, const char* object_name, const char* detaisinfo)
{
    Assert(detaisinfo);
    if (login_ok) {
    } else {
    }
}
