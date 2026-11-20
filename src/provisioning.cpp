#include "provisioning.hpp"

#include <cstring>

#include "pg_utils.hpp"

extern "C" {
#include "postgres.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/pg_database.h"
#include "catalog/pg_type_d.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "port/atomics.h"
#include "postmaster/bgworker.h"
#include "postmaster/postmaster.h"
#include "storage/dsm.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/procarray.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"
#include "utils/wait_event.h"

PGDLLEXPORT void pg_oidc_provision_worker(Datum main_arg);
}

namespace {

constexpr uint32 request_magic = 0x4f494443;
constexpr std::size_t request_capacity = 32768;
constexpr uint32 pending = 0;
constexpr uint32 accepted = 1;
constexpr uint32 denied = 2;
char* management_database = nullptr;

// Only fixed-size, process-independent data belongs in DSM. Atomic result
// publication happens after COMMIT; a false SQL result may commit revocations.
struct ProvisionRequest {
  uint32 magic;
  uint32 length;
  int parent_pid;
  ProcNumber parent_proc;
  LocalTransactionId parent_transaction;
  TimestampTz deadline;
  pg_atomic_uint32 result;
  pg_atomic_uint32 cancelled;
  char database[NAMEDATALEN];
  char json[request_capacity];
};

struct ProvisionCleanup {
  dsm_segment* segment;
  BackgroundWorkerHandle* worker;
};

bool check_management_database(char** value, void**, GucSource) {
  if (strlen(*value) >= NAMEDATALEN || strcmp(*value, "template0") == 0 || strcmp(*value, "template1") == 0) {
    GUC_check_errmsg("OAuth provisioning requires a non-template management database name shorter than NAMEDATALEN.");
    return false;
  }
  return true;
}

void cleanup_request(int, Datum argument) {
  auto* cleanup = reinterpret_cast<ProvisionCleanup*>(DatumGetPointer(argument));
  if (cleanup->segment != nullptr) {
    auto* request = static_cast<ProvisionRequest*>(dsm_segment_address(cleanup->segment));
    pg_atomic_write_u32(&request->cancelled, 1);
  }
  if (cleanup->worker != nullptr) {
    TerminateBackgroundWorker(cleanup->worker);
    pfree(cleanup->worker);
    cleanup->worker = nullptr;
  }
  if (cleanup->segment != nullptr) {
    dsm_detach(cleanup->segment);
    cleanup->segment = nullptr;
  }
}

void worker_exit(int, Datum argument) {
  auto* request = reinterpret_cast<ProvisionRequest*>(DatumGetPointer(argument));
  uint32 expected = pending;
  pg_atomic_compare_exchange_u32(&request->result, &expected, denied);
}

bool request_is_current(ProvisionRequest* request) {
  CHECK_FOR_INTERRUPTS();
  if (pg_atomic_read_u32(&request->cancelled) != 0 || GetCurrentTimestamp() >= request->deadline) return false;

  // Bind the request to the originating authentication transaction, not merely
  // a reusable PID. This also catches a vanished caller before worker COMMIT.
  LWLockAcquire(ProcArrayLock, LW_SHARED);
  PGPROC* parent = BackendPidGetProcWithLock(request->parent_pid);
  bool alive = parent != nullptr && parent->vxid.procNumber == request->parent_proc &&
               parent->vxid.lxid == request->parent_transaction;
  LWLockRelease(ProcArrayLock);
  return alive;
}

// This executes only in a fully initialized background-worker backend, never
// in the authenticating backend. The SQL function owns identity policy.
bool reconcile(ProvisionRequest* request) {
  SetCurrentStatementStartTimestamp();
  StartTransactionCommand();
  enable_timeout_at(STATEMENT_TIMEOUT, request->deadline);
  PushActiveSnapshot(GetTransactionSnapshot());

  HeapTuple database = SearchSysCache1(DATABASEOID, ObjectIdGetDatum(MyDatabaseId));
  if (!HeapTupleIsValid(database)) ereport(ERROR, (errmsg("OAuth provisioning database is unavailable")));
  bool is_template = reinterpret_cast<Form_pg_database>(GETSTRUCT(database))->datistemplate;
  ReleaseSysCache(database);
  if (is_template || RecoveryInProgress()) ereport(ERROR, (errmsg("OAuth provisioning requires a writable management database")));

  if (SPI_connect() != SPI_OK_CONNECT) ereport(ERROR, (errmsg("OAuth provisioning initialization failed")));
  if (SPI_execute("SET LOCAL search_path = pg_catalog", false, 0) != SPI_OK_UTILITY)
    ereport(ERROR, (errmsg("OAuth provisioning initialization failed")));

  Oid argument_types[] = {TEXTOID};
  Datum arguments[] = {CStringGetTextDatum(request->json)};
  if (SPI_execute_with_args("SELECT oidc_identity.reconcile($1::jsonb)", 1, argument_types, arguments, nullptr,
                            false, 1) != SPI_OK_SELECT ||
      SPI_processed != 1 || SPI_tuptable == nullptr ||
      SPI_gettypeid(SPI_tuptable->tupdesc, 1) != BOOLOID)
    ereport(ERROR, (errmsg("OAuth provisioning returned an invalid result")));

  bool is_null = false;
  Datum result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null);
  bool authorized = !is_null && DatumGetBool(result);
  SPI_finish();
  PopActiveSnapshot();
  if (!request_is_current(request)) ereport(ERROR, (errmsg("OAuth provisioning request expired")));

  // A normal false result may have removed stale privileges: commit it too.
  CommitTransactionCommand();
  disable_timeout(STATEMENT_TIMEOUT, false);
  return authorized;
}

}  // namespace

namespace oidc {

void register_provisioning_settings() {
  DefineCustomStringVariable("pg_oidc_validator.management_database",
                             gettext_noop("Management database containing oidc_identity.reconcile(jsonb)."),
                             gettext_noop("Empty disables identity provisioning; provisioning is primary-only."),
                             &management_database, "", PGC_SIGHUP, 0, check_management_database, nullptr, nullptr);
}

bool provisioning_enabled() { return management_database != nullptr && management_database[0] != '\0'; }

bool provision_identity(const std::string& request_json) {
  if (!provisioning_enabled() || request_json.empty() || request_json.size() >= request_capacity ||
      request_json.find('\0') != std::string::npos)
    return false;

  ProvisionCleanup* cleanup = nullptr;
  bool exit_callback_registered = false;
  bool authorized = false;
  try {
    pg::pg_try([&]() {
      // Reuse the connection's existing deadline, including time already spent
      // validating its token. Never create an unbounded secondary operation.
      if (!ClientAuthInProgress || !get_timeout_active(STATEMENT_TIMEOUT) || RecoveryInProgress()) return;
      TimestampTz deadline = get_timeout_finish_time(STATEMENT_TIMEOUT);
      if (GetCurrentTimestamp() >= deadline) return;

      cleanup = static_cast<ProvisionCleanup*>(MemoryContextAllocZero(TopMemoryContext, sizeof(ProvisionCleanup)));
      before_shmem_exit(cleanup_request, PointerGetDatum(cleanup));
      exit_callback_registered = true;
      cleanup->segment = dsm_create(sizeof(ProvisionRequest), DSM_CREATE_NULL_IF_MAXSEGMENTS);
      if (cleanup->segment == nullptr) return;

      auto* request = static_cast<ProvisionRequest*>(dsm_segment_address(cleanup->segment));
      memset(request, 0, sizeof(*request));
      request->magic = request_magic;
      request->length = static_cast<uint32>(request_json.size());
      request->parent_pid = MyProcPid;
      request->parent_proc = MyProc->vxid.procNumber;
      request->parent_transaction = MyProc->vxid.lxid;
      request->deadline = deadline;
      pg_atomic_init_u32(&request->result, pending);
      pg_atomic_init_u32(&request->cancelled, 0);
      strlcpy(request->database, management_database, sizeof(request->database));
      memcpy(request->json, request_json.c_str(), request_json.size() + 1);

      BackgroundWorker worker = {};
      strlcpy(worker.bgw_name, "OAuth identity provisioning", BGW_MAXLEN);
      strlcpy(worker.bgw_type, "OAuth identity provisioning", BGW_MAXLEN);
      worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
      worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
      worker.bgw_restart_time = BGW_NEVER_RESTART;
      strlcpy(worker.bgw_library_name, "pg_oidc_validator", MAXPGPATH);
      strlcpy(worker.bgw_function_name, "pg_oidc_provision_worker", BGW_MAXLEN);
      worker.bgw_main_arg = UInt32GetDatum(dsm_segment_handle(cleanup->segment));
      worker.bgw_notify_pid = MyProcPid;
      MemoryContext previous = MemoryContextSwitchTo(TopMemoryContext);
      bool registered = RegisterDynamicBackgroundWorker(&worker, &cleanup->worker);
      MemoryContextSwitchTo(previous);
      if (!registered) return;

      for (;;) {
        ResetLatch(MyLatch);
        if (!request_is_current(request)) break;
        pid_t worker_pid;
        BgwHandleStatus status = GetBackgroundWorkerPid(cleanup->worker, &worker_pid);
        if (status == BGWH_STOPPED) {
          authorized = pg_atomic_read_u32(&request->result) == accepted;
          break;
        }
        if (status == BGWH_POSTMASTER_DIED) break;
        WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 100L, PG_WAIT_EXTENSION);
      }
    });
  } catch (...) {
    // No token, claim payload, SQL text from errors, or credentials are logged.
    authorized = false;
  }

  if (cleanup != nullptr) {
    if (exit_callback_registered) cancel_before_shmem_exit(cleanup_request, PointerGetDatum(cleanup));
    pg::pg_try([&]() { cleanup_request(0, PointerGetDatum(cleanup)); });
    pfree(cleanup);
  }
  return authorized;
}

}  // namespace oidc

extern "C" PGDLLEXPORT void pg_oidc_provision_worker(Datum main_arg) {
  // Standard backend signal handlers preserve interruptible startup/SQL.
  pqsignal(SIGTERM, die);
  pqsignal(SIGINT, StatementCancelHandler);
  BackgroundWorkerUnblockSignals();

  dsm_segment* segment = nullptr;
  ProvisionRequest* request = nullptr;
  try {
    pg::pg_try([&]() {
      segment = dsm_attach(DatumGetUInt32(main_arg));
      if (segment == nullptr || dsm_segment_map_length(segment) != sizeof(ProvisionRequest)) return;
      dsm_pin_mapping(segment);
      request = static_cast<ProvisionRequest*>(dsm_segment_address(segment));
      if (request->magic != request_magic || request->length == 0 || request->length >= request_capacity ||
          request->json[request->length] != '\0' ||
          memchr(request->database, '\0', sizeof(request->database)) == nullptr)
        return;
      before_shmem_exit(worker_exit, PointerGetDatum(request));
      if (!request_is_current(request) || RecoveryInProgress()) return;
      BackgroundWorkerInitializeConnection(request->database, nullptr, 0);
      if (!request_is_current(request)) return;
      bool authorized = reconcile(request);
      pg_atomic_write_u32(&request->result, authorized ? accepted : denied);
    });
  } catch (...) {
    // Roll back before signaling failure; don't expose function error details.
    pg::pg_try([]() { AbortCurrentTransaction(); });
    if (request != nullptr) pg_atomic_write_u32(&request->result, denied);
  }
  proc_exit(0);
}
