# Ignore information_schema.global_status deprecation warning
--disable_warnings

--disable_query_log
SELECT VARIABLE_VALUE-@init_ndb_conflict_fn_epoch_trans AS ndb_conflict_fn_epoch_trans FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_FN_EPOCH_TRANS";
SELECT VARIABLE_VALUE-@init_ndb_conflict_fn_epoch2_trans AS ndb_conflict_fn_epoch2_trans FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_FN_EPOCH2_TRANS";
SELECT VARIABLE_VALUE-@init_ndb_conflict_trans_row_conflict_count AS ndb_conflict_trans_row_conflict_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_TRANS_ROW_CONFLICT_COUNT";
SELECT VARIABLE_VALUE-@init_ndb_conflict_trans_row_reject_count AS ndb_conflict_trans_row_reject_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_TRANS_ROW_REJECT_COUNT";
SELECT VARIABLE_VALUE-@init_ndb_conflict_trans_reject_count AS ndb_conflict_trans_reject_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_TRANS_REJECT_COUNT";
SELECT VARIABLE_VALUE-@init_ndb_conflict_trans_detect_iter_count AS ndb_conflict_trans_detect_iter_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_TRANS_DETECT_ITER_COUNT";
SELECT VARIABLE_VALUE-@init_ndb_conflict_trans_conflict_commit_count AS ndb_conflict_trans_conflict_commit_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_TRANS_CONFLICT_COMMIT_COUNT";
SELECT VARIABLE_VALUE-@init_ndb_conflict_epoch_delete_delete_count AS ndb_epoch_delete_delete_count FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME LIKE "NDB_CONFLICT_EPOCH_DELETE_DELETE_COUNT";
--enable_query_log

--enable_warnings