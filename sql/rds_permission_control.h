#ifndef RDS_PERMISSION_CONTROL_INCLUDED
#define RDS_PERMISSION_CONTROL_INCLUDED
#include "my_global.h"
#include "sql_list.h"
#include "table.h"

struct LEX;
struct TABLE_LIST;
class THD;
typedef struct st_lex_user LEX_USER;

/**
  Initialize the reserved user

  Called when server startup.

  @return state
  @retval 0 success
  @retval >=1 failed
*/
int rds_reserved_users_init();

/**
  Free the reserved user option variables.

  Called at server shutdown.
*/
void rds_reserved_users_free();

/**
  Update reserved users according to given string

  @return state
  @retval 0 success
  @retval >0 failed
*/
int rds_reserved_users_update(const char* users);

/**
  Validate the value for the system variable for RDS reserved users

  Note: the system variable for RDS reserved users (rds_reserved_users)
  is for internal use, and to simplify the logic, we do not allow
  whitespace as well as empty name in it (Documented).

  @param names  The string value for the system variable for the
                RDS reserved users (e.g., "admin1,admin2,admin3")
  @param len    the length of the names string

  @retval TRUE  valid
  @retval FALSE invalid
*/
bool is_valid_rds_reserved_users(const char *name, size_t len);

/**
  Check if local user has the given privilege
*/
int check_global_access_noerr(THD *thd, ulong want_access);

/**
   Access check regarding the RDS reserved users

   @retval
    0  ok
   @retval
    1  Access denied.  In this case an error is sent to the client
 */
int check_reserved_user(THD *thd, List <LEX_USER> &list, const char *command);

/**
   @retval
    0  ok
   @retval
    1  Access denied.
 */
int check_reserved_user_db(THD *thd, const char *user, const char *db);

/*
  @return
    @retval 0 OK
    @retval 1  Access denied; But column or routine privileges might need to
      be checked also.
*/
int check_internal_db(THD *thd, const char *db);

/*
  @param thd          Thread handler
  @param tables
  @param do_check_one_table
  @param no_error     True if no errors should be sent to the client.

  @return
    @retval 0  OK
    @retval 1  Access denied; But column or routine privileges might need to
      be checked also.
*/
int check_mysql_db_tables(THD *thd, TABLE_LIST *tables,bool do_check_one_table,bool no_error);

/*
  @param thd          Thread handler
  @param tables
  @param do_check_one_table
  @param no_error     True if no errors should be sent to the client.

  @return
    @retval 0  OK
    @retval 1  Access denied; But column or routine privileges might need to
      be checked also.
*/
int check_performance_schema_db_tables(THD *thd, TABLE_LIST *tables,bool do_check_one_table,bool no_error);

/**
  Check if a user is in the hash of reserved users.

  @return search result
  @retval TRUE  found
  @retval FALSE not found
*/
bool is_rds_reserved_user(const char *user);
#endif // RDS_PERMISSION_CONTROL_INCLUDED
