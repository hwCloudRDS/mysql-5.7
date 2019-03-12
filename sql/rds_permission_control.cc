#include "my_securec.h"  /* Should be the first include */

#include "rds_permission_control.h"
#include "mysqld.h"
#include "hash.h"
#include "sql_list.h"
#include "table.h"
#include "mysqld_error.h"
#include "sql_class.h"
#include "mysql/psi/mysql_thread.h"
#include "log.h"
#include "sql_acl.h"

PSI_rwlock_key  key_rds_user_list_active;
PSI_mutex_key   key_rds_user_list_update;
PSI_memory_key  key_rds_user_memory;

class RDS_reserved_users
{
public:
  RDS_reserved_users(void)
    : initialized(false), active_list(0)
  {
  }

  ~RDS_reserved_users()
  {
    release();
  }

  /**
    Initialize hash and mutex.

    Called on startup.

    @return state
    @retval 0 success
    @retval >0 failed
  */
  int init()
  {
#define GOTO_INIT_ERR(A) { error = A; goto err; }
    int error = 0;
    if (initialized)
    {
      sql_print_information("%s", "RDS reserved user struct already initialized.");
      GOTO_INIT_ERR(0);
    }
    if (my_hash_init(user_list+0
                     , &my_charset_bin
                     , 0, 0, 0
                     , hash_get_key
                     , my_free
                     , HASH_UNIQUE
					 , key_rds_user_memory))
    {
      sql_print_error("%s", "Failed to init RDS reserved user list.");
      GOTO_INIT_ERR(1);
    }
    if (my_hash_init(user_list+1
                     , &my_charset_bin
                     , 0, 0, 0
                     , hash_get_key
                     , my_free
                     , HASH_UNIQUE
					 , key_rds_user_memory))
    {
      sql_print_error("%s", "Failed to init RDS reserved user list.");
      GOTO_INIT_ERR(2);
    }
    register_psi_keys();
    if (mysql_rwlock_init(key_rds_user_list_active, &active_lock))
    {
      sql_print_error("%s", "Failed to init RDS reserved user lock.");
      GOTO_INIT_ERR(3);
    }
    if (mysql_mutex_init(key_rds_user_list_update, &update_mutex, MY_MUTEX_INIT_FAST))
    {
      sql_print_error("%s", "Failed to init RDS reserved user mutex.");
      GOTO_INIT_ERR(4);
    }
    active_list = 0;
    initialized = true;
err:
    switch(error)
    {
    case 4:
      mysql_rwlock_destroy(&active_lock);
    case 3:
      my_hash_free(user_list + 1);
    case 2:
      my_hash_free(user_list + 0);
    default:
      break;
    }
    return error;
  }

  /**
    Release hash and mutex (Coverity does not like free()).

    Called on server shutdown.
  */
  void release()
  {
    if (initialized)
    {
      my_hash_free(user_list + 0);
      my_hash_free(user_list + 1);
      mysql_rwlock_destroy(&active_lock);
      mysql_mutex_destroy(&update_mutex);
      active_list = 0;
      initialized = false;
    }
  }

  /**
    Generate new reserved users according to given users' string.
    Remove old reserved users.

    @return state
    @retval 0 success
    @retval >0 failed
  */
  int update(const char* reserved_users)
  {
#define GOTO_UPDATE_ERROR(A) { error = A; goto err; }
    char *origin_ptr = NULL;
    const char *delim = ",";
    char* context = NULL;
    char* input = NULL;
    char* output = NULL;
    uint len = 0;
    int error = 0;

    if (!initialized)
    {
      sql_print_error("%s", "RDS reserved user struct is not initialized.");
      return 1;
    }

    (void)mysql_mutex_lock(&update_mutex);
    HASH *update_list = user_list + (active_list +1)%2;
    my_hash_reset(update_list);
    len = (NULL == reserved_users) ? 0 : strlen(rds_reserved_users_ptr);
    if (0 == len)
    {
      sql_print_information("%s", "RDS reserved user list is empty.");
      GOTO_UPDATE_ERROR(0);
    }
    /* +1 the terminating zero */
    origin_ptr= (char *) my_malloc(key_rds_user_memory, len + 1, MYF(0));
    if (!origin_ptr)
    {
      sql_print_error("%s", "Failed to allocate memory while updating RDS reserved user list.");
      GOTO_UPDATE_ERROR(1);
    }
    if (my_strcpy(origin_ptr, len + 1, reserved_users, sql_print_error) == NULL)
    {
      sql_print_error("%s", "Failed to copy given string while updating RDS reserved user list.");
      GOTO_UPDATE_ERROR(1);
    }
    input = origin_ptr;
    while ((output = my_strtok(input, delim, &context, sql_print_error)) != NULL)
    {
      if (push_user(output, update_list))
      {
        GOTO_UPDATE_ERROR(2);
      }
      input = NULL;
    }
    error = 0;
err:
    // switch user list if no error
    if (0 == error)
    {
      (void)mysql_rwlock_wrlock(&active_lock);
      active_list = (active_list + 1)%2;
      (void)mysql_rwlock_unlock(&active_lock);
    }
    (void)mysql_mutex_unlock(&update_mutex);
    if (origin_ptr)
    {
      my_free(origin_ptr);
    }
    return error;
  }

  /**
    Check if given user name is an reserved user name.

    @retval ture yes
    @retval false no
  */
  bool is_user_reserved(const char* user)
  {
    bool ret = false;
    if (!initialized)
    {
      return ret;
    }
    (void)mysql_rwlock_rdlock(&active_lock);
    if (0 != user_list[active_list].records)
    {
      ret = (NULL != (my_hash_search(user_list+active_list, (const uchar*)user, strlen(user))));
    }
    (void)mysql_rwlock_unlock(&active_lock);
    return ret;
  }
private:
  /**
    register psi keys
  */
  void register_psi_keys()
  {
#ifdef HAVE_PSI_INTERFACE
    int count = 0;
    const char* category = "rds_user";
    PSI_rwlock_info all_rds_rwlocks[] =
    {
      { &key_rds_user_list_active, "rds_user_active_lock", 0}
    };
    count= sizeof(all_rds_rwlocks)/sizeof(all_rds_rwlocks[0]);
    mysql_rwlock_register(category, all_rds_rwlocks, count);
    PSI_mutex_info all_rds_mutexes[] =
    {
      { &key_rds_user_list_update, "rds_user_update_mutex", 0}
    };
    count= sizeof(all_rds_mutexes)/sizeof(all_rds_mutexes[0]);
    mysql_mutex_register(category, all_rds_mutexes, count);
    static PSI_memory_info all_rds_memorys[] =
    {
      { &key_rds_user_memory, "rds_user_memory", 0}
    };
    count= sizeof(all_rds_memorys)/sizeof(all_rds_memorys[0]);
    mysql_memory_register(category, all_rds_memorys, count);
#endif
  }

  /**
    Add given user into the given hash

    @param  user   given user name
    @param  hash   given hash
    @return        state
    @retval 0 success
    @retval >0 failed
  */
  static int push_user(const char* user, HASH* hash)
  {
#define GOTO_PUSH_USER_ERR(A) { error = A; goto err; }
    LEX_STRING *new_elt = NULL;
    char *new_elt_buffer = NULL;
    size_t user_len = strlen(user);
    int error = 0;
    if (!user_len)
    {
      sql_print_error("%s", "Found empty string while updating RDS reserved user list.");
      GOTO_PUSH_USER_ERR(1);
    }
    if (!my_multi_malloc(key_rds_user_memory, MYF(0),
                         &new_elt, sizeof(LEX_STRING),
                         &new_elt_buffer, user_len + 1,
                         NullS))
    {
      sql_print_error("%s", "Failed to allocate memory while updating RDS reserved user list.");
      GOTO_PUSH_USER_ERR(1);
    }
    new_elt->str= new_elt_buffer;
    if (my_strcpy(new_elt_buffer, user_len + 1, user, sql_print_error) == NULL)
    {
      sql_print_error("%s", "Failed to copy given string while updating RDS reserved user list.");
      GOTO_PUSH_USER_ERR(1);
    }
    new_elt->length= user_len;
    if (my_hash_insert(hash, (uchar *) new_elt))
    {
      sql_print_error("%s", "Failed to add given string while updating RDS reserved user list.");
      GOTO_PUSH_USER_ERR(1);
    }
err:
    if (NULL != new_elt && 0 != error)
    {
      my_free(new_elt);
    }
    return error;
  }

  /**
    Retrieves the key (the string itself) from the LEX_STRING hash members.

    Needed by hash_init().

    @param     data         the data element from the hash
    @param out len_ret      Placeholder to return the length of the key
    @param                  unused
    @return                 a pointer to the key
  */
  static uchar* hash_get_key(const uchar *data, size_t *len_ret,
                             my_bool MY_ATTRIBUTE((unused)))
  {
    LEX_STRING *e = (LEX_STRING *) data;
    *len_ret = e->length;
    return (uchar *) e->str;
  }
private:
  bool    initialized;
  HASH    user_list[2];  // use two hash to switch between backup and active
  int     active_list;   // indicate which hash is in use
  mysql_rwlock_t  active_lock;  // protect the active hash
  mysql_mutex_t   update_mutex; // protect from concurrent updating
};

RDS_reserved_users* get_rds_reserved_users()
{
  static RDS_reserved_users s_rds_users;
  return &s_rds_users;
}

/**
  Initialize the reserved user

  Called when server startup.

  @return state
  @retval 0 success
  @retval >0 failed
*/
int rds_reserved_users_init()
{
  return get_rds_reserved_users()->init();
}

/**
  Free the reserved users

  Called at server shutdown.

  @return state
  @retval 0 success
  @retval >0 failed
*/
void rds_reserved_users_free()
{
  get_rds_reserved_users()->release();
}

/**
  Update reserved users according to given string

  @return state
  @retval 0 success
  @retval >0 failed
*/
int rds_reserved_users_update(const char* users)
{
  return get_rds_reserved_users()->update(users);
}

/**
  Check if a user is in the hash of reserved users.

  @return search result
  @retval TRUE  found
  @retval FALSE not found
*/
bool is_rds_reserved_user(const char *user)
{
  bool ret = false;
  if (NULL != user && 0 != strlen(user))
  {
    ret = get_rds_reserved_users()->is_user_reserved(user);
  }
  return ret;
}

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
bool is_valid_rds_reserved_users(const char *names, size_t len)
{
  unsigned int i;

  /*if len ==0 return true,in case of unsigned number flipping*/
  if(len == 0)
    return true;

  /* Not allow whitespace in the string */
  for(i = 0; i < len; i++)
  {
    if(names[i] == ' ' || names[i] == '\t' || names[i] == '\n')
    {
      return false;
    }
  }
  /* Now check the empty name in the string */
  for(i = 0; i < (len - 1); i++)
  {
    if(names[i] == ',' &&  names[i + 1] == ',' )
    {
      return false;
    }
  }
  /* Do not allow leading or trailing comma like ",admin1,ad," */
  if (names[0] == ',' || names[len - 1] == ',')
  {
    return false;
  }

  return true;
}

/**
  Check if mysql db
*/
inline bool is_mysql_db(const char *name)
{
  return !my_strcasecmp(system_charset_info,
                        MYSQL_SCHEMA_NAME.str, name);
}

/**
  Check if local user has the given privilege
*/
int check_global_access_noerr(THD *thd, ulong want_access)
{
  DBUG_ENTER("check_global_access_noerr");
#ifndef NO_EMBEDDED_ACCESS_CHECKS
  if (thd->security_context()->check_access(want_access))
  {
    DBUG_RETURN(0);
  }
  DBUG_RETURN(1);
#else
  DBUG_RETURN(0);
#endif
}

/**
   Access check regarding the RDS reserved users

   @retval
    0  ok
   @retval
    1  Access denied.  In this case an error is sent to the client
 */
int check_reserved_user(THD *thd, List <LEX_USER> &list, const char *command)
{
  DBUG_ENTER("check_reserved_user");
  LEX_USER *tmp_user_name;
  List_iterator <LEX_USER> user_list(list);

  if (!check_global_access_noerr(thd,SUPER_ACL))
  {
    DBUG_RETURN(0);
  }

  LEX_CSTRING sec_user = thd->security_context()->user();
  if (NULL != sec_user.str &&  0 != sec_user.length && is_rds_reserved_user(sec_user.str))
  {
    DBUG_RETURN(0);
  }

  while ((tmp_user_name= user_list++))
  {
    if (tmp_user_name->user.str)
    {
      if (is_rds_reserved_user(tmp_user_name->user.str))
      {
        char account[HOSTNAME_LENGTH + USERNAME_CHAR_LENGTH + 6];
        (void)my_sprintf(account, sizeof(account), "'%s'@'%s'",
                         tmp_user_name->user.str, tmp_user_name->host.str);

        my_error(ER_CANNOT_USER, MYF(0), command, account);
        DBUG_RETURN(1);
      }
    }
  }

  DBUG_RETURN(0);
}

/**
   @retval
    0  ok
   @retval
    1  Access denied.
 */
int check_reserved_user_db(THD *thd, const char *user, const char *db)
{
  DBUG_ENTER("check_reserved_user_db");
  if (!check_global_access_noerr(thd,SUPER_ACL))
  {
    DBUG_RETURN(0);
  }

  LEX_CSTRING sec_user = thd->security_context()->user();
  if(NULL != sec_user.str && is_rds_reserved_user(sec_user.str) )
  {
	DBUG_RETURN(0);
  }

  if (NULL == user || !is_rds_reserved_user(user))
  {
    DBUG_RETURN(0);
  }

  Security_context *sctx= thd->security_context();
  my_error(ER_DBACCESS_DENIED_ERROR, MYF(0),
    	                   sctx->priv_user().str, sctx->priv_host().str, db);
  DBUG_RETURN(1);
}

/*
  @return
    @retval 0 OK
    @retval 1  Access denied; But column or routine privileges might need to
      be checked also.
*/
int check_internal_db(THD *thd, const char *db)
{
  DBUG_ENTER("check_internal_db");
  if (!check_global_access_noerr(thd,SUPER_ACL))
  {
    DBUG_RETURN(0);
  }

  if(is_rds_reserved_user(thd->security_context()->user().str))
  {
    DBUG_RETURN(0);
  }

  if (!is_perfschema_db(db) && !is_mysql_db(db))
  {
    DBUG_RETURN(0);
  }

  my_error(ER_DBACCESS_DENIED_ERROR, MYF(0), thd->security_context()->user().str, thd->security_context()->host_or_ip().str, db);
  DBUG_RETURN(1);
}

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
int check_mysql_db_tables(THD *thd, TABLE_LIST *tables,bool do_check_one_table,bool no_error)
{
  DBUG_ENTER("check_mysql_db_tables");
  if(!check_global_access_noerr(thd,SUPER_ACL))
  {
    DBUG_RETURN(0);
  }

  if(is_rds_reserved_user(thd->security_context()->user().str))
  {
    DBUG_RETURN(0);
  }

  TABLE_LIST *first_not_own_table= thd->lex->first_not_own_table();
  for (; tables != first_not_own_table && tables; tables= tables->next_global)
  {
    if (is_mysql_db(tables->get_db_name()))
	{
	  if (!no_error)
       {
		my_error(ER_DBACCESS_DENIED_ERROR, MYF(0), thd->security_context()->user().str, thd->security_context()->host_or_ip().str, tables->get_db_name());
	   }
	   DBUG_RETURN(1);
	}
  }

  DBUG_RETURN(0);
}

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
int check_performance_schema_db_tables(THD *thd, TABLE_LIST *tables,bool do_check_one_table,bool no_error)
{
  DBUG_ENTER("check_performance_schema_db_tables");
  if(!check_global_access_noerr(thd,SUPER_ACL))
  {
    DBUG_RETURN(0);
  }

  if(is_rds_reserved_user(thd->security_context()->user().str))
  {
    DBUG_RETURN(0);
  }

  TABLE_LIST *first_not_own_table= thd->lex->first_not_own_table();
  for (; tables != first_not_own_table && tables; tables= tables->next_global)
  {
    if (is_mysql_db(tables->get_db_name()))
	{
	  if (!no_error)
       {
		my_error(ER_DBACCESS_DENIED_ERROR, MYF(0), thd->security_context()->user().str, thd->security_context()->host_or_ip().str, tables->get_db_name());
	   }
	   DBUG_RETURN(1);
	}
  }

  DBUG_RETURN(0);
}
