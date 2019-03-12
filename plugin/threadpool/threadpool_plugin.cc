/* Copyright (C)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA */
#define MYSQL_SERVER 1

#include <set_var.h>
#include <mysql/plugin.h>
#include <my_global.h>
#include <my_sys.h>
#include <sql_class.h>
#include "threadpool.h"
#include <unistd.h>
#include <mysql/thread_pool_priv.h>

#define MAX_CONNECTIONS 100000

/*
 * declare system global variables for threadpool
 */

static uint getncpus()
{
  uint ncpus = sysconf(_SC_NPROCESSORS_ONLN);
  return MY_MAX(ncpus,1);
}

static void fix_threadpool_size(THD*,struct st_mysql_sys_var *, void*, const void* value)
{
  threadpool_size = *static_cast<const uint*>(value);
  tp_set_threadpool_size(threadpool_size);
}

static void fix_threadpool_stall_limit(THD*,struct st_mysql_sys_var *, void *, const void* value)
{
  threadpool_stall_limit = *static_cast<const uint*>(value);
  tp_set_threadpool_stall_limit(threadpool_stall_limit);
}

static MYSQL_SYSVAR_UINT(idle_timeout,threadpool_idle_timeout,
  PLUGIN_VAR_RQCMDARG,
  "Timeout in seconds for an idle thread in the thread pool. Worker thread will be shut down after timeout",
  NULL,NULL,60,1,UINT_MAX,1);

static MYSQL_SYSVAR_UINT(oversubscribe,threadpool_oversubscribe,
  PLUGIN_VAR_RQCMDARG,
  "How many additional active worker threads in a thread group are all allowed.",
  NULL,NULL,3,1,1000,1);

static MYSQL_SYSVAR_UINT(size,threadpool_size,
  PLUGIN_VAR_RQCMDARG,
  "Number of thread groups in the pool."
  "This parameter is roughly equivalent to maximum number of concurrently "
  "executing threads (threads in a waiting state do not count as executing).",
  NULL, fix_threadpool_size, (uint) getncpus(),1,MAX_THREAD_GROUPS,1);


static MYSQL_SYSVAR_UINT(stall_limit, threadpool_stall_limit,
  PLUGIN_VAR_RQCMDARG,
  "Maximum query execution time in milliseconds,"
  "before an executing non-yielding thread is considered stalled."
  "If a worker thread is stalled, additional worker thread "
  "may be created to handle remaining clients.",
  NULL,fix_threadpool_stall_limit,500,10,UINT_MAX,1);

static MYSQL_SYSVAR_UINT(max_threads,threadpool_max_threads,
  PLUGIN_VAR_RQCMDARG,
  "Maximum allowed number of worker threads in the thread pool",
  NULL, NULL, MAX_CONNECTIONS, 1, MAX_CONNECTIONS, 1);


static MYSQL_SYSVAR_UINT(prio_kickup_timer,threadpool_prio_kickup_timer,
  PLUGIN_VAR_RQCMDARG,
  "Timeout in milliseconds for moving a connection from low priority queue to high priority queue after timeout",
  NULL,NULL,1000,1,UINT_MAX,1);


static MYSQL_SYSVAR_UINT(high_prio_tickets,threadpool_high_prio_tickets,
  PLUGIN_VAR_RQCMDARG,
  "Number of tickets to enter the high priority event queue for each "
    "transaction.",
  NULL, NULL, UINT_MAX, 0, UINT_MAX, 1);


static struct st_mysql_sys_var* system_variables[]={
  MYSQL_SYSVAR(idle_timeout),
  MYSQL_SYSVAR(oversubscribe),
  MYSQL_SYSVAR(size),
  MYSQL_SYSVAR(stall_limit),
  MYSQL_SYSVAR(high_prio_tickets),
  MYSQL_SYSVAR(max_threads),
  MYSQL_SYSVAR(prio_kickup_timer),
  NULL
};

int show_threadpool_idle_threads(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_INT;
  var->value= buff;
  *(int *)buff= tp_get_idle_thread_count(); 
  return 0;
}

static SHOW_VAR status_variables[]= {
  {"Threadpool_idle_threads", (char *) &show_threadpool_idle_threads, SHOW_FUNC,SHOW_SCOPE_GLOBAL},
  {"Threadpool_threads",      (char *) &tp_stats.num_worker_threads, SHOW_INT,SHOW_SCOPE_GLOBAL},
};

static Connection_handler_functions tp_handler_functions=
{
    threadpool_max_threads,
    add_connection,
    tp_end,
};

THD_event_functions thd_event_functions=
{
    tp_wait_begin,
    tp_wait_end,
    tp_post_kill_notification,
};

/* when initialize the thread pool plugin,
 * update mysql scheduler functions point to our threadpool scheduler functions */
static int threadpool_plugin_init(void *p)
{
  DBUG_ENTER("threadpool_plugin_init");
  tp_init();
  my_connection_handler_set(&tp_handler_functions,&thd_event_functions);
  DBUG_RETURN(0);
}

/* when unload the thread pool plugin,
 * restore the scheduler to be the original one */
static int threadpool_plugin_deinit(void *p)
{
  DBUG_ENTER("threadpool_plugin_deinit");
  my_connection_handler_reset();
  tp_end();
  DBUG_RETURN(0);
}

struct st_mysql_daemon threadpool_plugin_info=
  {  MYSQL_DAEMON_INTERFACE_VERSION  };

mysql_declare_plugin(threadpool)
{
  MYSQL_DAEMON_PLUGIN,              /* type                            */
  &threadpool_plugin_info,          /* descriptor                      */
  "threadpool",                     /* name                            */
  "Percona",                        /* author                          */
  "Thread pool from Percona 5.7 and enhanced",   /* description        */
  PLUGIN_LICENSE_GPL,               /* plugin license                  */
  threadpool_plugin_init,           /* init function (when loaded)     */
  threadpool_plugin_deinit,         /* deinit function (when unloaded) */
  0x0001,                           /* version                         */
  status_variables,                 /* status variables                */
  system_variables,                 /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;
