--require r/have_pool_of_threads.require
disable_query_log;
show variables like 'threadpool_size';
enable_query_log;
