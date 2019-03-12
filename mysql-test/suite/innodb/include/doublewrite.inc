--echo #
--echo # Bug #17335427 INNODB CAN NOT USE THE DOUBLEWRITE BUFFER PROPERLY
--echo # Bug #18144349 INNODB CANNOT USE THE DOUBLEWRITE BUFFER FOR THE FIRST
--echo # PAGE OF SYSTEM TABLESPACE
--echo #

# Slow shutdown and restart to make sure ibuf merge is finished
SET GLOBAL innodb_fast_shutdown = 0;
--source include/restart_mysqld.inc

--disable_query_log
call mtr.add_suppression("InnoDB: Database page [0-9]+:1 contained only zeroes.");
call mtr.add_suppression("Header page consists of zero bytes");
call mtr.add_suppression("Checksum mismatch in datafile");
call mtr.add_suppression("but the innodb_page_size start-up parameter is");
call mtr.add_suppression("InnoDB: Resizing redo log from .*, LSN=[0-9]+");
call mtr.add_suppression("InnoDB: Starting to delete and rewrite log files.");
call mtr.add_suppression("InnoDB: New log files created, LSN=[0-9]+");
call mtr.add_suppression("option 'innodb-doublewrite-batch-size': unsigned value [0-9]+ adjusted to [0-9]+");
call mtr.add_suppression("Database page corruption or a failed file read of page");
--enable_query_log

let INNODB_PAGE_SIZE=`select @@innodb_page_size`;
let MYSQLD_DATADIR=`select @@datadir`;
let SEARCH_FILE= $MYSQLTEST_VARDIR/log/my_restart.err;

show variables like 'innodb_doublewrite';
show variables like 'innodb_fil_make_page_dirty_debug';
show variables like 'innodb_saved_page_number_debug';

create table t1 (f1 int primary key, f2 blob) engine=innodb;
create table t2 (f1 int primary key, f2 blob) engine=innodb;
create database testdblwr;
create table testdblwr.t1 (f1 int primary key, f2 blob) engine=innodb;

start transaction;
insert into t1 values(1, repeat('#',12));
insert into t1 values(2, repeat('+',12));
insert into t1 values(3, repeat('/',12));
insert into t1 values(4, repeat('-',12));
insert into t1 values(5, repeat('.',12));
insert into t2 values(1, repeat('#',12));
insert into t2 values(2, repeat('+',12));
insert into t2 values(3, repeat('/',12));
insert into t2 values(4, repeat('-',12));
insert into t2 values(5, repeat('.',12));
insert into testdblwr.t1 values(1, repeat('#',12));
insert into testdblwr.t1 values(2, repeat('+',12));
insert into testdblwr.t1 values(3, repeat('/',12));
insert into testdblwr.t1 values(4, repeat('-',12));
insert into testdblwr.t1 values(5, repeat('.',12));
commit work;

--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if first page of user
--echo # tablespace is full of zeroes.

select space from information_schema.innodb_sys_tables
where name = 'test/t1' into @space_id;

--echo # Wait for purge to complete
--source include/wait_innodb_all_purged.inc

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1 for export;
unlock tables;

begin;
insert into t1 values (6, repeat('%', 12));
# disable master thread so that it doesn't push up checkpoint
SET GLOBAL innodb_master_thread_disabled_debug = 1;
--source include/no_checkpoint_start.inc

--echo # Make the first page dirty for table t1
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that dirty pages of table t1 are flushed.
set global innodb_buf_flush_list_now = 1;

--let CLEANUP_IF_CHECKPOINT=drop table t1; drop table t2; drop database testdblwr;
--source include/no_checkpoint_end.inc

--echo # Make the first page (page_no=0) of the user tablespace
--echo # full of zeroes.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if first page of user
--echo # tablespace is corrupted.

select space from information_schema.innodb_sys_tables
where name = 'test/t1' into @space_id;

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1 for export;
unlock tables;

begin;
insert into t1 values (6, repeat('%', 12));

SET GLOBAL innodb_master_thread_disabled_debug = 1;
--source include/no_checkpoint_start.inc

--echo # Make the first page dirty for table t1
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that dirty pages of table t1 are flushed.
set global innodb_buf_flush_list_now = 1;

--source include/no_checkpoint_end.inc

--echo # Corrupt the first page (page_no=0) of the user tablespace.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if 2nd page of user
--echo # tablespace is full of zeroes.

select space from information_schema.innodb_sys_tables
where name = 'test/t1' into @space_id;

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1 for export;
unlock tables;

begin;
insert into t1 values (6, repeat('%', 400));

SET GLOBAL innodb_master_thread_disabled_debug = 1;
--source include/no_checkpoint_start.inc

--echo # Make the 2nd page dirty for table t1
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that dirty pages of table t1 are flushed.
set global innodb_buf_flush_list_now = 1;

--source include/no_checkpoint_end.inc

--echo # Make the 2nd page (page_no=1) of the tablespace all zeroes.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if 2nd page of user
--echo # tablespace is corrupted.

select space from information_schema.innodb_sys_tables
where name = 'test/t1' into @space_id;

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1 for export;
unlock tables;

begin;
insert into t1 values (6, repeat('%', 400));

SET GLOBAL innodb_master_thread_disabled_debug = 1;
--source include/no_checkpoint_start.inc

--echo # Make the 2nd page dirty for table t1
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = @space_id;

--echo # Ensure that the dirty pages of table t1 are flushed.
set global innodb_buf_flush_list_now = 1;

--source include/no_checkpoint_end.inc

--echo # Corrupt the 2nd page (page_no=1) of the user tablespace.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if first page of
--echo # system tablespace is full of zeroes.

begin;
insert into t1 values (6, repeat('%', 400));

--echo # Ensure that all dirty pages in the system are flushed.
set global innodb_buf_flush_list_now = 1;

--echo # Make the first page dirty for system tablespace
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = 0;

--echo # Ensure that the dirty page of system tablespace is also flushed.
# We do this after the transaction starts and all dirty pages have been flushed
# already. So flushing of this specified dirty page will surely keep the
# copy in doublewrite buffer, and no more writes to doublewrite buffer would
# overwrite the copy. Thus, we can safely modify the original page when server
# is down. So do the following testings.
set global innodb_buf_flush_list_now = 1;

--source include/kill_mysqld.inc

--echo # Make the first page (page_no=0) of the system tablespace
--echo # all zeroes.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if first page of
--echo # system tablespace is corrupted.

begin;
insert into t1 values (6, repeat('%', 400));

--echo # Ensure that all dirty pages in the system are flushed.
set global innodb_buf_flush_list_now = 1;

--echo # Make the first page dirty for system tablespace
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = 0;

--echo # Ensure that the dirty page of system tablespace is also flushed.
set global innodb_buf_flush_list_now = 1;

--source include/kill_mysqld.inc

--echo # Corrupt the first page (page_no=0) of the system tablespace.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if 2nd page of
--echo # system tablespace is full of zeroes.

begin;
insert into t1 values (6, repeat('%', 400));

--echo # Ensure that all dirty pages in the system are flushed.
set global innodb_buf_flush_list_now = 1;

--echo # Make the second page dirty for system tablespace
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = 0;

--echo # Ensure that the dirty page of system tablespace is also flushed.
set global innodb_buf_flush_list_now = 1;

--source include/kill_mysqld.inc

--echo # Make the 2nd page (page_no=1) of the system tablespace
--echo # all zeroes.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if 2nd page of
--echo # system tablespace is corrupted.

begin;
insert into t1 values (6, repeat('%', 400));

--echo # Ensure that all dirty pages in the system are flushed.
set global innodb_buf_flush_list_now = 1;

--echo # Make the second page dirty for system tablespace
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = 0;

--echo # Ensure that the dirty page of system tablespace is also flushed.
set global innodb_buf_flush_list_now = 1;

--source include/kill_mysqld.inc

--echo # Make the 2nd page (page_no=1) of the system tablespace
--echo # all zeroes.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if 1st and 2nd page of
--echo # system tablespace is corrupted.

begin;
insert into t1 values (6, repeat('%', 400));

--echo # Ensure that all dirty pages in the system are flushed.
set global innodb_buf_flush_list_now = 1;

--echo # Make the first and second page dirty for system tablespace
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = 0;
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = 0;

--echo # Ensure that the dirty page of system tablespace is also flushed.
set global innodb_buf_flush_list_now = 1;

--source include/kill_mysqld.inc

--echo # Corrupt the 1st page (page_no=0) of the system tablespace.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--echo # Corrupt the 2nd page (page_no=1) of the system tablespace.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}ibdata1";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--source include/start_mysqld.inc

check table t1;
select f1, f2 from t1;

--echo # Test End
--echo # ---------------------------------------------------------------
--echo # Test Begin: Test if recovery works if multiple pages corrupted
--echo # and even if mysqld is restarted with skip doublewrite

select space from information_schema.innodb_sys_tables
where name = 'test/t1' into @space_id;

select space from information_schema.innodb_sys_tables
where name = 'test/t2' into @space_id2;

select space from information_schema.innodb_sys_tables
where name = 'testdblwr/t1' into @space_id3;

--echo # Ensure that dirty pages of table t1 is flushed.
flush tables t1,t2,testdblwr.t1 for export;
unlock tables;

begin;
insert into t1 values (6, repeat('%', 400));
insert into t2 values (6, repeat('%', 400));
insert into testdblwr.t1 values (6, repeat('%', 400));

SET GLOBAL innodb_master_thread_disabled_debug = 1;
--source include/no_checkpoint_start.inc

--echo # Make multiple pages dirty
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = @space_id;
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = @space_id2;
set global innodb_saved_page_number_debug = 0;
set global innodb_fil_make_page_dirty_debug = @space_id3;
set global innodb_saved_page_number_debug = 1;
set global innodb_fil_make_page_dirty_debug = @space_id3;

--echo # Ensure that the dirty page of system tablespace is also flushed.
set global innodb_buf_flush_list_now = 1;

--source include/no_checkpoint_end.inc

--echo # Make multiple pages
--echo # full of zeroes or courrupted.
perl;
use IO::Handle;
my $fname= "$ENV{'MYSQLD_DATADIR'}test/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
$fname= "$ENV{'MYSQLD_DATADIR'}test/t2.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'});
close FILE;
$fname= "$ENV{'MYSQLD_DATADIR'}testdblwr/t1.ibd";
open(FILE, "+<", $fname) or die;
FILE->autoflush(1);
binmode FILE;
print FILE chr(0) x ($ENV{'INNODB_PAGE_SIZE'}/2);
seek(FILE, $ENV{'INNODB_PAGE_SIZE'}, SEEK_SET);
print FILE chr(3) x ($ENV{'INNODB_PAGE_SIZE'}/2);
close FILE;
EOF

--let $restart_parameters=restart:--skip-innodb_doublewrite
--source include/start_mysqld.inc

SELECT @@innodb_doublewrite;
check table t1;
check table t2;
check table testdblwr.t1;
select f1, f2 from t1;
select f1, f2 from t2;
select f1, f2 from testdblwr.t1;

--echo # Test End
--echo # ---------------------------------------------------------------

drop table t1;
drop table t2;
drop database testdblwr;

--echo # test innodb_doublewrite_batch_size configuration variable
--let $restart_parameters=restart:--innodb_doublewrite_batch_size=127
--source include/restart_mysqld.inc
SELECT @@GLOBAL.innodb_doublewrite_batch_size;
--error 1238
SELECT @@SESSION.innodb_doublewrite_batch_size;
--let $restart_parameters=restart:--innodb_doublewrite_batch_size=1
--source include/restart_mysqld.inc
SELECT @@innodb_doublewrite_batch_size;
--let $restart_parameters=restart:--innodb_doublewrite_batch_size=128
--source include/restart_mysqld.inc
SELECT @@innodb_doublewrite_batch_size;
--let $restart_parameters=restart:--innodb_doublewrite_batch_size=0
--source include/restart_mysqld.inc
SELECT @@innodb_doublewrite_batch_size;

--let $restart_parameters=
--source include/restart_mysqld.inc

--echo # innodb_doublewrite_batch_size default value
SELECT @@GLOBAL.innodb_doublewrite_batch_size;
--echo # Setting innodb_doublewrite_batch_size should fail
--error ER_INCORRECT_GLOBAL_LOCAL_VAR
SET @@GLOBAL.innodb_doublewrite_batch_size=32;
--error 1238
SET @@SESSION.innodb_doublewrite_batch_size=32;

--echo #
--echo # BUG#20511314 - INNODB: FAILING ASSERTION: FOUND IN BUF0BUF.CC LINE 3856
--echo #

SET GLOBAL innodb_fil_make_page_dirty_debug=38098908;

--echo #
--echo # Bug#22311319 - SERVER CRASHES ON INVALID VALUE FOR VARIABLE
--echo #		INNODB_SAVED_PAGE_NUMBER_DEBUG
--echo #
set global innodb_saved_page_number_debug=461461461;
set global innodb_fil_make_page_dirty_debug=0;
set global innodb_saved_page_number_debug=default;
