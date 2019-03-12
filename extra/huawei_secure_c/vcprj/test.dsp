# Microsoft Developer Studio Project File - Name="test" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=test - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "test.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "test.mak" CFG="test - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "test - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "test - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "test - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /c
# ADD BASE RSC /l 0x804 /d "NDEBUG"
# ADD RSC /l 0x804 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "test - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I "../include" /I "../test" /I "../test/comptest" /I "../src" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR /FD /GZ /Zm1000 /c
# ADD BASE RSC /l 0x804 /d "_DEBUG"
# ADD RSC /l 0x804 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "test - Win32 Release"
# Name "test - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_float.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_int_d.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_int_i.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_other.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_str_c.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_printftest_str_s.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_float.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_int_d.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_int_i.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_other.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_str_c.c
# End Source File
# Begin Source File

SOURCE=..\test\comptest\compare_sscanftest_str_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\dopra_comptest.c
# End Source File
# Begin Source File

SOURCE=..\src\fscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\fwscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\gets_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\gets_test.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\mem_perf.c
# End Source File
# Begin Source File

SOURCE=..\src\memcpy_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\memcpytest.c
# End Source File
# Begin Source File

SOURCE=..\src\memmove_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\memmove_test.c
# End Source File
# Begin Source File

SOURCE=..\src\memset_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\memset_s_test.c
# End Source File
# Begin Source File

SOURCE=..\test\pub_funcs.c
# End Source File
# Begin Source File

SOURCE=..\src\scanf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\scanftest.c
# End Source File
# Begin Source File

SOURCE=..\src\securecutil.c
# End Source File
# Begin Source File

SOURCE=..\src\secureinput_a.c
# End Source File
# Begin Source File

SOURCE=..\src\secureinput_w.c
# End Source File
# Begin Source File

SOURCE=..\src\secureprintoutput_a.c
# End Source File
# Begin Source File

SOURCE=..\src\secureprintoutput_w.c
# End Source File
# Begin Source File

SOURCE=..\src\snprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\sprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\perftest\sprintfod.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\sprintftest.c
# End Source File
# Begin Source File

SOURCE=..\src\sscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\str_perf.c
# End Source File
# Begin Source File

SOURCE=..\src\strcat_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\strcattest.c
# End Source File
# Begin Source File

SOURCE=..\src\strcpy_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\strcpytest.c
# End Source File
# Begin Source File

SOURCE=..\src\strncat_s.c
# End Source File
# Begin Source File

SOURCE=..\src\strncpy_s.c
# End Source File
# Begin Source File

SOURCE=..\src\strtok_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\strtoktest.c
# End Source File
# Begin Source File

SOURCE=..\src\swprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\swprintftest.c
# End Source File
# Begin Source File

SOURCE=..\src\swscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\testmain.c
# End Source File
# Begin Source File

SOURCE=..\test\perftest\testperf.c
# End Source File
# Begin Source File

SOURCE=..\test\testutil.c
# End Source File
# Begin Source File

SOURCE=..\src\vfscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vfwscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vsnprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vsprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vsscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vswprintf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vswscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\vwscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wcscat_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wcscpy_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wcsncat_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wcsncpy_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wcstok_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wmemcpy_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wmemmove_s.c
# End Source File
# Begin Source File

SOURCE=..\src\wscanf_s.c
# End Source File
# Begin Source File

SOURCE=..\test\basecases\wscanftest.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\test\basecases\dopra_comptest.h
# End Source File
# Begin Source File

SOURCE=..\src\input.inl
# End Source File
# Begin Source File

SOURCE=..\src\output.inl
# End Source File
# Begin Source File

SOURCE=..\test\pub_funcs.h
# End Source File
# Begin Source File

SOURCE=..\src\secinput.h
# End Source File
# Begin Source File

SOURCE=..\include\securec.h
# End Source File
# Begin Source File

SOURCE=..\include\securectype.h
# End Source File
# Begin Source File

SOURCE=..\src\securecutil.h
# End Source File
# Begin Source File

SOURCE=..\src\secureprintoutput.h
# End Source File
# Begin Source File

SOURCE=..\test\comptest\unittest.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "test"

# PROP Default_Filter ""
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
