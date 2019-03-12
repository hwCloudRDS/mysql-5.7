#include "securec.h"
#include <assert.h>
#include <string.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif

#define    VOS_OK 1
#define VOS_FALSE 0
#define    VOS_ERROR 0
#define BUFFER_SIZE 100 
#ifdef SECUREC_ON_64BITS
#define    VOS_WORDSIZE 64
#else
#define    VOS_WORDSIZE 32
#endif
#define VOS_NULL_PTR NULL
#define STRLEN 64

#define VOS_VOID void
#define VOS_CHAR char
#define VOS_INT64 INT64T
#define VOS_INT32 INT32T
#define    VOS_UINT32 UINT32T
#define    VOS_UINT64 UINT64T
#define    VOS_INT16 short int
#define VOS_UINT16 unsigned short int
#define VOS_INT int
#define    VOS_SIZE_T size_t

#define VOS_sscanf  sscanf_s 
#define VOS_sprintf(dest,format,arg)  sprintf_s(dest,STRLEN,format,arg)
#define VOS_nvsprintf(dest,iuStrLen,format,arg) vsnprintf_s(dest,STRLEN,iuStrLen, format,arg)
#define VOS_vsprintf(dest,format,arg) vsprintf_s(dest,STRLEN,format,arg)
#define VOS_nsprintf(dest,iuStrLen,format,arg) snprintf_s(dest,STRLEN,iuStrLen,format,arg)
#define VOS_MemCmp memcpy
#define VOS_Printf printf

#define VOS_StrLen(a) strlen(a)
#define VOS_MemAlloc(arg1, arg2, size)                      malloc(size)
#define VOS_MemFree(arg1, pAddr)                            free(pAddr)
#define VOS_MemSet(buf, ch, size)                           memset(buf, ch, size)
#define VOS_MemCpy_Safe(dest, destMax, src, count)          memcpy_s(dest, destMax, src, count)
#define VOS_MemSet_Safe(dest, destMax, c, count)            memset_s(dest, destMax, c, count)
#define VOS_StrCpy(strDest, strSrc)                         strcpy(strDest, strSrc)
#define VOS_StrCpy_Safe(strDest, destMax, strSrc)           strcpy_s(strDest, destMax, strSrc)
#define VOS_StrCat_Safe(dest, destMax, strSrc)              strcat_s(dest, destMax, strSrc)
#define VOS_strncat_Safe(strDest, destMax, strSrc, count)   strncat_s(strDest, destMax, strSrc, count)
#define VOS_StrTok_Safe(strToken, strDelimit, context)      strtok_s(strToken, strDelimit, context)
#define VOS_StrCmp(str1, str2)                              strcmp(str1, str2)

#define CU_ASSERT_NOT_EQUAL(a,b) assert((a)!=(b))
#define CU_ASSERT_EQUAL(a,b) assert((a)==(b))
#define CU_ASSERT_TRUE(a) assert(a) 
#define CU_ASSERT_STR_EQUAL(a,b) assert(0== strcmp(a,b))


VOS_VOID Tl_VOS_sscanf_INT64(VOS_CHAR *pscIBuf, VOS_CHAR *pfmt, VOS_INT64 IValue ,VOS_INT32 uiRet,VOS_INT64 IExpValue)
{
    uiRet = VOS_sscanf(pscIBuf, pfmt,&IValue);
    if (uiRet > 0)
    {
        CU_ASSERT_EQUAL(IValue,IExpValue);
    }
}
VOS_VOID Tl_VOS_sscanf_UINT64(VOS_CHAR *pscIBuf, VOS_CHAR *pfmt, VOS_UINT64 IValue ,VOS_INT32 uiRet,VOS_UINT64 IExpValue)
{
    uiRet = VOS_sscanf(pscIBuf, pfmt,&IValue);
    if (uiRet > 0)
    {
        CU_ASSERT_EQUAL(IValue,IExpValue);
    }
}

VOS_VOID Tl_VOS_sprintf_UINT64(VOS_CHAR *pscIBuf, VOS_CHAR *pfmt, VOS_UINT64 pWriteBuf ,VOS_UINT32 uiExpRet,VOS_CHAR *IExpValue,VOS_UINT32 uiRet)
{
    VOS_INT32 uiCount = 0;/*sjl modify, sprintf return int value,not uint32 value*/
    uiCount = VOS_sprintf(pscIBuf,pfmt,pWriteBuf);
    if (VOS_OK == uiRet)
    {
        CU_ASSERT_EQUAL(uiCount,uiExpRet);
        CU_ASSERT_EQUAL(0,strcmp(pscIBuf,IExpValue));
    }
}

VOS_VOID Tl_VOS_sprintf_INT64(VOS_CHAR *pscIBuf, VOS_CHAR *pfmt, VOS_INT64 pWriteBuf ,VOS_UINT32 uiExpRet,VOS_CHAR *IExpValue,VOS_UINT32 uiRet)
{
    VOS_INT32 uiCount = 0;/*sjl modify, sprintf return int value,not uint32 value*/
    uiCount = VOS_sprintf(pscIBuf,pfmt,pWriteBuf);
    if (VOS_OK == uiRet)
    {
        CU_ASSERT_EQUAL(uiCount,uiExpRet);
        CU_ASSERT_EQUAL(0,strcmp(pscIBuf,IExpValue));
    }
}
VOS_INT32 Tl_VOS_nvsprintf(VOS_CHAR * pscStr, VOS_UINT32 uiMaxStrLen, const VOS_CHAR *pscFormat,...)
{
    VOS_INT32 ulStrLen;
    va_list arguments;

    va_start(arguments, pscFormat);
    ulStrLen = VOS_nvsprintf(pscStr, uiMaxStrLen, pscFormat, arguments);
    va_end(arguments);
    return ulStrLen;
}

VOS_INT32 Test_VOS_vsprintf(VOS_CHAR *pscStr, const VOS_CHAR *pscFmt, ...)
{
    va_list arg;
    register VOS_INT slCount;   

    va_start(arg, pscFmt);
    slCount = VOS_vsprintf(pscStr, (const VOS_CHAR *) pscFmt, arg);
    va_end(arg);
    return (slCount);
}

VOS_INT32 Test_VOS_nvsprintf(VOS_CHAR *pscStr, VOS_UINT32 uiMaxStrLen, const VOS_CHAR *pscFmt, ...)
{
    va_list arg;
    register VOS_INT32 slCount;

    va_start(arg, pscFmt);
    slCount = VOS_nvsprintf(pscStr, uiMaxStrLen - 1, (const VOS_CHAR *) pscFmt, arg);
    if((VOS_UINT32)slCount < uiMaxStrLen)
    {
        pscStr[slCount] = '\0';
    }
    va_end(arg);
    return (slCount);
}

#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
VOS_INT32 VOS_vsnprintf(char *buff,int len,char* formatstring, ...) 
{
    va_list args;
    int nSize = 0;

    memset(buff, 'a', sizeof(buff));
    va_start(args, formatstring);
    nSize = vsnprintf( buff,  len, formatstring, args);
    return nSize;
}
#endif

VOS_INT32 VOS_vsnprintf_s(char *buff,int bufflen,int len,char* formatstring, ...) 
{
    va_list args;
    int nSize = 0;

    memset(buff, 0, sizeof(buff));
    va_start(args, formatstring);
    nSize = vsnprintf_s( buff, bufflen, len, formatstring, args);
    return nSize;
}
VOS_INT32 vos_vsprintf(char *buffer,char * format, ...)
{
    va_list args;
    int ret = 0;
    va_start(args, format);

    ret = vsprintf(buffer, format, args);
    return ret;
}

VOS_INT32 vos_vsprintf_s(char *buffer,int len,char * format, ...)
{
    va_list args;
    int ret = 0;
    va_start(args, format);
    
    ret = vsprintf_s(buffer, len, format, args);
    return ret;
}

VOS_VOID dopra_comptest();
VOS_VOID dopratest_main();
