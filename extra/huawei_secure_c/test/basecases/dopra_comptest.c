
#include "securec.h"
#include "base_funcs.h"
#include "dopra_comptest.h"
#include <string.h>
#ifdef COMPATIBLE_LINUX_FORMAT
#include <stdint.h>
#include <stddef.h>
#endif
#include <stdio.h>
#include <stdlib.h>


int byte_order()
 {
    unsigned short wValue = 0x1234;
    unsigned char myVal[] = {0x12, 0x34, 0x56, 0x78, 0x91, 0x32, 0x54, 0x76  };
    unsigned int i = 0;
#if !(defined(__hpux))
    i = *(int*)(myVal +1);

   if (*(char*)&wValue == 0x12) 
    {
        return 1;
    }
   else
    {
        return 0;
    }
#endif    
    return 0;
}

#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
/**
 *@test    Itest_VOS_sscanf_01
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"9223372036854775807 123"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_01()
{    
    VOS_CHAR   sBuf[64] = "9223372036854775807 123";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0x7fffffffffffffffULL;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_02
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"0"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_02()
{    
    VOS_CHAR   sBuf[64] = "0";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_03
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_03()
{    
    VOS_CHAR   sBuf[64] = "1";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 1;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_04
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"-1"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_04()
{    
    VOS_CHAR   sBuf[64] = "-1";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = -1;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_05
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"4294967294"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_05()
{    
    VOS_CHAR   sBuf[64] = "4294967294";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0xFFFFFFFE;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,(VOS_INT32)uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_06
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"-4294967294"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_06()
{    
    VOS_CHAR   sBuf[64] = "-4294967294";  
    VOS_INT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_INT64 iExpValue = 0xFFFFFFFF00000002LL;
    
    Tl_VOS_sscanf_INT64(sBuf,"%lld",iValue,uiRet,iExpValue);
    
}


/**
 *@test    Itest_VOS_sscanf_07
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"0"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_07()
{    
    VOS_CHAR   sBuf[64] = "0";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = 0;
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_08
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"9223372036854775807"
 *- @texpect    写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_08()
{    
    VOS_CHAR   sBuf[64] = "18446744073709551615";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = 0xffffffffffffffffULL;
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sscanf_08
 *- @tspec    VOS_sscanf
 *- @ttitle    写入字符64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"-1"
 *- @texpect    写入不成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sscanf_09()
{    
    VOS_CHAR   sBuf[64] = "-1";  
    VOS_UINT64 iValue=0;
    VOS_INT32 uiRet=0;
    VOS_UINT64 iExpValue = (VOS_UINT64)(-1);
    
    Tl_VOS_sscanf_UINT64(sBuf,"%llu",iValue,uiRet,iExpValue);
    
}

/**
 *@test    Itest_VOS_sprintf_01
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_01()
{    
    VOS_CHAR   sReadBuf[64] = {0};  
    VOS_UINT64  sWriteBuf = 1;  
    VOS_INT32 uiExpRet = 18;/*sjl modify sprintf return int value, not uint32 value*/
    VOS_CHAR iExpValue[64] = "vos_sprintf test 1";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,VOS_OK);/*sjl test bug*/

    
}

/**
 *@test    Itest_VOS_sprintf_02
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"0xffffffffffffffff"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_02()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0xffffffffffffffffULL;  
    VOS_INT32 uiExpRet = 37;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 18446744073709551615";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,VOS_OK);

    
}

/**
 *@test    Itest_VOS_sprintf_03
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_03()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = (VOS_UINT64)(-1);  
    VOS_INT32 uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";
    
    Tl_VOS_sprintf_UINT64(sReadBuf,"vos_sprintf test %llu",sWriteBuf,uiExpRet,iExpValue,(VOS_UINT32)VOS_ERROR);

    
}

/**
 *@test    Itest_VOS_sprintf_04
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_04()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = (VOS_UINT64)(-1);  
    VOS_INT32 uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %lld",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
  
}

/**
 *@test    Itest_VOS_sprintf_05
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_sprintf_05()
{    
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0x7fffffffffffffffULL;  
    VOS_INT32 uiExpRet = 36;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 9223372036854775807";
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %lld",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK); 
}
#endif
/**
 *@test    Itest_VOS_sprintf_06
 *- @tspec    VOS_sprintf
 *- @ttitle    读取64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"1"
 *- @texpect   读取成功
 *- @tprior
 *- @tremark 该用例在大端机器运行，会出错
 */

#ifndef _MSC_VER
 VOS_VOID Itest_VOS_sprintf_06()
{  
    VOS_CHAR   sReadBuf[64];  
    VOS_UINT64  sWriteBuf = 0x7fffffffffffffffULL;  
    
#if (VOS_WORDSIZE == 64)
    VOS_INT32 uiExpRet = 36;
    
    VOS_CHAR iExpValue[64] = "vos_sprintf test 9223372036854775807"; 
    
    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#else
    
    /* 在大端机器运行,截取 7fffffff */
#if (byte_order)
    VOS_INT32 uiExpRet = 27;
    VOS_CHAR iExpValue[64] = "vos_sprintf test 2147483647";  /* 该用例在大端机器运行，截取前部分，而非后部分 */

    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#else
    VOS_INT uiExpRet = 19;
    VOS_CHAR iExpValue[64] = "vos_sprintf test -1";  

    Tl_VOS_sprintf_INT64(sReadBuf,"vos_sprintf test %zd",(VOS_INT64)sWriteBuf,uiExpRet,iExpValue,VOS_OK);
#endif
#endif 
}
#endif
/**
 *@test    Itest_VOS_nvsprintf_01
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把acString的内容写入到acBuff
 *- @tbrief    
 *        -# 被测试函数返回拷贝的字节长度，要拷贝的最大长度大于字符串的长度
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_01()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_01";
    VOS_UINT32 uiMaxStrLen = 64;
    VOS_INT32 ulStrLen;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, acString);

    CU_ASSERT_EQUAL(ulStrLen, VOS_StrLen(acString));
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_02
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把acString的内容写入到acBuff
 *- @tbrief    
 *        -# 被测试函数返回拷贝的字节长度，要拷贝的最大长度小于字符串的长度
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_02()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_02";
    VOS_UINT32 uiMaxStrLen = 23;
    VOS_INT32 ulStrLen = 0;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff,uiMaxStrLen,acString);/*uiMaxStrLen must smaller than 64 and bigger than 21*/
    
    /*uiMaxStrLen的长度包括'\0'*/
    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    VOS_MemCmp(acBuff, acString, (VOS_SIZE_T)ulStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_03
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把acString的内容写入到acBuff
 *- @tbrief    
 *        -# 各种异常情况(acBuff为空、uiMaxStrLen为0、acString为空、arg为空)
 *          
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_03()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "Itest_VOS_nvsprintf_03";
    VOS_UINT32 uiMaxStrLen = 19;
    VOS_INT32 ulStrLen;

    ulStrLen = Tl_VOS_nvsprintf(VOS_NULL_PTR, uiMaxStrLen, acString);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);

    ulStrLen = Tl_VOS_nvsprintf(acBuff, 0, acString);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, VOS_NULL_PTR);
    CU_ASSERT_EQUAL(ulStrLen, (VOS_UINT32)-1);
    
/* 来自编译器SE魏哲:
    weizhe:
    va_list本质上就是指向栈上的一个指针，不同的平台上实现的定义略有不用。
    有的是char* 或者 void*,在arm上的gcc4.1之后严格按照arm的eabi定义，是一个结构（结构里面还是个指针）。
    我觉得 (NULL == arguments) 这个判断没有必要，可以删掉。
    因为va_list是一个指向栈的地址，只能通过va_start va_end va_arg这几个函数或宏来操作，不会是空指针。
    如果一定要写这个判断，可以试试这样改：
    (NULL == *(void**)&arguments)
    不过我还是建议删掉。
鉴于以上分析，将该用例注释;
    ulStrLen = VOS_nvsprintf(acBuff, uiMaxStrLen, acString, NULL);
    CU_ASSERT_EQUAL(ulStrLen, -1); */ 
    
}

/**
 *@test    Itest_VOS_nvsprintf_04
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把acString的内容写入到acBuff
 *- @tbrief    
 *        -# 被测试函数返回拷贝的字节长度，acString为'\0'
 *           
 *- @texpect   写入失败
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_04()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "\0";
    VOS_UINT32 uiMaxStrLen = 19;
    VOS_INT32 ulStrLen;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, acString);

    CU_ASSERT_EQUAL(ulStrLen, 0);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_05
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把内容写入到acBuff
 *- @tbrief    
 *        -# 缓存传入"5"，把内容写入acBuff，然后与acString相比较
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_05()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 5";
    VOS_UINT32 uiMaxStrLen = 16;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum = 5;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %ld", lNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_06
 *- @tspec    VOS_nvsprintf
 *- @ttitle    把内容写入到acBuff
 *- @tbrief    
 *        -# 缓存传入"-1"，把内容写入acBuff，然后与acString相比较
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_06()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test -1";
    VOS_UINT32 uiMaxStrLen = 17;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum = -1;
    
    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %d", lNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_07
 *- @tspec    VOS_nvsprintf
 *- @ttitle    读取64位无符号整型，"%llu"
 *- @tbrief    
 *        -# 缓存传入"0xffffffffffffffffULL"，把内容写入acBuff，然后与acString相比较
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_07()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 18446744073709551615";
    VOS_UINT32 uiMaxStrLen = 35;
    VOS_INT32 ulStrLen;
    VOS_UINT64 ullNum = 0xffffffffffffffffULL;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %llu", ullNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
 *@test    Itest_VOS_nvsprintf_08
 *- @tspec    VOS_nvsprintf
 *- @ttitle    读取64位整型，"%lld"
 *- @tbrief    
 *        -# 缓存传入"0x7fffffffffffffffULL"，把内容写入acBuff，然后与acString相比较
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */

 VOS_VOID Itest_VOS_nvsprintf_08()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 9223372036854775807";
    VOS_UINT32 uiMaxStrLen = 34;
    VOS_INT32 ulStrLen;
    VOS_INT64 ullNum = 0x7fffffffffffffffULL;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, "nvprintf test %lld", ullNum);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}
#endif
/**
 *@test    Itest_VOS_nvsprintf_09
 *- @tspec    VOS_nvsprintf
 *- @ttitle    传入多个整型
 *- @tbrief    
 *        -# 缓存传入"1","2","3","4"，把内容写入acBuff，然后与acString相比较
 *           
 *- @texpect   写入成功
 *- @tprior
 *- @tremark
 */
 VOS_VOID Itest_VOS_nvsprintf_09()
{
    VOS_CHAR acBuff[64];
    VOS_CHAR acString[64] = "nvprintf test 1 2 3 4";
    VOS_UINT32 uiMaxStrLen = 22;
    VOS_INT32 ulStrLen;
    VOS_INT32 lNum1 = 1;
    VOS_INT32 lNum2 = 2;
    VOS_INT32 lNum3 = 3;
    VOS_INT32 lNum4 = 4;

    ulStrLen = Tl_VOS_nvsprintf(acBuff, uiMaxStrLen, 
        "nvprintf test %d %d %d %d", lNum1, lNum2, lNum3, lNum4);

    CU_ASSERT_EQUAL(ulStrLen + 1, uiMaxStrLen);
    CU_ASSERT_EQUAL(0,strcmp(acBuff, acString));
}

/**
*@test Itest_VOS_sprintf_FUNC_001
*- @tspec
*- @ttitle VOS_sprintf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_sprintf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断返回位数
           3.判断打印数值与实际值
*- @texpect 1.输出返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
#ifndef SECUREC_ON_64BITS
VOS_VOID Itest_VOS_sprintf_FUNC_001()
{
    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32位 有符号数 最大值 */
    VOS_UINT32 uiNum = 4294967295UL;  /* 32位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_sprintf(scBuffer, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "37777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "ffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);    
}
/**
*@test Itest_VOS_nsprintf_FUNC_001
*- @tspec
*- @ttitle VOS_nsprintf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_nsprintf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断返回位数
           3.判断打印数值与实际值
*- @texpect 1.输出返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_001()
{
    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32位 有符号数 最大值 */
    VOS_UINT32 uiNum = 4294967295UL;  /* 32位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_nsprintf(scBuffer, 64, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "37777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "ffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 8);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_001
*- @tspec
*- @ttitle VOS_sscanf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_sscanf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断输入返回位数
           3.判断输入数值与实际值是否一步
*- @texpect 1.输入返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_001()
{
    //VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T uiNumFirst   = 2147483647;  /* 32位 有符号数 最大值 */
    VOS_SIZE_T iNumAdd = 0;
    VOS_UINT32 uiNum = 4294967295UL;  /* 32位 无符号数 最大值 */  
    VOS_UINT32 uiNumAdd;
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_sscanf("z", "%zc", scBuffer,sizeof(scBuffer));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("2147483647", "%zd", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, uiNumFirst);

    uiRet = VOS_sscanf("2147483647", "%zi", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, uiNumFirst);

    uiRet = VOS_sscanf("37777777777", "%zo", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("4294967295", "%zu", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("ffffffff", "%zx", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("FFFFFFFF", "%zX", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);
}

/**
*@test Itest_VOS__vsprintf_FUNC_001
*- @tspec
*- @ttitle VOS_vsprintf/ VOS_nvsprintf与'zd'组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_vsprintf/ VOS_nvsprintf分别与'zd'组合
           2.判断输入返回位数
           3.判断输入数值与实际值是否一步
*- @texpect 1.正确返回位数
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

/* VOS_vsprintf/ VOS_nvsprintf涉及可变参数列表指针，以下两函数用于封装该列表指针 */



VOS_VOID Itest_VOS__vsprintf_FUNC_001()
{   
 //   VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32位 有符号数 最大值 */
   // VOS_UINT32 uiNum = 4294967295;  /* 32位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* VOS_vsprintf/ VOS_nvsprintf分别格式控制字符串"%zd"组合 */
    uiRet = Test_VOS_vsprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = Test_VOS_nvsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
   
}

/**
*@test Itest_VOS_sprintf_FUNC_002
*- @tspec
*- @ttitle VOS_sprintf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_sprintf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_002()
{
//    VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32位 有符号数 最大值 */
  //  VOS_UINT32 uiNum = 4294967295;  /* 32位 无符号数 最大值 */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */
   
    iRet = VOS_sprintf(scBuffer, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
    
    //printf("\n%d-", VOS_nsprintf(scBuffer, 64, "%Zd", Num));
    /* printf("\n\r scBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);
   
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
    */
    /*
    uiRet = VOS_sprintf(scBuffer, "%dz", iNum);
    printf("\n\r scBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);

    pcBuffer = VOS_MemSet(scBuffer,0,(sizeof(VOS_CHAR)*64));
    printf("\n\r scBuffer is %p\r \n", scBuffer);
    
    CU_ASSERT_EQUAL(uiRet, 10);
    uiRet = VOS_StrCmp(scBuffer, "2147483647");
    CU_ASSERT_EQUAL(uiRet, 0);
    */
/*
    uiRet = VOS_sprintf(scBuffer, "%zz", uiNum);
    printf("\n\rscBuffer is %p,\r the bit is %u\n", scBuffer,uiRet);
    
    CU_ASSERT_EQUAL(uiRet, 11);
    uiRet = VOS_StrCmp(scBuffer, "4294967295");
    CU_ASSERT_EQUAL(uiRet, 0);
    */

}

/**
*@test Itest_VOS_nsprintf_FUNC_002
*- @tspec
*- @ttitle VOS_nsprintf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_nsprintf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_002()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = 2147483647;  /* 32位 有符号数 最大值 */
 //   VOS_UINT32 uiNum = 4294967295;  /* 32位 无符号数 最大值 */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */
   
    iRet = VOS_nsprintf(scBuffer, 64, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_sscanf_FUNC_002
*- @tspec
*- @ttitle VOS_sscanf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_sscanf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_002()
{
    //VOS_INT32 iNumAdd   = 2147483647;  /* 32位 有符号数 最大值 */
    VOS_SIZE_T iNumAdd = 4294967295UL;  /* 32位 无符号数 最大值 */  
    VOS_INT32 iRet = 0;
    //VOS_CHAR scBuffer[64] = {0};
  
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */
   
    
    iRet = VOS_sscanf("2147483647", "%Zd", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

    iRet = VOS_sscanf("2147483647", "%dz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

    iRet = VOS_sscanf("2147483647", "%zz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zd\n", iNumAdd); 

}
#endif

#ifdef SECUREC_ON_64BITS
/**
*@test Itest_VOS_sprintf_FUNC_003
*- @tspec
*- @ttitle VOS_sprintf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_sprintf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断返回位数
           3.判断打印数值与实际值
*- @texpect 1.输出返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_003()
{
    VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64位 有符号数 最大值 */
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_sprintf(scBuffer, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 22);
    uiRet = VOS_StrCmp(scBuffer, "1777777777777777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 20);
    uiRet = VOS_StrCmp(scBuffer, "18446744073709551615");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "ffffffffffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sprintf(scBuffer, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFFFFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_nsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_nsprintf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_nsprintf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断返回位数
           3.判断打印数值与实际值
*- @texpect 1.输出返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_003()
{
    VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64位 有符号数 最大值 */
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_nsprintf(scBuffer, 64, "%zc", cBuffer);
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBuffer, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zi", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zo", uiNum);
    CU_ASSERT_EQUAL(uiRet, 22);
    uiRet = VOS_StrCmp(scBuffer, "1777777777777777777777");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zu", uiNum);
    CU_ASSERT_EQUAL(uiRet, 20);
    uiRet = VOS_StrCmp(scBuffer, "18446744073709551615");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zx", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "ffffffffffffffff");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_nsprintf(scBuffer, 64, "%zX", uiNum);
    CU_ASSERT_EQUAL(uiRet, 16);
    uiRet = VOS_StrCmp(scBuffer, "FFFFFFFFFFFFFFFF");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_003
*- @tspec
*- @ttitle VOS_sscanf使用’z’分别与cdiouxX组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_sscanf使用’z’分别与c、d、i、o、u、x、X组合
           2.判断输入返回位数
           3.判断输入数值与实际值是否一步
*- @texpect 1.输入返回位数正确
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_003()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64位 有符号数 最大值 */
    VOS_INT64 iNumAdd;
    VOS_SIZE_T uiNum = 18446744073709551615UL;  /* 64位 无符号数 最大值 */  
    VOS_SIZE_T uiNumAdd;
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBufferAdd[64] = {0};

    /* 该接口分别与格式控制字符串"%zc"、"%zd"、"%zi"、"%zo"、"%zu"、"%zx"、"%zX"组合 */
    uiRet = VOS_sscanf("z", "%zc", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBufferAdd, "z");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("9223372036854775807", "%zd", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, iNum);

    uiRet = VOS_sscanf("9223372036854775807", "%zi", &iNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(iNumAdd, iNum);

    uiRet = VOS_sscanf("1777777777777777777777", "%zo", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("18446744073709551615", "%zu", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("ffffffffffffffff", "%zx", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);

    uiRet = VOS_sscanf("FFFFFFFFFFFFFFFF", "%zX", &uiNumAdd);    
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(uiNumAdd, uiNum);
}

/**
*@test Itest_VOS__vsprintf_FUNC_002
*- @tspec
*- @ttitle VOS_vsprintf/ VOS_nvsprintf与'zd'组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_vsprintf/ VOS_nvsprintf分别与'zd'组合
           2.判断输入返回位数
           3.判断输入数值与实际值是否一步
*- @texpect 1.正确返回位数
            2.打印数值与实际值一致
*- @tprior 1
*- @tauto True
*- @tremark
*/

VOS_VOID Itest_VOS__vsprintf_FUNC_002()
{
   // VOS_CHAR cBuffer = 'z';
    VOS_INT64 iNum   = 9223372036854775807;  /* 64位 有符号数 最大值 */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64位 无符号数 最大值 */  
    VOS_INT32 uiRet = 0;
    VOS_CHAR scBuffer[64] = {0};

    /* VOS_vsprintf/ VOS_nvsprintf分别格式控制字符串"%zd"组合 */
    uiRet = Test_VOS_vsprintf(scBuffer, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = Test_VOS_nvsprintf(scBuffer, 64, "%zd", iNum);
    CU_ASSERT_EQUAL(uiRet, 19);
    uiRet = VOS_StrCmp(scBuffer, "9223372036854775807");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sprintf_FUNC_004
*- @tspec
*- @ttitle VOS_sprintf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_sprintf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sprintf_FUNC_004()
{
    //VOS_CHAR cBuffer = 'z';
    VOS_SIZE_T iNum   = (VOS_SIZE_T)9223372036854775807;  /* 64位 有符号数 最大值 */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64位 无符号数 最大值 */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */
   
    iRet = VOS_sprintf(scBuffer, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_sprintf(scBuffer, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_nsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_nsprintf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_nsprintf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_nsprintf_FUNC_004()
{
    VOS_SIZE_T iNum   = (VOS_SIZE_T)9223372036854775807;  /* 64位 有符号数 最大值 */
    //VOS_UINT64 uiNum = 18446744073709551615;  /* 64位 无符号数 最大值 */  
    VOS_INT32 iRet = 0;
    VOS_CHAR scBuffer[64] = {0};
  
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */
   
    iRet = VOS_nsprintf(scBuffer, 64, "%Zd", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%dz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer); 

    iRet = VOS_nsprintf(scBuffer, 64, "%zz", iNum);
    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n scBuffer is %s\n", scBuffer);
}

/**
*@test Itest_VOS_sscanf_FUNC_004
*- @tspec
*- @ttitle VOS_sscanf与'Zd'、'dz'、'zz'组合
*- @tprecon DOPRA默认配置，64位系统
*- @tbrief 1.VOS_sscanf与'Zd'、'dz'、'zz'组合
           2.判断输入返回位数范围
           
*- @texpect 1.返回位数范围正确
            2.用例正常执行，无异常
*- @tprior 1
*- @tauto False
*- @tremark
*/

VOS_VOID Itest_VOS_sscanf_FUNC_004()
{
    VOS_SIZE_T iNumAdd = (VOS_SIZE_T)9223372036854775807;  /* 64位 有符号数 最大值 */  
    VOS_INT32 iRet = 0;
      
    /* 该接口分别与非法格式控制字符串"Zd"、"dz"、"zz"组合 */    
    iRet = VOS_sscanf("9223372036854775807", "%Zd", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 

    iRet = VOS_sscanf("9223372036854775807", "%dz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 

    iRet = VOS_sscanf("9223372036854775807", "%zz", &iNumAdd);    

    VOS_Printf("\n the return num. is %d",iRet);
    VOS_Printf("\n iNumAdd is %zu\n", iNumAdd); 
}
#endif
#endif
/**
*@test Itest_VOS_sscanf_FUNC_005
*- @tspec
*- @ttitle VOS_sscanf与"%i"组合
*- @tprecon DOPRA默认配置，32位系统
*- @tbrief 1.VOS_sscanf与"%i"组合
           2.判断输入返回值正确
           
*- @texpect 1.输入返回值正确
     
*- @tprior 1
*- @tauto False
*- @tremark DTS2013040801523 
*/

VOS_VOID Itest_VOS_sscanf_FUNC_005()
{
    VOS_INT32  siNum1 = 0x12345678;
    VOS_INT32  siNum2 = 0;   
    VOS_CHAR   scTmpBuf[50] = {0};

    VOS_sprintf(scTmpBuf, "%i", siNum1);
    CU_ASSERT_EQUAL(VOS_sscanf(scTmpBuf, "%i", &siNum2), 1);
    CU_ASSERT_EQUAL(siNum1, siNum2);
    //printf("\n siNum1 is %d \n",siNum1);
    //printf("\n siNum2 is %d \n",siNum2);
}

/**
*@test Itest_VOS_sprintf_FUNC_006
*- @tspec
*- @ttitle VOS_sprintf函数对0x80000000处理正确

*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf函数对0x80000000处理
           2.判断输入返回值正确
           
*- @texpect 1.输入返回值正确
     
*- @tprior 1
*- @tauto False
*- @tremark DTS2013062508226 
*/

VOS_VOID Itest_VOS_sprintf_FUNC_006()
{
    unsigned long dwVal = 0x80000000;
    char acOutputString[64];
    memset(acOutputString, 0, sizeof(acOutputString));
     
    (void)VOS_sprintf(acOutputString, "%ld", (signed long)dwVal);
    //printf("ld fmt signed long=%s(%lu)\r\n", acOutputString, dwVal);
#ifdef SECUREC_ON_64BITS    
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(0,strcmp(acOutputString, "-2147483648"));
    #else
    CU_ASSERT_EQUAL(0,strcmp(acOutputString, "2147483648"));
    #endif
#else
    CU_ASSERT_EQUAL(0,strcmp(acOutputString, "-2147483648"));
#endif

}


VOS_UINT32 test_CompareStringError(const char * pStringA, const char * pStringB)
{
    VOS_INT32 iRet;

    iRet = VOS_StrCmp(pStringA,pStringB);

    if (0 != iRet)
    {
        VOS_Printf("\nASSERT_ERROR! pStringA: %s ,  pStringB: %s \n", pStringA, pStringB);
        return VOS_ERROR;
    }

    return VOS_OK;
}

/**
*@test Itest_VOS_nsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_nsprintf与"%ld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%ld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long int tempNum1 = 0;
    long int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0x7fffffff; // 2147483647
    tempNum2 = 0x80000000; //-2147483648

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    #if (defined(COMPATIBLE_WIN_FORMAT))
    VOS_INT64 tempNum11 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64 tempNum22 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum11);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum22);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #else
    tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_nsprintf与"%lu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%lu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 429 496 729 5
    tempNum2 = 0; 


    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    tempNum2 = 0; //

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);    
    #else
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_nsprintf与"%lld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%lld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    #ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*    9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;       /* -9223372036854775808     20个字符*/


    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*    9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000;       /* -9223372036854775808     20个字符*/

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_nsprintf与"%llu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%llu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS
    unsigned   long  long  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20个字符
    unsigned   long  long  tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }
#endif 
/**
*@test Itest_VOS_nsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_nsprintf与"%x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_010
*- @tspec
*- @ttitle VOS_nsprintf与"%#x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%#x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_011
*- @tspec
*- @ttitle VOS_nsprintf与"%X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nsprintf与"%#X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%#X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nsprintf与"%p"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%p"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = VOS_nsprintf(sBuff, 64, "%p", pTemp);
    
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    #else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19个字符

    iRet = VOS_nsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
    
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_nsprintf与"%lx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%lx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 268435455
    tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%#lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_nsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_nsprintf_FUNC_015
*- @tspec
*- @ttitle VOS_nsprintf与"%llx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nsprintf与"%llx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nsprintf_FUNC_015()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
 
    #ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_nsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif

 }
#endif 
/**
*@test Itest_VOS_sprintf_FUNC_005
*- @tspec
*- @ttitle VOS_sprintf与"%ld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%ld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long int tempNum1 = 0;
    long int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0x7fffffff;         /* 2147483647  10个字符*/
    tempNum2 = 0x80000000;        /*-2147483648 11个字符*/

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    #if (defined(COMPATIBLE_WIN_FORMAT))
    VOS_INT64 tempNum11 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64 tempNum22 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = VOS_sprintf(sBuff,  "%lld", tempNum11);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lld", tempNum22);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #else
    tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_006
*- @tspec
*- @ttitle VOS_sprintf与"%lu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%lu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_006_1()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 429 496 729 5
    tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    tempNum2 = 0; //

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_007
*- @tspec
*- @ttitle VOS_sprintf与"%lld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%lld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
 VOS_VOID Itest_VOS_sprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*    9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;       /* -9223372036854775808     20个字符*/


    iRet = VOS_sprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*    9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000;       /* -9223372036854775808     20个字符*/

    iRet = VOS_sprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_008
*- @tspec
*- @ttitle VOS_sprintf与"%llu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%llu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
 
    #ifndef SECUREC_ON_64BITS
    VOS_UINT64  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64  tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = VOS_sprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = VOS_sprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif

 }
#endif

/**
*@test Itest_VOS_sprintf_FUNC_009
*- @tspec
*- @ttitle VOS_sprintf与"%x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_010
*- @tspec
*- @ttitle VOS_sprintf与"%#x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%#x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_011
*- @tspec
*- @ttitle VOS_sprintf与"%X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = VOS_sprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_012
*- @tspec
*- @ttitle VOS_sprintf与"%#X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%#X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_sprintf与"%p"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%p"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = VOS_sprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

    iRet = VOS_sprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19个字符

    iRet = VOS_sprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = VOS_sprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_014
*- @tspec
*- @ttitle VOS_sprintf与"%lx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%lx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    long unsigned int tempNum1 = 0;
    long unsigned int tempNum2 = 0;
    
    #ifndef SECUREC_ON_64BITS
    tempNum1 = 0xffffffff; // 268435455
   tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%#lx", tempNum1);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
    #else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
    #endif

    iRet = VOS_sprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_015
*- @tspec
*- @ttitle VOS_sprintf与"%llx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sprintf与"%llx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sprintf_FUNC_015()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))  
    #ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = VOS_sprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_vsprintf与"%ld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%ld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_003()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10个字符*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11个字符*/

    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_vsprintf(sBuff,  "%lld", tempNum1);
#else
    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum1);
#endif
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_vsprintf(sBuff,  "%lld", tempNum2);
#else
    iRet = Test_VOS_vsprintf(sBuff,  "%ld", tempNum2);
#endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_vsprintf与"%lu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%lu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_004()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    #ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 429 496 729 5
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

    #else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; //
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%llu", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum1);
    #endif

    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
    #endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_vsprintf与"%lld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%lld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_vsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    #ifndef SECUREC_ON_64BITS

    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;        /* -9223372036854775808     20个字符*/

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

    #else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
    #endif
 }
#endif 
/**
*@test Itest_VOS_vsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_vsprintf与"%llu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%llu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))  
#ifndef SECUREC_ON_64BITS
    unsigned   long  long  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20个字符
    unsigned   long  long  tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
#endif
 }


/**
*@test Itest_VOS_vsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_vsprintf与"%x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_vsprintf与"%#x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%#x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_vsprintf与"%X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_vsprintf与"%#X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%#X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_vsprintf与"%p"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%p"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = Test_VOS_vsprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    iRet = Test_VOS_vsprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    printf("%s\n",sBuff);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19个字符

    iRet = Test_VOS_vsprintf(sBuff,  "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = Test_VOS_vsprintf(sBuff,  "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_vsprintf与"%lx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%lx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    #else
    iRet = Test_VOS_vsprintf(sBuff,  "%#lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_vsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_vsprintf与"%llx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%llx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_vsprintf_FUNC_013()
{ 
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64 tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_INT64 tempNum2 = 0; 

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
#endif

 }
#endif 
/**
*@test Itest_VOS_vsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_vsprintf与"%d"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_vsprintf与"%d"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_vsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10个字符*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11个字符*/

    iRet = Test_VOS_vsprintf(sBuff,  "%d", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_vsprintf(sBuff,  "%d", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_003
*- @tspec
*- @ttitle VOS_nvsprintf与"%ld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%ld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_003()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10个字符*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11个字符*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);

#else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
#else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum1);
#endif
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
#else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%ld", tempNum2);
#endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_004
*- @tspec
*- @ttitle VOS_nvsprintf与"%lu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%lu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_004()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 429 496 729 5
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "4294967295"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; //
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);
    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lu", tempNum2);
    #endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_005
*- @tspec
*- @ttitle VOS_nvsprintf与"%lld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%lld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_FUNC_005()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT64  tempNum1 = 0x7fffffffffffffffLL;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = (VOS_INT64)0x8000000000000000LL;        /* -9223372036854775808     20个字符*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);

#else
    VOS_INT64  tempNum1 = 0x7fffffffffffffff;        /*   9223372036854775807       19个字符*/
    VOS_INT64  tempNum2 = 0x8000000000000000;        /* -9223372036854775808     20个字符*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum1);
    CU_ASSERT_EQUAL(iRet, 19);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "9223372036854775807"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lld", tempNum2);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-9223372036854775808"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_006
*- @tspec
*- @ttitle VOS_nvsprintf与"%llu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%llu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_006()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64  tempNum1 = 0xffffffffffffffffLL; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64  tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //184 467 440 737 095 516 15     20个字符
    VOS_UINT64 tempNum2 = 0; 
    
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum1);
    CU_ASSERT_EQUAL(iRet, 20);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "18446744073709551615"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llu", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }
#endif
/**
*@test Itest_VOS_nvsprintf_FUNC_007
*- @tspec
*- @ttitle VOS_nvsprintf与"%x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_007()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_008
*- @tspec
*- @ttitle VOS_nvsprintf与"%#x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%#x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_008()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#x", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_009
*- @tspec
*- @ttitle VOS_nvsprintf与"%X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_009()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0;

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nvsprintf与"%#X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%#X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_010()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum1 = 0xffffffff; // 268435455
    VOS_UINT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#else
    VOS_UINT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_UINT64 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#X", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_sprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nvsprintf与"%p"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%p"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_011()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffff; // 268435455

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif
    
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);
#endif

#else
    VOS_VOID *pTemp = (VOS_VOID *)0xffffffffffffffff; //115292 150460 684697 5      19个字符

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "FFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__UNIX)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#p", pTemp);
#if defined(_MSC_VER)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0XFFFFFFFFFFFFFFFF"), VOS_OK);
#elif defined(__hpux)
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#elif defined(_AIX) || defined(__SOLARIS)
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);
#else
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);
#endif
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_012
*- @tspec
*- @ttitle VOS_nvsprintf与"%lx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%lx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_012()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32 tempNum1 = (VOS_INT32)0xffffffff; // 268435455
    VOS_INT32 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 8);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#lx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_INT64 tempNum2 = 0; 
    #if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    #else
    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#lx", tempNum1);
    #endif
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    #if (defined(COMPATIBLE_WIN_FORMAT))
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    #else
	iRet = Test_VOS_nvsprintf(sBuff, 64, "%lx", tempNum2);
    #endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }

/**
*@test Itest_VOS_nvsprintf_FUNC_013
*- @tspec
*- @ttitle VOS_nvsprintf与"%llx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%llx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
 VOS_VOID Itest_VOS_nvsprintf_FUNC_013()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;
    
#ifndef SECUREC_ON_64BITS
    unsigned long long tempNum1 = 0xffffffffffffffffLL; // 1152921504606846975
    unsigned long long tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);

#else
    VOS_INT64 tempNum1 = 0xffffffffffffffff; //115292 150460 684697 5      19个字符
    VOS_INT64 tempNum2 = 0; 

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 16);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "ffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%#llx", tempNum1);
    CU_ASSERT_EQUAL(iRet, 18);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0xffffffffffffffff"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%llx", tempNum2);
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "0"), VOS_OK);
#endif
 }
#endif
/**
*@test Itest_VOS_nvsprintf_FUNC_014
*- @tspec
*- @ttitle VOS_nvsprintf与"%d"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_nvsprintf与"%d"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_nvsprintf_FUNC_014()
{    
    VOS_CHAR sBuff[64] = {0};  
    VOS_INT32 iRet;

    VOS_INT32     tempNum1 = 0x7fffffff;         /* 2147483647  10个字符*/
    VOS_INT32     tempNum2 = (VOS_INT32)0x80000000;        /*-2147483648 11个字符*/

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%d", tempNum1);
    CU_ASSERT_EQUAL(iRet, 10);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "2147483647"), VOS_OK);

    iRet = Test_VOS_nvsprintf(sBuff, 64, "%d", tempNum2);
    CU_ASSERT_EQUAL(iRet, 11);
    CU_ASSERT_EQUAL(test_CompareStringError(sBuff, "-2147483648"), VOS_OK);
 }

/**
*@test Itest_VOS_sscanf_FUNC_006
*- @tspec
*- @ttitle VOS_sscanf与"%ld"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%ld"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_006()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_INT32 tempNum = 0;

    iRet = VOS_sscanf("2147483647", "%ld", &tempNum);  /* 0x7fffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x7fffffff);

    iRet = VOS_sscanf("-2147483648", "%ld", &tempNum); /* 0x80000000 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x80000000);

#else
    VOS_INT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("9223372036854775807", "%lld", &tempNum);  /* 0x7fffffffffffffff */
#else
    iRet = VOS_sscanf("9223372036854775807", "%ld", &tempNum);  /* 0x7fffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x7fffffffffffffff);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("-9223372036854775808", "%lld", &tempNum); /* 0x8000000000000000 */
#else
    iRet = VOS_sscanf("-9223372036854775808", "%ld", &tempNum); /* 0x8000000000000000 */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0x8000000000000000);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_007
*- @tspec
*- @ttitle VOS_sscanf与"%lu"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%lu"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_007()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("4294967295", "%lu", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%lu", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("18446744073709551615", "%llu", &tempNum);  /* 0xffffffffffffffff */
#else
    iRet = VOS_sscanf("18446744073709551615", "%lu", &tempNum);  /* 0xffffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("0", "%llu", &tempNum); /* 0 */
#else
    iRet = VOS_sscanf("0", "%lu", &tempNum); /* 0 */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_008
*- @tspec
*- @ttitle VOS_sscanf与"%x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_008()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%x", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%x", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%llx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_009
*- @tspec
*- @ttitle VOS_sscanf与"%#x"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%#x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_009()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;
    iRet = VOS_sscanf("0xffffffff", "%#x", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#x", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("0xffffffff", "%#llx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);


    iRet = VOS_sscanf("0", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#endif/* 处理不了#号 */
 }


/**
*@test Itest_VOS_sscanf_FUNC_010
*- @tspec
*- @ttitle VOS_sscanf与"%X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_010()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("FFFFFFFF", "%X", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%X", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("FFFFFFFF", "%llX", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_011
*- @tspec
*- @ttitle VOS_sscanf与"%#X"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%#X"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_011()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;
    
    iRet = sscanf("0XFFFFFFFF", "%#X", &tempNum);
    iRet = VOS_sscanf("0XFFFFFFFF", "%#X", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#X", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("0XFFFFFFFF", "%#llX", &tempNum);  /* 0XFFFFFFFF */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

    iRet = VOS_sscanf("0", "%#llX", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0);

#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_012
*- @tspec
*- @ttitle VOS_sscanf与"%p"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%x"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_012()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 * pTemp = VOS_NULL_PTR;

    iRet = VOS_sscanf("ffffffff", "%p", &pTemp);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, (VOS_UINT32 *)0xffffffff);

    iRet = VOS_sscanf("0", "%x", &pTemp); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, 0);

#else
    VOS_UINT64 * pTemp = VOS_NULL_PTR;

    iRet = VOS_sscanf("ffffffff", "%llx", &pTemp);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((long)pTemp, (long)0xffffffff);

    iRet = VOS_sscanf("0", "%llx", &pTemp); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(pTemp, 0);
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_013
*- @tspec
*- @ttitle VOS_sscanf与"%lx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%#lx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_013()
{    
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT32 tempNum = 0;

    iRet = VOS_sscanf("ffffffff", "%lx", &tempNum);  /* 0xffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);

#if 0
    tempNum = 0;
    iRet = VOS_sscanf("0xffffffff", "%#lx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffff);
#endif/* 处理不了#号 */

#else
    VOS_UINT64 tempNum = 0;
#if (defined(COMPATIBLE_WIN_FORMAT))
    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
#else
    iRet = VOS_sscanf("ffffffffffffffff", "%lx", &tempNum);  /* 0xffffffffffffffff */
#endif
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);

#if 0
    tempNum = 0;
    iRet = VOS_sscanf("0xffffffffffffffff", "%#lx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#endif/* 处理不了#号 */
#endif
 }


/**
*@test Itest_VOS_sscanf_FUNC_014
*- @tspec
*- @ttitle VOS_sscanf与"%llx"组合
*- @tprecon DOPRA默认配置
*- @tbrief 1.VOS_sscanf与"%#llx"组合
                   2.判断输入返回值正确
*- @texpect 1.输入返回值正确
*- @tprior 1
*- @tauto True
*- @tremark 
*/

 VOS_VOID Itest_VOS_sscanf_FUNC_014()
{  
#if !(defined(_MSC_VER) &&(1200 == _MSC_VER))
    VOS_INT32 iRet;

    /* VOS_sscanf的功能是从字符串里解析数字 */
    
#ifndef SECUREC_ON_64BITS
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((tempNum== 0xffffffffffffffffLL), 1);
#if 0
    iRet = VOS_sscanf("0xffffffffffffffff", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL((tempNum== 0xffffffffffffffffLL), 1);
#endif/* 处理不了#号 */

#else
    VOS_UINT64 tempNum = 0;

    iRet = VOS_sscanf("ffffffffffffffff", "%llx", &tempNum);  /* 0xffffffffffffffff */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#if 0
    iRet = VOS_sscanf("0xffffffffffffffff", "%#llx", &tempNum); /* 0 */
    CU_ASSERT_EQUAL(iRet, 1);
    CU_ASSERT_EQUAL(tempNum, 0xffffffffffffffff);
#endif/* 处理不了#号 */
#endif
#endif
 }

/**
*@test Itest_VOS_sscanf_FUNC_015
*- @tspec
*- @ttitle VOS_sscanf与'%[]'组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf 与'%[]'组合
           2.通过%[]格式化字符串
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_015()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_CHAR scBufferAdd2[10]="StringErr"; 
    VOS_INT32 uiRet = 0;

    uiRet = VOS_sscanf("sscanf-noinit-alinit", "sscanf-%[a-z]-%s", scBufferAdd, sizeof(scBufferAdd),scBufferAdd2,sizeof(scBufferAdd2));
    CU_ASSERT_EQUAL(uiRet, 2);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    /*检测%[]格式化字符串是否会在末尾添加'\0'                     */
    /*若添加'\0', 则应当输出noinit，若没有加,则输出noinitErr*/
    uiRet = VOS_StrCmp(scBufferAdd, "noinit");
    CU_ASSERT_EQUAL(uiRet, 0);

  /*  uiRet = VOS_StrCmp(scBufferAdd2, "alinit");
    CU_ASSERT_EQUAL(uiRet, 0);*//*secure funxtion return StringErr*/
}

/**
*@test Itest_VOS_sscanf_FUNC_016
*- @tspec
*- @ttitle VOS_sscanf与'%[^]'组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf 与'%[^]'组合
           2.通过%[]格式化字符串
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_016()
{
    VOS_CHAR scBufferAdd[]="HELLOworld"; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("HELLOworld", "%[^a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    /*检测%[]格式化字符串是否会在末尾添加'\0' */
    uiRet = VOS_StrCmp(scBufferAdd, "HELLO");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("notepad=1.0.0.641", "%[^=]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "notepad");
    CU_ASSERT_EQUAL(uiRet, 0);

    uiRet = VOS_sscanf("123abcBCDEF", "%[^C-Z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123abcB");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_017
*- @tspec
*- @ttitle VOS_sscanf 与'%[]'组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf 与'%[]'组合
           2.通过%[]格式化字符串
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_017()
{
    VOS_CHAR scBufferAdd[64]; 
    VOS_CHAR scBufferAdd2[64]; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("123456a=AAbcCCdedfBCDEF", "%[1-9a-z]=%s", scBufferAdd,sizeof(scBufferAdd), scBufferAdd2,sizeof(scBufferAdd2));
    CU_ASSERT_EQUAL(uiRet, 2);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123456a");
    CU_ASSERT_EQUAL(uiRet, 0);

    /*uiRet = VOS_StrCmp(scBufferAdd2, "AAbcCCdedfBCDEF");
    CU_ASSERT_EQUAL(uiRet, 0);*//*securec function return ......123456a*/
}

/**
*@test Itest_VOS_sscanf_FUNC_018
*- @tspec
*- @ttitle VOS_sscanf * 与'%[^]'组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf * 与'%[^]'组合
           2.通过%[]格式化字符串
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_018()
{
    VOS_CHAR scBufferAdd[64]={0}; 
    VOS_INT32 uiRet = 0;
    
    uiRet = VOS_sscanf("notepad=1.2@#4", "%*[^=]=%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "1.2@#4");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/**
*@test Itest_VOS_sscanf_FUNC_019
*- @tspec
*- @ttitle VOS_sscanf  *与别的格式化字符组合s c d i  o u x X
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf * 与别的格式化字符组合
           2.通过*格式化字符串
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_019()
{
    VOS_CHAR scBufferAdd[]="HELLOworld"; 
    VOS_INT32 uiRet = 0;
    VOS_INT32 tempNum = 0;
    long int tempNum2 = 0;
    VOS_UINT32 utempNum = 0;
    VOS_CHAR scBuffer[10] = {0};

    /* '*'与%ld组合*/
#ifndef SECUREC_ON_64BITS
    tempNum2 = 0;
    uiRet = VOS_sscanf("2147483647,2147483646", "%*ld,%ld", &tempNum2);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum32 : %ld", tempNum32);
    CU_ASSERT_EQUAL(tempNum2, 0x7FFFFFFE);
    
#else
    tempNum2 = 0;
    uiRet = VOS_sscanf("9223372036854775807,9223372036854775806", "%*ld,%ld", &tempNum2);  /* 0x7fffffffffffffff */
    CU_ASSERT_EQUAL(uiRet, 1);
    printf("\r\n tempNum64 : %ld", tempNum2);
    CU_ASSERT_EQUAL(tempNum2, 0x7FFFFFFFFFFFFFFE);
#endif
    
    /* '*'与%s组合*/
    uiRet = VOS_sscanf("hello WORLD", "%*s%*c%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "WORLD");
    CU_ASSERT_EQUAL(uiRet, 0);

    /* '*'与%i 组合*/
    uiRet = VOS_sscanf("1234()2147483647", "%*i()%i", &tempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %i", tempNum);
    CU_ASSERT_EQUAL(tempNum, 2147483647);

    /* '*'与%o组合*/
    uiRet = VOS_sscanf("1234~77777", "%*o~%o", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %o", tempNum);
    CU_ASSERT_EQUAL(utempNum, 32767);
    
    /* '*'与%x组合*/
    uiRet = VOS_sscanf("abcd^ffffffff", "%*x^%x", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %x", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);
    
    /* '*'与%X组合*/
    uiRet = VOS_sscanf("ABCD@FFFFFFFF", "%*X@%X", &utempNum);
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %X", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);
    
    /* '*'与%u组合*/
    uiRet = VOS_sscanf("4294967293#4294967295", "%*u#%u", &utempNum);    
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %u", tempNum);
    CU_ASSERT_EQUAL(utempNum, 4294967295UL);

    /* '*'与%c组合*/
    uiRet = VOS_sscanf("x$y", "%*c$%c", scBuffer,sizeof(scBuffer));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %s", scBuffer);
    uiRet = VOS_StrCmp(scBuffer, "y");
    CU_ASSERT_EQUAL(uiRet, 0);

}

/**
*@test Itest_VOS_sscanf_FUNC_020
*- @tspec
*- @ttitle VOS_sscanf  "%hd" "%hu" "%hi"组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"%hd" "%hu" "%hi"组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_020()
{
    VOS_INT32 uiRet = 0;
    VOS_INT16 tempNum = 0;

    /*%hd格式化字符串*/
    uiRet = VOS_sscanf("32767", "%hd", &tempNum);  /* 0x7fff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 0x7fff);

    uiRet = VOS_sscanf("-32768", "%hd", &tempNum); /* 0x8000 */
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, -32768);
    
    /*%hi格式化字符串*/
    uiRet = VOS_sscanf("32767", "%hi", &tempNum); 
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 32767);

}

/**
*@test Itest_VOS_sscanf_FUNC_021
*- @tspec
*- @ttitle VOS_sscanf  "%ho" "%hx" "%hX"组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"%ho" "%hx" "%hX"组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_021()
{
    VOS_INT32 uiRet = 0;
    VOS_UINT16 tempNum = 0;

    /*%ho格式化字符串*/
    uiRet = VOS_sscanf("77777", "%ho", &tempNum);  /* 0x7fff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum : %d", tempNum);
    CU_ASSERT_EQUAL(tempNum, 32767);

    /*%hu格式化字符串*/
    uiRet = VOS_sscanf("65535", "%hu", &tempNum);  /* 0xffff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 0xffff);

    uiRet = VOS_sscanf("0", "%hu", &tempNum); /* 0*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 0);
    
    /*%hx格式化字符串*/
    uiRet = VOS_sscanf("ffff", "%hx", &tempNum);  /* 0xffff*/
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 65535);

    /*%hX格式化字符串*/
    uiRet = VOS_sscanf("FFFF", "%hX", &tempNum); 
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n tempNum2 : %d", tempNum2);
    CU_ASSERT_EQUAL(tempNum, 65535);

}

/**
*@test Itest_VOS_sscanf_FUNC_022
*- @tspec
*- @ttitle VOS_sscanf "n"与s, d,i,0,u,x,X组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"n"与s, d,i,0,u,x,X组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_022()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_INT32 uiRet = 0;
    VOS_INT32 tempNum1 = 0;
    VOS_INT32 tempNum2 = 0;
    VOS_UINT32 utempNum1 = 0;

    /*%ns格式化字符串*/
    VOS_MemSet(scBufferAdd,0,sizeof(scBufferAdd));
    uiRet = VOS_sscanf("abcdef", "%5s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    uiRet = VOS_StrCmp(scBufferAdd, "abcde");
    CU_ASSERT_EQUAL(uiRet, 0);
   
    /*%nd格式化字符串*/
    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = sscanf("123456", "%3d%3d", &tempNum1, &tempNum2); 

    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = VOS_sscanf("123456", "%3d%3d", &tempNum1, &tempNum2); 
    CU_ASSERT_EQUAL(uiRet, 2);
    CU_ASSERT_EQUAL(tempNum1, 123);
   /* CU_ASSERT_EQUAL(tempNum2, 456);*//*securec can not support %3d%3d*/

    /*%ni格式化字符串*/
    tempNum1 = 0;
    tempNum2 = 0;
    uiRet = VOS_sscanf("123456", "%3i%3d", &tempNum1, &tempNum2);
    CU_ASSERT_EQUAL(uiRet, 2);
    CU_ASSERT_EQUAL(tempNum1, 123);
    /*CU_ASSERT_EQUAL(tempNum2, 456);*//*securec can not support %3d%3d*/

    /*%no格式化字符串*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("77777777", "%5o", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 0x7FFF);
    
    /*%nx格式化字符串*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("ffffffff", "%4x", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 65535);
 
     /*%nX格式化字符串*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("FFFFFFFF", "%4X", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 65535);
 
     /*%nu格式化字符串*/
    utempNum1 = 0;
    uiRet = VOS_sscanf("4294967295", "%6u", &utempNum1);
    CU_ASSERT_EQUAL(uiRet, 1);
    CU_ASSERT_EQUAL(utempNum1, 429496);
}

/**
*@test Itest_VOS_sscanf_FUNC_023
*- @tspec
*- @ttitle VOS_sscanf "n"与[]组合
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"n"与[]组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_023()
{
    VOS_CHAR scBufferAdd[10]="StringErr";
    VOS_INT32 uiRet = 0;

    /*%n[]格式化字符串*/
    uiRet = VOS_sscanf("abcdefBAS", "%3[a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "abc");
    CU_ASSERT_EQUAL(uiRet, 0);
    
     /*%n[^]格式化字符串*/
    uiRet = VOS_sscanf("ABCDEasad", "%4[^a-z]", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "ABCD");
    CU_ASSERT_EQUAL(uiRet, 0);

}


/**
*@test Itest_VOS_sscanf_FUNC_024
*- @tspec
*- @ttitle VOS_sscanf "%%"读取%
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"%%"组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_024()
{
    VOS_CHAR scBufferAdd[10];
    VOS_INT32 uiRet = 0;

    /*%n[]格式化字符串*/
    uiRet = VOS_sscanf("%%%123", "%%%%%%%s", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "123");
    CU_ASSERT_EQUAL(uiRet, 0);

}

/**
*@test Itest_VOS_sscanf_FUNC_025
*- @tspec
*- @ttitle VOS_sscanf 读取空格等字符
*- @tprecon 
*- @tbrief 
           1.VOS_sscanf与"%[^\n]"组合
           2.判断输入返回值正确
*- @texpect 
           1.返回位数正确
           2.格式化后的字符串正确
*- @tprior 1
*- @tauto False
*- @tremark
*/
VOS_VOID Itest_VOS_sscanf_FUNC_025()
{
    VOS_CHAR scBufferAdd[64] = {0};
    VOS_INT32 uiRet = 0;

    /*%n[]格式化字符串*/
    uiRet = VOS_sscanf("Idkalwjdkl$   &^%^   *(*(?>?<?~~~", "%[^\n]*c", scBufferAdd,sizeof(scBufferAdd));
    CU_ASSERT_EQUAL(uiRet, 1);
    //printf("\r\n scBufferAdd : %s", scBufferAdd);
    uiRet = VOS_StrCmp(scBufferAdd, "Idkalwjdkl$   &^%^   *(*(?>?<?~~~");
    CU_ASSERT_EQUAL(uiRet, 0);
}

/* **************** the end *************** */
VOS_VOID dopra_comptest()
{
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_sscanf_01();
    Itest_VOS_sscanf_02();
    Itest_VOS_sscanf_03();
    Itest_VOS_sscanf_04();
    Itest_VOS_sscanf_05();
    Itest_VOS_sscanf_06();

    Itest_VOS_sscanf_07();
    Itest_VOS_sscanf_08();
    Itest_VOS_sscanf_09();
    Itest_VOS_sprintf_01();
    Itest_VOS_sprintf_02();
    Itest_VOS_sprintf_03();
    Itest_VOS_sprintf_04();
    Itest_VOS_sprintf_05();
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    //Itest_VOS_sprintf_06();/*already test in comptest document*/
#endif
    Itest_VOS_nvsprintf_01();
    Itest_VOS_nvsprintf_02();/*bug,count smaller than source string*/
    Itest_VOS_nvsprintf_03();
    Itest_VOS_nvsprintf_04();
    Itest_VOS_nvsprintf_05();
    Itest_VOS_nvsprintf_06();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_07();
    Itest_VOS_nvsprintf_08();
#endif
    Itest_VOS_nvsprintf_09();
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
#ifndef SECUREC_ON_64BITS
    Itest_VOS_sprintf_FUNC_001();
    Itest_VOS_nsprintf_FUNC_001();
    Itest_VOS_sscanf_FUNC_001();
    Itest_VOS__vsprintf_FUNC_001();
#else
    Itest_VOS_sprintf_FUNC_003();
    Itest_VOS_nsprintf_FUNC_003();
    Itest_VOS_sscanf_FUNC_003();
    Itest_VOS__vsprintf_FUNC_002();
#endif
#endif
    Itest_VOS_sscanf_FUNC_005();
    Itest_VOS_sprintf_FUNC_006();
    Itest_VOS_nsprintf_FUNC_005();
    Itest_VOS_nsprintf_FUNC_006();
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    Itest_VOS_nsprintf_FUNC_007();
    Itest_VOS_nsprintf_FUNC_008();
#endif
    Itest_VOS_nsprintf_FUNC_009();
    Itest_VOS_nsprintf_FUNC_010();
    Itest_VOS_nsprintf_FUNC_011();
    Itest_VOS_nsprintf_FUNC_012();
    Itest_VOS_nsprintf_FUNC_013();/*bug,%#p need to test*/
    Itest_VOS_nsprintf_FUNC_014();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_nsprintf_FUNC_015();
#endif
    Itest_VOS_sprintf_FUNC_005();
    Itest_VOS_sprintf_FUNC_006_1();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_sprintf_FUNC_007();
    Itest_VOS_sprintf_FUNC_008();
#endif
    Itest_VOS_sprintf_FUNC_009();
    Itest_VOS_sprintf_FUNC_010();
    Itest_VOS_sprintf_FUNC_011();
    Itest_VOS_sprintf_FUNC_012();
    Itest_VOS_sprintf_FUNC_013();/*bug,%#p need to test*/
    Itest_VOS_sprintf_FUNC_014();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_sprintf_FUNC_015();
#endif
    Itest_VOS_vsprintf_FUNC_003();
    Itest_VOS_vsprintf_FUNC_004();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER)) 
    Itest_VOS_vsprintf_FUNC_005();
    Itest_VOS_vsprintf_FUNC_006();
#endif
    Itest_VOS_vsprintf_FUNC_007();
    Itest_VOS_vsprintf_FUNC_008();
    Itest_VOS_vsprintf_FUNC_009();
    Itest_VOS_vsprintf_FUNC_010();
    Itest_VOS_vsprintf_FUNC_011();/*bug,%#p need to test*/
    Itest_VOS_vsprintf_FUNC_012();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_vsprintf_FUNC_013();
#endif
    Itest_VOS_vsprintf_FUNC_014();
    Itest_VOS_nvsprintf_FUNC_003();
    Itest_VOS_nvsprintf_FUNC_004();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_FUNC_005();
    Itest_VOS_nvsprintf_FUNC_006();
#endif
    Itest_VOS_nvsprintf_FUNC_007();
    Itest_VOS_nvsprintf_FUNC_008();
    Itest_VOS_nvsprintf_FUNC_009();
    Itest_VOS_nvsprintf_FUNC_010();
    Itest_VOS_nvsprintf_FUNC_011();/*bug,%#p need to test*/
    Itest_VOS_nvsprintf_FUNC_012();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_nvsprintf_FUNC_013();
#endif
    Itest_VOS_nvsprintf_FUNC_014();
    Itest_VOS_sscanf_FUNC_006();
    Itest_VOS_sscanf_FUNC_007();
    Itest_VOS_sscanf_FUNC_008();
    Itest_VOS_sscanf_FUNC_010();
    Itest_VOS_sscanf_FUNC_012();
    Itest_VOS_sscanf_FUNC_013();
#if !(defined(_MSC_VER)&&(1200 == _MSC_VER))
    Itest_VOS_sscanf_FUNC_014();
#endif
    Itest_VOS_sscanf_FUNC_015();
    Itest_VOS_sscanf_FUNC_016();
    Itest_VOS_sscanf_FUNC_017();
    Itest_VOS_sscanf_FUNC_018();
#if !(defined(SECUREC_ON_64BITS))
    Itest_VOS_sscanf_FUNC_019();/*not the same in linux64*/
#endif
    Itest_VOS_sscanf_FUNC_020();
    Itest_VOS_sscanf_FUNC_021();
    Itest_VOS_sscanf_FUNC_022();
    Itest_VOS_sscanf_FUNC_023();
    Itest_VOS_sscanf_FUNC_024();
    Itest_VOS_sscanf_FUNC_025();
}

VOS_VOID dopratest_main()
{
#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    char acString[64] = "Itest_VOS_nvsprintf_02";/*22 character*/
    char scString[10] = "IT_02";/*22 character*/
#endif
    int ret = 0;
    char sBuff[64]={0};
    void *pTemp = NULL;
    unsigned int tempNum = 0; 
    char scBuffer[100] = {0};
#ifdef SECUREC_ON_64BITS
#ifndef _MSC_VER
    long long int iNum = 0;
#else
    __int64 iNum = 0;
#endif
#else
    int iNum = 0;
#endif
    long int templd = 0;

#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    /*nvsprintf function test*/
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf(scBuffer,50,"abcd%s",acString);/*if vsnprintf the count bigger than or equal 26,it will OK*/
    printf("sys:%d,%s\n",ret,scBuffer);
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf_s(scBuffer,32,50,"abcd%s",acString,sizeof(acString));
    printf("sec:%d,%s\n",ret,scBuffer);

    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf(scBuffer,12,"abcd%s",acString);/*if vsnprintf the count bigger than or equal 26,it will OK*/
    printf("sys:%d,%s\n",ret,scBuffer);
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = VOS_vsnprintf_s(scBuffer,64,12,"abcd%s",acString,sizeof(acString));
    printf("sec:%d,%s\n",ret,scBuffer);

    /*count smaller than the source string length*/
    ret = VOS_vsnprintf(scBuffer,12,"abcd%s",scString);
    printf("sys:%d,%s\n",ret,scBuffer);
    ret = VOS_vsnprintf_s(scBuffer,64,12,"abcd%s",scString,sizeof(scString));
    printf("sec:%d,%s\n",ret,scBuffer);
#endif
    /*sprintf %#p test*/
#ifdef SECUREC_ON_64BITS
        ret = 0;pTemp = (void *)0xffffffffffffffff;
        memset(sBuff,'a',sizeof(sBuff));
        ret = sprintf(sBuff, "%#p", pTemp);
        printf("sys:%s\n",sBuff);
        memset(sBuff,'a',sizeof(sBuff));
        ret = 0;pTemp = (void *)0xffffffffffffffff;
        ret = sprintf_s(sBuff, 64, "%#p", pTemp);
        printf("sec:%s\n",sBuff);
#else
        ret = 0;pTemp = (void *)0xffffffff;
        memset(sBuff,'a',sizeof(sBuff));
        ret = sprintf(sBuff, "%#p", pTemp);
        printf("sys:%s\n",sBuff);
        memset(sBuff,'a',sizeof(sBuff));
        ret = 0;pTemp = (void *)0xffffffff;
        ret = sprintf_s(sBuff, 64, "%#p", pTemp);
        printf("sec:%s\n",sBuff);
#endif
    /*sscanf %#x test*/
    ret = 0; tempNum = 0;
    ret = sscanf("0xffffffff", "%#x", &tempNum); 
    printf("sys:%x\n",tempNum);
    ret = 0; tempNum = 0;
    ret = sscanf_s("0xffffffff", "%#x", &tempNum); 
    printf("sec:%x\n",tempNum);

    /*snprintf %#x test*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM))
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf(sBuff, 64, "%#x", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf_s(sBuff, 64,64, "%#x", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf(sBuff, 64, "%#X", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = snprintf_s(sBuff, 64,64, "%#X", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);
#endif
    
    /*sprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf(sBuff, "%#x", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf_s(sBuff, 64, "%#x", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf(sBuff, "%#X", tempNum);
    printf("sys:%d,%s\n",ret,sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    ret = sprintf_s(sBuff, 64, "%#X", tempNum); 
    printf("sec:%d,%s\n",ret,sBuff);
    
    /*vsprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf(sBuff, "%#x", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf_s(sBuff, 64, "%#x", tempNum); 
    printf("sec:%s\n",sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf(sBuff, "%#X", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    vos_vsprintf_s(sBuff, 64, "%#X", tempNum); 
    printf("sec:%s\n",sBuff);
 
#if !(defined(SECUREC_VXWORKS_PLATFORM)||(defined(_MSC_VER)&&(1200 ==_MSC_VER)))
    /*vsnprintf %#x test*/
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf(sBuff, 64,"%#x", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf_s(sBuff, 64, 64,"%#x", tempNum); 
    printf("sec:%s\n",sBuff);

    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf(sBuff,  64,"%#X", tempNum);
    printf("sys:%s\n",sBuff);
    ret = 0; tempNum = 0;
    memset(sBuff,'a',sizeof(sBuff));
    VOS_vsnprintf_s(sBuff, 64,64, "%#X", tempNum);
    printf("sec:%s\n",sBuff);
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    /*%Zd test*/
    ret = 0; tempNum = 0;
    ret = sscanf("123", "%Zd", &tempNum); 
    printf("sys:%zd\n",tempNum);
    ret = 0; tempNum = 0;
    ret = sscanf_s("0xffffffff", "%Zd", &tempNum); 
    printf("sec:%zd\n",tempNum);
#endif
#ifndef SECUREC_ON_64BITS
    ret = 0;templd = 0;
    ret = sscanf("2147483647,2147483646", "%*ld,%ld", &templd);
    printf("sys,tempNum32 : %ld\n", templd);
    ret = 0;templd = 0;
    ret = sscanf_s("2147483647,2147483646", "%*ld,%ld", &templd);
    printf("sec,tempNum32 : %ld\n", templd);
#else
    ret = 0;templd = 0;
    ret = sscanf("9223372036854775807,9223372036854775806", "%*ld,%ld", &templd);  /* 0x7fffffffffffffff */
    printf("sys,tempNum64 : %ld\n", templd);
    ret = 0;templd = 0;
    ret = sscanf_s("9223372036854775807,9223372036854775806", "%*ld,%ld", &templd);  /* 0x7fffffffffffffff */
    printf("sec,tempNum64 : %ld\n", templd);
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    iNum = 0;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%Zd", iNum);
    printf("sys: %s\n", scBuffer); 
    iNum = 0;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer, 100,"%Zd", iNum);
    printf("sec: %s\n", scBuffer);
#endif
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%dz", iNum);
    printf("sys: %s\n", scBuffer);
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer, 100,"%dz", iNum);
    printf("sec: %s\n", scBuffer); 
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf(scBuffer, "%zz", iNum);
    printf("sys: %s\n", scBuffer);
    iNum = 2147483647;ret = 0;
    memset(scBuffer,'a',sizeof(scBuffer));
    ret = sprintf_s(scBuffer,100, "%zz", iNum);
    printf("sec: %s\n", scBuffer);
#endif
    /*dopra sample test*/
    dopra_comptest();
}
#ifdef __cplusplus
 #if __cplusplus
}
 #endif
#endif 

