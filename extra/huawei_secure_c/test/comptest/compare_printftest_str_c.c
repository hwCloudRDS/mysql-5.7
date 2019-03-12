
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>

#if (defined(_WIN32) || defined(_WIN64) || defined(COMPATIBLE_LINUX_FORMAT))
    extern int swprintf (wchar_t* ws, size_t len, const wchar_t* format, ...); /*lint !e18*/
#endif
#define EPSINON 0.00001

#if defined(COMPATIBLE_LINUX_FORMAT)
#define IS_TEST_LINUX 1
#else
#undef IS_TEST_LINUX
#endif


#define BIG_BUFFER_SIZE 256

extern void outputdataprintf(FILE *fstd, 
                      FILE *fsec, 
                      char *formats, 
                      char *sample, 
                      char *sampletype,
                      int stdresult,
                      int secresult,
                      int isdifferent,
                      char *stdbuffer,
                      char *secbuffer,
                      unsigned long line);

void test_printf_format_c(FILE* fStd,FILE* fSec)
{
#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t *wformats[] = {
        L"%c",
#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
        L"%lc",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        L"%hc",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(_AIX))) || defined(SECUREC_VXWORKS_PLATFORM))
        L"%wc",
#endif
        NULL
    };
#endif
    char *formats[] = {
        "%c",
#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
        "%lc",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%hc",
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(_AIX))) || defined(SECUREC_VXWORKS_PLATFORM))
        "%wc",
#endif
        NULL
    };

    char *kuanformats[] = {
        "%0c",   
        "%1c",   
        "%10c",   
        "%010c",
        NULL
    };

    char sysBuf[BIG_BUFFER_SIZE];
    char secBuf[BIG_BUFFER_SIZE];

    int i; 
    int j; 
    int sysret = 0, secret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------c test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], '1');

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], '1');

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:'1'\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:'1'\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(kuanformats[i],"1","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], 135);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], 135);

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:(char)135\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:(char)135\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(kuanformats[i],"(char)135","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, formats[i], 'a');

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 'a');

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:'a'\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:'a'\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(formats[i],"a","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#ifndef SECUREC_VXWORKS_PLATFORM
#if (defined(_MSC_VER) && (_MSC_VER > 1200)) || !( defined(_WIN32) || defined(_WIN64))
    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));

        sysret = swprintf((wchar_t *)sysBuf, 100, wformats[i], L'a');

        memset(secBuf, 0, sizeof(secBuf));
        secret = swprintf_s((wchar_t *)secBuf, 100, wformats[i], L'a');

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%ls)- comparedResult:Equal\n", wformats[i]);
            fprintf(fSec, "Expression:sprintf-(%ls)- comparedResult:Equal\n", wformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%ls)- comparedResult:Different\n", wformats[i]);
            fprintf(fSec, "Expression:sprintf-(%ls)- comparedResult:Different (%d)\n", wformats[i], __LINE__);
        }
        fprintf(fStd, "input value:L'a'\nreturn value :%2d\noutput value:%c %c %c %c %c %c\n\n",  sysret, sysBuf[0], sysBuf[1], sysBuf[2], sysBuf[3], sysBuf[4], sysBuf[5]);
        fprintf(fSec, "input value:L'a'\nreturn value :%2d\noutput value:%c %c %c %c %c %c\n\n", secret, secBuf[0], secBuf[1], secBuf[2], secBuf[3], secBuf[4], secBuf[5]);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
             SPRINTF(wformats[i],"a","normal",sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif 
#endif 

    fprintf(fStd, "-------------------------------c test end--------------------------- \n");
    fprintf(fSec, "-------------------------------c test end--------------------------- \n");

} /*lint !e529*/

void test_printf_format_C(FILE* fStd,FILE* fSec)
{
    char *formats[] = {
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))
        "%C",
        "%lC",
        "%hC",
#endif
        "%wC",
        NULL
    };


    char *kuanformats[] = {
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM))  
        "%0C",   
        "%1C",   
        "%10C",   
#endif
        NULL
    };

    char sysBuf[BIG_BUFFER_SIZE];
    char secBuf[BIG_BUFFER_SIZE];

    int i; 
    int j; 
    int sysret = 0, secret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------C test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------C test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], '1');

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], '1');

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:'1'\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:'1'\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
           SPRINTF(kuanformats[i],"1","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, formats[i], 'a');

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 'a');

        for(j = 0; j < BIG_BUFFER_SIZE; j++)
        {
            if(sysBuf[j] != secBuf[j])
            {
                issame = 0;
                break;
            }
        }

#if TXT_DOCUMENT_PRINT    
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:'a'\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:'a'\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(formats[i],"a","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    fprintf(fStd, "-------------------------------C test end--------------------------- \n");
    fprintf(fSec, "-------------------------------C test end--------------------------- \n");

}

void test_printf_format_c_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%-4c",
        "%+4c",
        "% 4c",
        "%04c",
        "%.4c",
        NULL
    };

    char  sampleChar[] = 
    {
        '1',
        0
    };
    char *flagint32[][2] = 
    {
        {"1",       "normal"  }
    };

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;
    int m=0;

    fprintf(fstd, "-------------------------------c test 2 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------c test 2 begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sampleChar[m] != 0)
        {
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, formats[k], sampleChar[m]);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleChar[m]);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        k++;
    }

#endif

    fprintf(fstd, "-------------------------------c test 2 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------c test 2 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_char_Xing(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*c",
        /*"%2$*1$c",*/
        "%*C",
        /*"%2$*1$C",*/
        NULL
    };

    char  sample[] = 
    {
        '1',
        0
    };
    char *flag[][2] = 
    {
        {"1",       "normal"  }
    };


    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;
    int m=0;

    fprintf(fstd, "-------------------------------c C test * $ begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------c C test * $ begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sample[m] != 0)
        {
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, formats[k], 4, sample[m]);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], 4, sample[m]);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, formats[k], flag[m][0], flag[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        k++;
    }

#endif

    fprintf(fstd, "-------------------------------c C test * $  end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------c C test * $  end--------------------------- \n"); /*lint !e668*/

}
