
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>
//lint -esym(526, makeoutputdataprintf)
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
                      
extern void makeoutputdataprintf(FILE *fstd, 
    FILE *fsec, 
    char *formats, 
    char *sample, 
    char *sampletype,
    int stdresult,
    int secresult,
    int isdifferent,
    char *stdbuffer,
    int stdlen,
    char *secbuffer,
    int seclen,
    unsigned long line);
    
void test_sprintf_format_s(FILE *fstd, FILE *fsec)
{
    char *formats[] = {/* 305419896 */
        "%s",
        "%3s",
        "%10s",
        "%-10s",
        "%-4294967266s",
        "%010s",
        NULL
    };
#ifndef SECUREC_VXWORKS_PLATFORM
    wchar_t *samplew = L"hello";
#endif
    char    *sample  = "world";

#if !defined(__SOLARIS )  
    char *formatEx1s[] = {
        "%.3s",
        NULL
    };
    char *sampleEx1 = NULL;
#endif

    int m = 0;
    int isdiff = 0;
    char stdbuf[32];
    char secbuf[32];
    int retc;
    int rets;
    
    while(formats[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formats[m], sample);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formats[m], sample);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, formats[m], sample, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }

#if !defined(__SOLARIS )
    /* NULL */
    /* 在hp上做兼容性测试的时候，sprintf，当格式串是%.3s，输入数据是NULL时有一处差异为共性差异 */
    m = 0;
    while(formatEx1s[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formatEx1s[m], sampleEx1);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formatEx1s[m], sampleEx1);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, formatEx1s[m], "NULL", "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(SECUREC_VXWORKS_PLATFORM))
    {/* ls */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ls", samplew);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ls", samplew);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%ls", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#ifndef COMPATIBLE_LINUX_FORMAT
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    {/* hs */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hs", sample);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hs", sample);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%hs", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
    {/* ws */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ws", samplew); /*lint !e557*/
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ws", samplew);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%ws", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    {/* S */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%S", samplew);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%S", samplew);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%S", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    {/* hS */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hS", sample);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hS", sample);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%hS", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    {/* lS */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%lS", samplew);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%lS", samplew);
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        makeoutputdataprintf(fstd, fsec, "%lS", stdbuf, "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#endif
}

void test_sprintf_format_s_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%-4s",
        "%.4s",
        NULL
    };

    char *sampleStr[] = 
    {
        "12",
        "1234",
        "12345",
        0
    };
    char *flagint32[][2] = 
    {
        {"12",       "edge"  },
        {"1234",       "normal" },
        {"12345",      "edge"  }
    };

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;
    int m=0;

    fprintf(fstd, "-------------------------------s test 2 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test 2 begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sampleStr[m] != 0)
        {
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, formats[k], sampleStr[m]);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleStr[m]);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        k++;
    }

#endif

    fprintf(fstd, "-------------------------------s test 2 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test 2 end--------------------------- \n"); /*lint !e668*/

}

#if !(defined(SECUREC_VXWORKS_PLATFORM))
void test_swprintf_format_s(FILE *fstd, FILE *fsec)
{

    wchar_t *formatsw[] = {/* 305419896 */
        L"%s",
        L"%ls",
        L"%3s",
        L"%10s",
        L"%-10s",
        L"%010s",
        NULL
    };

    wchar_t samplew[] = L"w_hello";
    char    sample[]  = "w_world";

#if !defined(__SOLARIS )
    wchar_t *formatEx1s[] = {
        L"%s",
        L"%.2s",
        NULL
    };
    wchar_t *sampleEx1 = NULL;
#endif

    int m = 0;
    int isdiff = 0;
    wchar_t stdbuf[32];
    wchar_t secbuf[32];
    char fmt[32];
    char smp[32];
    int i, len;
    int retc;
    int rets;
    
    while(formatsw[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
#if defined(COMPATIBLE_LINUX_FORMAT)
        
        if(0 == wcscmp(L"%ls",formatsw[m] ))
        {
            /* print out standard c function result */
            retc = swprintf(stdbuf, 32,formatsw[m], samplew);
            /* print out secure c function result */
            rets = swprintf_s(secbuf, 32, formatsw[m], samplew);
        }
        else
        {
            /* print out standard c function result */
            retc = swprintf(stdbuf, 32,formatsw[m], sample);
            /* print out secure c function result */
            rets = swprintf_s(secbuf, 32, formatsw[m], sample);
        }
#else
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
        /* print out standard c function result */
        retc = swprintf(stdbuf, formatsw[m], samplew);
#else
        retc = swprintf(stdbuf, 32,formatsw[m], samplew);
#endif
        /* print out secure c function result */
        rets = swprintf_s(secbuf, 32, formatsw[m], samplew);
#endif
        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));
        
        len = wcslen(stdbuf);
        for(i=0;i<len;++i)
        {
            *((char*)stdbuf + i) = (char)(stdbuf[i]) ;
        }
        *((char*)stdbuf + i) = (char)0;

        len = wcslen(secbuf);
        for(i=0;i<len;++i)
        {
            *((char*)secbuf + i) = (char)(secbuf[i]) ;
        }
        *((char*)secbuf + i) = (char)0;

       
        len = wcslen(formatsw[m]);
        for(i=0;i<len;++i)
        {
            *((char*)fmt + i) = (char)(formatsw[m][i]) ;
        }
        *((char*)fmt + i) = (char)0;

        len = wcslen(samplew);
        for(i=0;i<len;++i)
        {
            *((char*)smp + i) = (char)(samplew[i]) ;
        }
        *((char*)smp + i) = (char)0;

#if defined(COMPATIBLE_LINUX_FORMAT)
        if(0 != wcscmp(L"%ls",formatsw[m] ))
        {
            strcpy(smp,sample);
        }
#endif
        makeoutputdataprintf(fstd, fsec, fmt, smp, "normal", retc, rets, isdiff, 
            (char*)stdbuf, sizeof(stdbuf), (char*)secbuf, sizeof(secbuf), __LINE__);
        m++;
    }

#if !defined(__SOLARIS )
    /* NULL */
    m = 0;
    while(formatEx1s[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
#if (defined(_MSC_VER) && (_MSC_VER == 1200))
        /* print out standard c function result */
        retc = swprintf(stdbuf, formatEx1s[m], sampleEx1);
#else
        retc = swprintf(stdbuf, sizeof(stdbuf), formatEx1s[m], sampleEx1);
#endif
        
        /* print out secure c function result */
        rets = swprintf_s(secbuf, sizeof(secbuf), formatEx1s[m], sampleEx1);

        /* compare the results */
        isdiff = (memcmp(stdbuf, secbuf, 32) || (retc != rets));

        len = wcslen(stdbuf);
        for(i=0;i<len;++i)
        {
            *((char*)stdbuf + i) = (char)(stdbuf[i]) ;
        }
        *((char*)stdbuf + i) = (char)0;

        len = wcslen(secbuf);
        for(i=0;i<len;++i)
        {
            *((char*)secbuf + i) = (char)(secbuf[i]) ;
        }
        *((char*)secbuf + i) = (char)0;

        len = wcslen(formatEx1s[m]);
        for(i=0;i<len;++i)
        {
            *((char*)fmt + i) = (char)(formatEx1s[m][i]) ;
        }
        *((char*)fmt + i) = (char)0;

        if (sampleEx1 == NULL)
        {
            strcpy(smp,"NULL");
        }
        else
        {
            len = wcslen(sampleEx1);
            for(i=0;i<len;++i)
            {
                *((char*)smp + i) = (char)(sampleEx1[i]) ;
            }
            *((char*)smp + i) = (char)0;
        }

        makeoutputdataprintf(fstd, fsec, fmt, smp, "normal", retc, rets, isdiff, 
            (char*)stdbuf, sizeof(stdbuf), (char*)secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif

}
#endif


void test_sprintf_format_s_3(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*s",
        /*"%2$*1$s",*/
        NULL
    };

    char *sample[] = 
    {
        "12",
        "1234",
        "12345",
        NULL
    };
    char *flag[][2] = 
    {
        {"12",       "edge"  },
        {"1234",       "normal" },
        {"12345",      "edge"  }
    };


    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;
    int m=0;

    fprintf(fstd, "-------------------------------s test 3 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test 3 begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sample[m] != NULL)
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

    fprintf(fstd, "-------------------------------s test 3  end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test 3  end--------------------------- \n"); /*lint !e668*/

}

void test_sprintf_format_s_NULL(FILE *fstd, FILE *fsec)
{
    char *formats[] = {
#ifndef __SOLARIS
        "%.3s",
        "%.4s",
        "%.7s",
        "%3.3s",
        "%3.4s",
        "%3.7s",
        "%7.3s",
        "%7.4s",
        "%7.7s",
#endif
        NULL
    };

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int k=0;

    fprintf(fstd, "-------------------------------s test NULL begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test NULL begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formats[k], NULL);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], NULL);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, formats[k], "NULL", "overflow", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        k++;
    }

    fprintf(fstd, "-------------------------------s test NULL  end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------s test NULL  end--------------------------- \n"); /*lint !e668*/

}

