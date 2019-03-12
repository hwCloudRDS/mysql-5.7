
#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>
#ifdef COMPATIBLE_LINUX_FORMAT
#include <stdint.h>
#include <stddef.h>
#endif

#define EPSINON 0.00001

#if defined(COMPATIBLE_LINUX_FORMAT)
#define IS_TEST_LINUX 1
#else
#undef IS_TEST_LINUX
#endif

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
                      
void makeoutputdataprintf(FILE *fstd, 
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
                          unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    int j = 0;
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sprintf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output buffer:");
    for(j = 0; j < stdlen; j++)
        fprintf(fstd, " %02x", stdbuffer[j]);
    fprintf(fstd, "\n\n");

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sprintf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output buffer:");
    for(j = 0; j < seclen; j++)
        fprintf(fsec, " %02x", secbuffer[j]);
    fprintf(fsec, "\n\n");
#endif
#if SCREEN_PRINT
    if(isdifferent)
    {
        if (formats == NULL)
        {
            formats="NULL";
        }
        if (sample == NULL)
        {
            sample="NULL";
        }
        if (sampletype == NULL)
        {
            sampletype="NULL";
        }
        if (stdbuffer == NULL)
        {
            stdbuffer="NULL";
        }
        if (secbuffer == NULL)
        {
            secbuffer="NULL";
        }

        SPRINTF(formats,sample,sampletype,stdresult,secresult,stdbuffer,secbuffer,(long unsigned)line);

        sample = NULL;
        formats = NULL;
        sampletype = NULL;
        stdbuffer = NULL;
        secbuffer = NULL;
    }
#endif
}


void OutputTestResult(
                          char *fun,
                          FILE *fstd, 
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
                          unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    int j = 0;

    if (fun == NULL)
    {
        printf("fun is NULL.");
        return;
    }
    
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:%-15s-(%-5s)-%-12s", fun, formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output buffer:");
    for(j = 0; j < stdlen; j++)
        fprintf(fstd, " %02x", stdbuffer[j]);
    fprintf(fstd, "\n\n");

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:%-15s-(%-5s)-%-12s", fun, formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output buffer:");
    for(j = 0; j < seclen; j++)
        fprintf(fsec, " %02x", secbuffer[j]);
    fprintf(fsec, "\n\n");
#endif
#if SCREEN_PRINT
    if(isdifferent)
    {
        if (formats == NULL)
        {
            formats="NULL";
        }
        if (sample == NULL)
        {
            sample="NULL";
        }
        if (sampletype == NULL)
        {
            sampletype="NULL";
        }
        if (stdbuffer == NULL)
        {
            stdbuffer="NULL";
        }
        if (secbuffer == NULL)
        {
            secbuffer="NULL";
        }

        SPRINTF(formats,sample,sampletype,stdresult,secresult,stdbuffer,secbuffer,(long unsigned)line);

        sample = NULL;
        formats = NULL;
        sampletype = NULL;
        stdbuffer = NULL;
        secbuffer = NULL;
    }
#endif
}

void test_sprintf_format_i(FILE *fstd, FILE *fsec)
{
    char *formats[] = {/* 305419896 */
        "%i",
    /*#ifdef Linux*/
        /*"%'i",*/
    /*#endif*/
        "%0i",
        "%6i",
        "%06i",
        "%-6i",
        "%+6i",
        "%12i",
        "%012i",
        "%-12i",
        "%+12i",
        "% 12i",
        "%12.6i",
        "%12.06i",
        "%12.10i",
        "%012.10i",
        "%-12.10i",
        "%-012.10i",
        "%#i",
        "%5#i",
        "%#5i",
        "%5#10i",
        NULL
    };
    /*linux,%hhi,char*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char samplechar[] = {0x56, 127, -128, 0};
    char *flagchar[][2] = 
    {
        {"0x56",        "normal"  },
        {"127",         "edge"  },
        {"-128",        "edge"  },
    };
#endif
    /*windows,linux,vxworks,%hi,short int*/
    short int sampleshortint[] = {0x1234, 128,-129,32767, -32768, 0};
    char *flagshortint[][2] = 
    {
        {"0x1234",      "normal"  },
        {"128",         "normal"  },
        {"-129",        "normal" },
        {"32767",       "edge"  },
        {"-32768",      "edge" },
    };

    /*windows,linux,vxworks,%i,int*/
    int  sampleint32[]  = 
    {
        0x05060708,
        32768,
        -32769,
        2147483647,
        -2147483647-1,
        0
    };
    char *flagint32[][2] = 
    {
        {"0x05060708",    "normal"  },
        {"32768",         "normal" },
        {"-32769",        "normal"  },
        {"2147483647",    "edge"  },
        {"-2147483648",   "edge"  },
    };

    /*linux,vxworks,%lli,%Li,long long int*/
#if !(defined(_MSC_VER))
    long long int sampleint64[]= 
    {
        2147483648LL,
        -2147483649LL,
        4294967295LL,
        9223372036854775807LL,
        -9223372036854775807LL-1,
        0
    };
#else
    /*windows,%lld,%I64d,__int64*/
    __int64 sampleint64[]   = 
    {
        2147483648,
        -2147483649,
        4294967295,
        9223372036854775807,
        -9223372036854775807-1,
        0
    };
#endif
    char *flagint64[][2] = 
    {
        {"2147483648",        "normal" },
        {"-2147483649",       "normal"  },
        {"4294967295",       "normal"  },
        {"9223372036854775807", "edge" },
        {"-9223372036854775808","edge" },
    };

    /*windows,linux,vxworks*/
    short int   hi;
    int         i;
    long int li;
    INT64T lli;
    /*linux*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char        hhi;
    ptrdiff_t   ti;
    size_t      zi;
    intmax_t    ji;
#endif 
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int qi;
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int Li;
#elif _MSC_VER
    int Li;
#endif
    /*windows*/
#if defined(_MSC_VER)
#if !(1200 == _MSC_VER)
    ptrdiff_t   ii;
    __int32     i32i;
#endif
    __int64     i64i;
#endif

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int m =0;

    fprintf(fstd, "-------------------------------i test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------i test begin--------------------------- \n"); /*lint !e668*/
    /* i */ 
    i = 305419896;
    m = 0;
    while(formats[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formats[m], i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formats[m], i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, formats[m], "305419896", "normal", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }

#ifdef xxx
    /* test %' */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%'i", 12);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%'i", 12);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%'i", "12", "normal", retc, rets, isdiff, stdbuf, secbuf, __LINE__);

    /* test %*d and %2$*1$d */
    char *formats4[] = {/* 305419896 */
        "%*i",
        /*"%2$*1$i",*/
        NULL
    };

    m = 0;
    while(formats4[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formats4[m], 8, 12);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formats4[m], 8, 12);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, formats4[m], "12", "normal", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#endif

    m = 0;
    while(sampleint32[m] != 0)
    {/* i */
        i = sampleint32[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%i", i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%i", i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%i", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
#if !(defined(_MSC_VER))
    m = 0;
    while(sampleint64[m] != 0)
    {/* i */
        lli = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%i", lli);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%i", lli);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%i", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#else
    m = 0;
    while(sampleint64[m] != 0)
    {/* i */
        i64i = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%i", i64i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%i", i64i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%i", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

    /* 18446744073709551615 */  
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", 18446744073709551615);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", 18446744073709551615);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "18446744073709551615", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

    /* -18446744073709551615 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", -18446744073709551615);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", -18446744073709551615);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "-18446744073709551615", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

#if !(defined(_MSC_VER))
    /* 18446744073709551616 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", 18446744073709551616);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", 18446744073709551616);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "18446744073709551616", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    /* -18446744073709551616 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%i", -18446744073709551616);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%i", -18446744073709551616);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%i", "-18446744073709551616", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#endif

    m = 0;
    while(sampleshortint[m] != 0)
    {/* hi */
        hi = sampleshortint[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hi", hi);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hi", hi);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%hi", flagshortint[m][0], flagshortint[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleint32[m] != 0)
    {/* hi */
        i = sampleint32[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hi", i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hi", i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%hi", flagint32[m][0], "overflow(int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM)|| defined(__hpux)) 
   m = 0;
    while(samplechar[m] != 0)
    {/* hhi */
        hhi = samplechar[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hhi", hhi);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhi", hhi);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%hhi", flagchar[m][0], flagchar[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleshortint[m] != 0)
    {/* hhi */
        hi = sampleshortint[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hhi", hi);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhi", hi);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%hhi", flagshortint[m][0], "overflow( short int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif
#endif
    if(8 == sizeof(long int)) /*lint !e506*/
    {
        m = 0;
        while(sampleint64[m] != 0)
        {/* li : long int */
            li = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%li", li);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%li", li);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%li", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%li", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%li", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%li", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%li", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%li", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%li", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {/* li : long int */
            li = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%li", li);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%li", li);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%li", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
#if !(defined(_MSC_VER))
        m = 0;
        while(sampleint64[m] != 0)
        {/* li : long int */
            lli = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%li", lli);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%li", lli);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%li", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#else
        m = 0;
        while(sampleint64[m] != 0)
        {/* li : long int */
            i64i = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%li", i64i);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%li", i64i);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%li", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif    
#endif
    }
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    m = 0;
    while(sampleint64[m] != 0)
    {
        Li = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Li", Li);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Li", Li);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Li", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%Li", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%Li", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%Li", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%Li", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%Li", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%Li", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#endif
#if !(defined(_MSC_VER) && 1200 == _MSC_VER)
    m = 0;
    while(sampleint64[m] != 0)
    {
        lli = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%lli", lli);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%lli", lli);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%lli", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%lli", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%lli", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%lli", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%lli", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%lli", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    makeoutputdataprintf(fstd, fsec, "%lli", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            qi = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%qi", qi);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%qi", qi);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%qi", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%qi", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%qi", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%qi", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%qi", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%qi", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%qi", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    if(8 == sizeof(intmax_t))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            ji = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ji", ji);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", ji);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ji", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ji", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%ji", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ji", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%ji", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            ji = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ji", ji);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", ji);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ji", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lli = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ji", lli);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", lli);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ji", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
    }

    if(8 == sizeof(size_t))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            zi = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zi", zi);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", zi);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%zi", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);;
            m++;
        }

        /*  wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
        m = 0;
        while(sampleint64[m] != 0)
        {
            zi = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Zi", zi);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Zi", zi);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%Zi", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
        /* wzh added end */

#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%zi", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%zi", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%zi", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%zi", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            zi = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zi", zi);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", zi);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%zi", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

            m++;
        }

        /*  wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
        m = 0;
        while(sampleint32[m] != 0)
        {
            zi = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Zi", zi);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Zi", zi);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%Zi", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
        /* wzh added end */

#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lli = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zi", lli);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", lli);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%zi", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
    }
    if(8 == sizeof(ptrdiff_t))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            ti = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ti", ti);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", ti);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ti", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ti", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%ti", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ti", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%ti", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            ti = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ti", ti);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", ti);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ti", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lli = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ti", lli);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", lli);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ti", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
    }
#endif
#if defined(_MSC_VER)
#if !(1200 == _MSC_VER)
    if(8 == sizeof(long))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            ii = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Ii", ii);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", ii);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%Ii", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Ii", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Ii", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Ii", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Ii", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            ii = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Ii", ii);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", ii);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%Ii", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {            
            i64i = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Ii", i64i);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", i64i);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%Ii", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#endif
    }
    m = 0;
    while(sampleint32[m] != 0)
    {
        i32i = sampleint32[m] ;
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32i", i32i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32i", i32i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%I32i", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleint64[m] != 0)
    {
        i64i = sampleint64[m] ;
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32i", i64i);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32i", i64i);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%I32i", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        m++;
    }
#endif
#endif
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            i64i = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%I64i", i64i);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%I64i", i64i);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%I64i", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I64i", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I64i", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%I64i", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I64i", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I64i", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%I64i", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
    }
#endif    
    /* ***********not support veritify***************** */
#if UNSUPPORT_TEST
#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    {   
        /*127*/
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hhi", 32767);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhi", 32767);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%hhi", "32767", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        /* 9223372036854775807 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ji", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ji", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%ji", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);

        if(8 == sizeof(long int))
        {
            /* 9223372036854775807 */
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ti", 9223372036854775807);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", 9223372036854775807);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ti", "9223372036854775807", "edge", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        }
        else
        {   
            /*2147483647*/
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ti", 2147483647);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ti", 2147483647);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%ti", "2147483647", "edge", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        }

        if(8 == sizeof(size_t))
        {
            /* 9223372036854775807 */
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zi", 9223372036854775807);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", 9223372036854775807);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%zi", "9223372036854775807", "edge", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        }
        else
        {
            /*2147483647*/
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zi", 2147483647);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zi", 2147483647);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            makeoutputdataprintf(fstd, fsec, "%zi", "2147483647", "edge", retc, rets, isdiff, 
                stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        }

    }
#endif

#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%qi", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%qi", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%qi", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Li", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Li", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Li", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#if (defined(_MSC_VER) && 1200 == _MSC_VER)
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%lli", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%lli", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%lli", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#if !(defined(_MSC_VER)) || (defined(_MSC_VER) && 1200 == _MSC_VER)
    if(8 == sizeof(long int))
    {
        /* 9223372036854775807 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Ii", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Ii", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);    
    }
    else
    {
        /*2147483647*/
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Ii", 2147483647);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Ii", 2147483647);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        makeoutputdataprintf(fstd, fsec, "%Ii", "2147483647", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
    {
        /*2147483647*/
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32i", 2147483647);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32i", 2147483647);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 256);
        makeoutputdataprintf(fstd, fsec, "%I32i", "2147483647", "edge", retc, rets, isdiff, 
            stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
    }
#endif
#if !(defined(_MSC_VER))
    /* 9223372036854775807 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%I64i", 9223372036854775807);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%I64i", 9223372036854775807);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 256);
    makeoutputdataprintf(fstd, fsec, "%I64i", "9223372036854775807", "edge", retc, rets, isdiff, 
        stdbuf, sizeof(stdbuf), secbuf, sizeof(secbuf), __LINE__);
#endif
#endif
    fprintf(fstd, "-------------------------------i test end--------------------------- \n");
    fprintf(fsec, "-------------------------------i test end--------------------------- \n");
} /*lint !e529*/

/*

*/
void test_sprintf_format_i_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*i",
        /*"%2$*1$i",*/
        NULL
    };

    int  sampleint32[] = 
    {
        12,
        1234,
        12345,
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

    fprintf(fstd, "-------------------------------i test 2 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------i test 2 begin--------------------------- \n"); /*lint !e668*/

    k = 0;
    while(formats[k] != NULL)
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, formats[k], 4, sampleint32[m]);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], 4, sampleint32[m]);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        k++;
    }

#endif

    fprintf(fstd, "-------------------------------i test 2 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------i test 2 end--------------------------- \n"); /*lint !e668*/

}
