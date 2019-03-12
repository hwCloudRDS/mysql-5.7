
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

#define BIG_BUFFER_SIZE 256

UINT64T samplesLongLong1[4] = {
    0,   
    037777777777,  
#if _MSC_VER != 1200
    040000000000LL
#else 
    040000000000
#endif
};
char* flagLongLong1[4]={
    "0",
    "037777777777",
#if _MSC_VER != 1200
    "040000000000LL"
#else 
    "040000000000"
#endif
};

unsigned  int samplesint1[3] = {
    0,   
    037777777777,   
    0177777
};

char* flagint1[3] = {
    "0",   
    "037777777777",   
    "0177777"
};

UINT64T samplesLongLong3[5] = {
    0,   
    037777777777, 
#if _MSC_VER != 1200
    040000000000LL,
    01777777777777777777777LL
#else 
    040000000000,
    01777777777777777777777
#endif
};

char* flagLongLong3[5] = {
    "0",   
    "037777777777", 
#if _MSC_VER != 1200
    "040000000000LL",
    "01777777777777777777777LL"
#else 
    "040000000000",
    "01777777777777777777777"
#endif
};

unsigned  int samplesint3[5] = {
    0,   
    037777777777,   
    0177777,
    0200000
};

char* flagint3[5] = {
    "0",   
    "037777777777",   
    "0177777",
    "0200000"
};

unsigned short samplesInt5[4] = {
    0,
    0177777,
    0377,
    0400
};

char* flagInt5[4] = {
    "0",
    "0177777",
    "0377",
    "0400"
};

unsigned long int samplesLong1[4] = {
    0, 
#if OVERFLOW_MARK
    01777777777777777777777,
#endif
    037777777777,
#ifdef SECUREC_ON_64BITS
    040000000000
#endif
};

char* flagLong1[4] = {
    "0", 
#if OVERFLOW_MARK
    "01777777777777777777777",
#endif
    "037777777777",
#ifdef SECUREC_ON_64BITS
    "040000000000"
#endif
};

long int samplesLong[4] = {
    0,   
    0177777,   
    -1,   
    0200000
};
char* flagLong[4] = {
    "0",   
    "0177777",   
    "-1",   
    "0200000"
};

int samplesInt[6] = {
    0,   
    0377,   
    -1,   
    0400,
    0177777,
    0200000
};
char* flagInt[6] = {
    "0",   
    "0377",   
    "-1",   
    "0400",
    "0177777",
    "0200000"
};

UINT64T samplesLongLong2[2] = {
    0,  
#if  _MSC_VER != 1200
    01777777777777777777777LL
#else 
    01777777777777777777777
#endif
};

char* flagLongLong2[2] = {
    "0",  
#if  _MSC_VER != 1200
    "01777777777777777777777LL"
#else 
    "01777777777777777777777"
#endif
};

char *flag[] = 
{
    "edge",
    "edge",     
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "NULL"
};

void outputdataprintf(FILE *fstd, 
                      FILE *fsec, 
                      char *formats, 
                      char *sample, 
                      char *sampletype,
                      int stdresult,
                      int secresult,
                      int isdifferent,
                      char *stdbuffer,
                      char *secbuffer,
                      long unsigned line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sprintf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
    {
        fprintf(fstd, "comparedResult:Different\n");
    }
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %s", stdbuffer);
    fprintf(fstd, "\n\n");

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sprintf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(isdifferent)
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %s",secbuffer);
    fprintf(fsec, "\n\n");
#endif
#if SCREEN_PRINT
    if(isdifferent)
    {
        SPRINTF(formats,sample,sampletype,stdresult,secresult,stdbuffer,secbuffer,line);
    }
#endif
}

void test_printf_format_d(FILE *fstd, FILE *fsec)
{
    char *formats[] = {/* 305419896 */
        "%d",
        "%0d",
        "%6d",
        "%06d",
        "%-6d",
        "%+6d",
        "%12d",
        "%012d",
        "%-12d",
        "%+12d",
        "% 12d",
        "%12.6d",
        "%12.06d",
        "%12.10d",
        "%012.10d",
        "%-12.10d",
        "%-012.10d",
        "%#d",
        "%5#d",
        "%#5d",
        "%5#10d",
        /*#ifdef Linux*/
                   /* "%'d",*/
        /*#endif*/
        NULL
    };

    /*linux,%hhd,char*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char samplechar[] = {12, 127, -128, 0};
    char *flagchar[][2] = 
    {
        {"12",         "normal"  },
        {"127",        "edge"  },
        {"-128",       "edge"  },
    };
#endif
    /*windows,linux,vxworks,%hd,short int*/
    short int sampleshortint[] = {123, 128,-129,32767, -32768, 0};
    char *flagshortint[][2] = 
    {
        {"123",      "normal"  },
        {"128",      "normal"  },
        {"-129",     "normal" },
        {"32767",    "edge"  },
        {"-32768",   "edge" },
    };

    /*windows,linux,vxworks,%d,int*/
    int  sampleint32[] = 
    {
        12345,
        32768,
        -32769,
        2147483647,
        -2147483647-1,
        0
    };
    char *flagint32[][2] = 
    {
        {"12345",       "normal"  },
        {"32768",       "normal" },
        {"-32769",      "normal"  },
        {"2147483647",  "edge"  },
        {"-2147483648", "edge"  },
    };

    /*linux,vxworks,%lld,%Ld,long long int*/
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
        -2147483648-1,
        4294967295,
        9223372036854775807,
        -9223372036854775807-1,
        0
    };
#endif
    char *flagint64[][2] = 
    {
        {"2147483648",          "normal" },
        {"-2147483649",         "normal"  },
        {"4294967295",          "normal"  },
        {"9223372036854775807", "edge" },
        {"-9223372036854775808","edge" },
    };

    /*windows,linux,vxworks*/
    short int   hd;
    int         d;
    long int    ld;
    INT64T lld;
    /*linux*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char        hhd;
    ptrdiff_t   td;
    size_t      zd;
    intmax_t    jd;
#endif 
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int qd;
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int Ld;
#elif _MSC_VER
    int Ld;
#endif

    /*windows*/
#if defined(_MSC_VER)
#if !(1200 == _MSC_VER)
    ptrdiff_t   id;
    __int32     i32d;
#endif
    __int64     i64d;
#endif

    int isdiff=0;
    int retc, rets;
    char stdbuf[256];
    char secbuf[256];
    int m=0;

    fprintf(fstd, "-------------------------------d test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------d test begin--------------------------- \n"); /*lint !e668*/
    /* d */ 
    d = 305419896;
    m = 0;
    while(formats[m] != NULL)
    {
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, formats[m], d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), formats[m], d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, formats[m], "305419896", "normal", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }


#ifdef xxx
    /* test %'d 12 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%'d", 12);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%'d", 12);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%'d", "12", "normal", retc, rets, isdiff, stdbuf, secbuf, __LINE__);

        /* test %*d and %2$*1$d */
        char *formats4[] = {/* 305419896 */
                "%*d",
                /*"%2$*1$d",*/
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
        d = sampleint32[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%d", d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%d", d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%d", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
#if !(defined(_MSC_VER))
    m = 0;
    while(sampleint64[m] != 0)
    {/* d */
        lld = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%d", lld);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%d", lld);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%d", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#else
    m = 0;
    while(sampleint64[m] != 0)
    {/* i */
        i64d = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%d", i64d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%d", i64d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%d", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#endif 
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);

    outputdataprintf(fstd, fsec, "%d", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);

    outputdataprintf(fstd, fsec, "%d", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    /* 18446744073709551615 */  
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", 18446744073709551615);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", 18446744073709551615);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);

    outputdataprintf(fstd, fsec, "%d", "18446744073709551615", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    /* -18446744073709551615 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", -18446744073709551615);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", -18446744073709551615);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%d", "-18446744073709551615", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

#if !(defined(_MSC_VER))
    /* 18446744073709551616 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", 18446744073709551616);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", 18446744073709551616);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%d", "18446744073709551616", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
    /* -18446744073709551616 */ 
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%d", -18446744073709551616);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%d", -18446744073709551616);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%d", "-18446744073709551616", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif
#endif
    m = 0;
    while(sampleshortint[m] != 0)
    {/* hd */
        hd = sampleshortint[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hd", hd);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hd", hd);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%hd", flagshortint[m][0], flagshortint[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleint32[m] != 0)
    {/* hd */
        d = sampleint32[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hd", d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hd", d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%hd", flagint32[m][0], "overflow(int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM)|| defined(__hpux))
    m = 0;
    while(samplechar[m] != 0)
    {/* hhd */
        hhd = samplechar[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hhd", hhd);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhd", hhd);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%hhd", flagchar[m][0], flagchar[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleshortint[m] != 0)
    {/* hhd */
        hd = sampleshortint[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%hhd", hd);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhd", hd);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%hhd", flagshortint[m][0], "overflow(short int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#endif
#endif
    if(8 == sizeof(long int)) /*lint !e506*/
    {
        m = 0;
        while(sampleint64[m] != 0)
        {/* ld : long int */
            ld = sampleint64[m];;
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ld", ld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", ld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%ld", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ld", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%ld", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%ld", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%ld", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {/* ld : long int */
            ld = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ld", ld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", ld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%ld", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
#if !(defined(_MSC_VER))
        m = 0;
        while(sampleint64[m] != 0)
        {/* ld : long int */
            lld = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ld", lld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", lld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%ld", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#else
        m = 0;
        while(sampleint64[m] != 0)
        {/* ld : long int */
            i64d = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%ld", i64d);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%ld", i64d);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%ld", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
#endif
    }
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    m = 0;
    while(sampleint64[m] != 0)
    {
        Ld = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Ld", Ld);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Ld", Ld);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%Ld", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%Ld", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%Ld", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);

    outputdataprintf(fstd, fsec, "%Ld", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%Ld", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%Ld", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%Ld", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif
#endif

#if !(defined(_MSC_VER) && 1200 == _MSC_VER)
    m = 0;
    while(sampleint64[m] != 0)
    {
        lld = sampleint64[m];
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%lld", lld);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%lld", lld);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%lld", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    /* 9223372036854775808 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%lld", 9223372036854775808);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%lld", 9223372036854775808);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%lld", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    /* -9223372036854775809 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%lld", -9223372036854775809);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%lld", -9223372036854775809);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%lld", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif
#endif

#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            qd = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%qd", qd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%qd", qd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%qd", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%qd", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%qd", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%qd", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%qd", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%qd", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%qd", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
#endif

#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    if(8 == sizeof(intmax_t))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            jd = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%jd", jd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", jd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%jd", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%jd", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%jd", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%jd", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%jd", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            jd = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%jd", jd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", jd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%jd", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lld = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%jd", lld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", lld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%jd", flagint64[m][0], "overflow(long lng int)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
    }
    if(8 == sizeof(size_t))
    {            
        m = 0;
        while(sampleint64[m] != 0)
        {
            zd = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zd", zd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", zd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%zd", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%zd", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%zd", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%zd", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%zd", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            zd = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zd", zd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", zd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%zd", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }

        /* wzh add 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
        m = 0;
        while(sampleint32[m] != 0)
        {
            zd = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Zd", zd);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Zd", zd);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%Zd", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lld = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zd", lld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", lld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%zd", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
    }
    if(8 == sizeof(ptrdiff_t))
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            td = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%td", td);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%td", td);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%td", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%td", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%td", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%td", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%td", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%td", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%td", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            td = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%td", td);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%td", td);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%td", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {
            lld = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%td", lld);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%td", lld);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%td", flagint64[m][0], "overflow(long long int)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
    }
#endif

#if defined(_MSC_VER)
#if !(defined(_MSC_VER) && 1200 == _MSC_VER)
    if(8 == sizeof(long))    
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            id = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Id", id);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", id);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%Id", flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Id", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%Id", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Id", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%Id", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
#endif
    }
    else
    {
        m = 0;
        while(sampleint32[m] != 0)
        {
            id = sampleint32[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Id", id);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", id);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%Id", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        m = 0;
        while(sampleint64[m] != 0)
        {            
            i64d = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%Id", i64d);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", i64d);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%Id", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#endif
    }
    m = 0;
    while(sampleint32[m] != 0)
    {
        i32d = sampleint32[m] ;
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32d", i32d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32d", i32d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%I32d", flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#if OVERFLOW_MARK
    m = 0;
    while(sampleint64[m] != 0)
    {
        i64d = sampleint64[m] ;
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32d", i64d);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32d", i64d);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%I32d", flagint64[m][0], "overflow(__int64)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
        m++;
    }
#endif
#endif
    {
        m = 0;
        while(sampleint64[m] != 0)
        {
            i64d = sampleint64[m];
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%I64d", i64d);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%I64d", i64d);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%I64d",flagint64[m][0], flagint64[m][1], retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
            m++;
        }
#if OVERFLOW_MARK
        /* 9223372036854775808 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I64d", 9223372036854775808);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I64d", 9223372036854775808);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%I64d", "9223372036854775808", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* -9223372036854775809 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I64d", -9223372036854775809);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I64d", -9223372036854775809);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%I64d", "-9223372036854775809", "overflow(unsigned long long int)", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
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
        retc = sprintf(stdbuf, "%hhd", 32767);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%hhd", 32767);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%hhd", "32767", "edge", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        /* 9223372036854775807 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%jd", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%jd", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%jd", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);

        if(8 == sizeof(long int))
        {
            /* 9223372036854775807 */
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%td", 9223372036854775807);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%td", 9223372036854775807);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%td", "9223372036854775807", "edge", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
        }
        else
        {   
            /*2147483647*/
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%td", 2147483647);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%td", 2147483647);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%td", "2147483647", "edge", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
        }

        if(8 == sizeof(size_t))
        {
            /* 9223372036854775807 */
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zd", 9223372036854775807);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", 9223372036854775807);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%zd", "9223372036854775807", "edge", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
        }
        else
        {
            /*2147483647*/
            isdiff = 0;
            memset(stdbuf, 1, sizeof(stdbuf));
            memset(secbuf, 1, sizeof(secbuf));
            /* print out standard c function result */
            retc = sprintf(stdbuf, "%zd", 2147483647);
            /* print out secure c function result */
            rets = sprintf_s(secbuf, sizeof(secbuf), "%zd", 2147483647);
            /* compare the results */
            isdiff = memcmp(stdbuf, secbuf, 32);
            outputdataprintf(fstd, fsec, "%zd", "2147483647", "edge", retc, rets, isdiff, 
                stdbuf, secbuf, __LINE__);
        }

    }
#endif

#if (defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%qd", 9223372036854775807);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%qd", 9223372036854775807);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%qd", "9223372036854775807", "edge", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);

    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%Ld", 9223372036854775807);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%Ld", 9223372036854775807);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%Ld", "9223372036854775807", "edge", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif

#if (defined(_MSC_VER) && 1200 == _MSC_VER)
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%lld", 9223372036854775807);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%lld", 9223372036854775807);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 32);
    outputdataprintf(fstd, fsec, "%lld", "9223372036854775807", "edge", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif

#if !(defined(_MSC_VER)) || (defined(_MSC_VER) && 1200 == _MSC_VER)
    if(8 == sizeof(long int))
    {
        /* 9223372036854775807 */
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Id", 9223372036854775807);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", 9223372036854775807);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%Id", "9223372036854775807", "edge", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);    
    }
    else
    {
        /*2147483647*/
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%Id", 2147483647);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%Id", 2147483647);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 32);
        outputdataprintf(fstd, fsec, "%Id", "2147483647", "edge", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
    }
    {
        /*2147483647*/
        isdiff = 0;
        memset(stdbuf, 1, sizeof(stdbuf));
        memset(secbuf, 1, sizeof(secbuf));
        /* print out standard c function result */
        retc = sprintf(stdbuf, "%I32d", 2147483647);
        /* print out secure c function result */
        rets = sprintf_s(secbuf, sizeof(secbuf), "%I32d", 2147483647);
        /* compare the results */
        isdiff = memcmp(stdbuf, secbuf, 256);
        outputdataprintf(fstd, fsec, "%I32d", "2147483647", "edge", retc, rets, isdiff, 
            stdbuf, secbuf, __LINE__);
    }
#endif

#if !(defined(_MSC_VER))
    /* 9223372036854775807 */
    isdiff = 0;
    memset(stdbuf, 1, sizeof(stdbuf));
    memset(secbuf, 1, sizeof(secbuf));
    /* print out standard c function result */
    retc = sprintf(stdbuf, "%I64d", 9223372036854775807);
    /* print out secure c function result */
    rets = sprintf_s(secbuf, sizeof(secbuf), "%I64d", 9223372036854775807);
    /* compare the results */
    isdiff = memcmp(stdbuf, secbuf, 256);
    outputdataprintf(fstd, fsec, "%I64d", "9223372036854775807", "edge", retc, rets, isdiff, 
        stdbuf, secbuf, __LINE__);
#endif
#endif
    fprintf(fstd, "-------------------------------d test end--------------------------- \n");
    fprintf(fsec, "-------------------------------d test end--------------------------- \n");
} /*lint !e529*/
void test_printf_format_o(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
        "%o",   
        /*"%'o", */
        "%#o",   
        "%ho",
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%hho",   
#endif
#if OVERFLOW_MARK
        "%lo",   
#if UNSUPPORT_TEST 
        "%llo",  
#endif
#if UNSUPPORT_TEST
        "%Lo", 
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Io", 
#endif
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I32o", 
#endif
#if OVERFLOW_MARK
#if UNSUPPORT_TEST
        "%I64o", 
#endif
#if UNSUPPORT_TEST
        "%jo", 
#endif
#if UNSUPPORT_TEST
        "%qo", 
#endif
#if UNSUPPORT_TEST
        "%to",   
        "%zo",
        "%Zo",
#endif
#endif
        NULL
    };

 /*   char *longformats[] = {
#if UNSUPPORT_TEST
        "%lo", 
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llo",  
#endif  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lo", 
#endif
#if UNSUPPORT_TEST ||   !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64o",   
#endif 
#if OVERFLOW_MARK
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%jo",
 #endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qo",   
#endif
#if UNSUPPORT_TEST
        "%to",   
        "%zo",
        "%Zo",
#endif
#endif
        NULL
    };
*/
    char *kuanformats[] = {
        "%0o",   
        "%2o",   
        "%3o",   
        "%5o",   
        "%#5o",   
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%5#o", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%5#10o", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%10#5o", 
#endif
        NULL
    };

    char sysBuf[BIG_BUFFER_SIZE];
    char secBuf[BIG_BUFFER_SIZE];
    int i,j;
    int secret = 0, sysret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-normal  comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal  comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-normal  comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal  comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(kuanformats[i], "123", "normal", sysret, secret, sysBuf, secBuf, (long unsigned)__LINE__);
        }
#endif
        i++;
    }


    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, formats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal  comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal  comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal  comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal  comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(formats[i], "123", "normal", sysret, secret, sysBuf, secBuf, (long unsigned)__LINE__);
        }
#endif
        i++;
    }

    /* test %'
    isdiff = 0;
    memset(sysBuf, 1, sizeof(sysBuf));
    memset(secBuf, 1, sizeof(secBuf));
    sysret = sprintf(sysBuf, "%'o", 1234);
    secret = sprintf_s(secBuf, sizeof(secBuf), "%'o", 1234);

    isdiff = memcmp(sysBuf, secBuf, 32);
    outputdataprintf(fStd, fSec, "%'o", "1234", "normal", sysret, secret, issame, sysBuf, secBuf, __LINE__);

    i=0;
    while(NULL != longformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, longformats[i], (UINT64T)123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, longformats[i], (UINT64T)123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different (%d)\n", longformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(longformats[i], "123", "normal", sysret, secret, sysBuf, secBuf, __LINE__);
        }
#endif
        i++;
    }
 */

    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%o", samplesint1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%o", samplesint1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%o",flagint1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if OVERFLOW_MARK
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%o", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%o", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%o", flagLongLong1[i], flag[i], sysret, secret, sysBuf, secBuf, __LINE__);
        }
#endif
        i++;
    }
#endif
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%ho", samplesInt5[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%ho", samplesInt5[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%ho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different (%d)\n", "%ho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%ho",flagInt5[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }
#if OVERFLOW_MARK 
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%ho", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%ho", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%ho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%ho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
        fprintf(fSec, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%ho", flagint3[i], flag[i], sysret, secret, sysBuf, secBuf, __LINE__);
        }
#endif
        i++;
    }
#endif 
#if UNSUPPORT_TEST || !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 6)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hho", samplesInt[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hho", samplesInt[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hho", flagInt[i], flag[i], sysret, secret, sysBuf, secBuf, __LINE__);
        }
#endif
        i++;
    }
 #endif   
#if OVERFLOW_MARK
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lo", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lo", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%lo", flag[i], __LINE__);
        }

        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lo",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lo", samplesLongLong3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lo", samplesLongLong3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%lo", flag[i], __LINE__);
        }

        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lo",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lo", samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lo", samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (long int)comparedResult:Equal\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (long int)comparedResult:Equal\n", "%lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (long int)comparedResult:Different\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (long int)comparedResult:Different (%d)\n", "%lo", flag[i], __LINE__);
        }

        if (i == 4)
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf); /*lint !e415*/
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf); /*lint !e415*/
        }
        else
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf);
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lo",flagLong1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }
    
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%llo", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%llo", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%llo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%llo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%llo",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }
#endif

#if OVERFLOW_MARK
#if UNSUPPORT_TEST
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lo", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lo", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%Lo", flag[i], __LINE__);
        }

        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lo",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lo", samplesLongLong3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lo", samplesLongLong3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Lo", flag[i], __LINE__);
        }

        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lo",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#ifdef IS_TEST_LINUX 

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%jo", (uintmax_t)samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%jo", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%jo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%jo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%jo",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%qo", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%qo", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%qo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%qo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%qo",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%to", (ptrdiff_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%to", (ptrdiff_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%to", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%to", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%to", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%to", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%to",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%zo", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%zo", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%zo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%zo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%zo",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
/* wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
    i = 0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Zo", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Zo", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Zo", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Zo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Zo",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
    /* wzh added end */

#endif
#endif

#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Io", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Io", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Io", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Io", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Io", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Io", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Io",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I32o", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I32o", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I32o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I32o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I32o",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||   !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I64o", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I64o", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I64o", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I64o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I64o",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    fprintf(fStd, "-------------------------------o test end--------------------------- \n");
    fprintf(fSec, "-------------------------------o test end--------------------------- \n");

}

void test_printf_format_u(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
        "%u",   
        /*"%'u",*/
        "%hu",
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) ||  defined(__hpux))
        "%hhu", 
#endif
#if OVERFLOW_MARK        
        "%lu",   
#if UNSUPPORT_TEST
        "%llu",  
#endif
#if UNSUPPORT_TEST
        "%Lu", 
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Iu",
#endif
#endif 
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I32u", 
#endif
#if OVERFLOW_MARK
#if UNSUPPORT_TEST
        "%I64u",   
#endif
#if UNSUPPORT_TEST
        "%ju",
#endif
#if UNSUPPORT_TEST 
        "%qu",   
#endif
#if UNSUPPORT_TEST
        "%tu",   
        "%zu",
        "%Zu",
#endif
#endif
        NULL
    };

    /*char *longformats[] = {
#if UNSUPPORT_TEST
        "%lu",   
#endif  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llu",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lu", 
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64u",
#endif
#if OVERFLOW_MARK      
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%ju", 
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qu",   
#endif
#if UNSUPPORT_TEST
        "%tu",   
        "%zu",
        "%Zu",
#endif
#endif
        NULL
    };*/

    char *kuanformats[] = {
        "%0u",   
        "%2u",   
        "%3u",   
        "%5u",   
        NULL
    };

    char sysBuf[BIG_BUFFER_SIZE];
    char secBuf[BIG_BUFFER_SIZE];
    int i,j;
    int secret = 0, sysret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-normal  comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal  comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-normal  comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal  comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(kuanformats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, formats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal  comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal  comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal  comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal  comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(formats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    /* test %' 
    isdiff = 0;
    memset(sysBuf, 1, sizeof(sysBuf));
    memset(secBuf, 1, sizeof(secBuf));

    sysret = sprintf(sysBuf, "%'u", 1234);
    
    secret = sprintf_s(secBuf, sizeof(secBuf), "%'u", 1234);

    isdiff = memcmp(sysBuf, secBuf, 32);
    outputdataprintf(fStd, fSec, "%'u", "1234", "normal", sysret, secret, issame, sysBuf, secBuf, __LINE__);


    i=0;
    while(NULL != longformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, longformats[i], (UINT64T)123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, longformats[i], (UINT64T)123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different (%d)\n", longformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(longformats[i],"123","normal",sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
*/

    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%u", samplesint1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%u", samplesint1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%u",flagint1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    
#if OVERFLOW_MARK    
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%u", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%u", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%u",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
    
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hu", samplesInt5[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hu", samplesInt5[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different (%d)\n", "%hu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hu",flagInt5[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if OVERFLOW_MARK 
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hu", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hu", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
        fprintf(fSec, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hu",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) ||  defined(__hpux))
    i=0;
    while(i < 6)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hhu", samplesInt[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hhu", samplesInt[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hhu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hhu",flagInt[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if OVERFLOW_MARK
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lu", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lu", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%lu", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lu",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lu", (unsigned long)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lu", (unsigned long)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%lu", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lu",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lu", samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lu", samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different (%d)\n", "%lu", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf); /*lint !e415*/
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf); /*lint !e415*/
        }
        else
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf);
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lu",flagLong1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%llu", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%llu", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%llu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%llu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%llu",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }
#endif

#if OVERFLOW_MARK
#if UNSUPPORT_TEST
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lu", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lu", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%Lu", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lu",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lu", samplesLongLong3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lu", samplesLongLong3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Lu", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lu",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#ifdef IS_TEST_LINUX 

#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%ju", (uintmax_t)samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%ju", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%ju", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%ju", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%ju", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%ju", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%ju",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%qu", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%qu", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%qu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%qu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%qu",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%tu", (ptrdiff_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%tu", (ptrdiff_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%tu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%tu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%tu",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%zu", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%zu", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%zu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%zu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%zu",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
/*  wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
    i = 0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Zu", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Zu", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Zu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Zu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Zu",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
    /* wzh added end */

#endif
#endif

#if UNSUPPORT_TEST || !((defined(_MSC_VER) && (_MSC_VER == 1200)) || (defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Iu", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Iu", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Iu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Iu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Iu", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Iu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Iu",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I32u", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I32u", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I32u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I32u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I32u",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||   !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I64u", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I64u", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)- (unsigned long long int)comparedResult:Different\n", "%I64u", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)- (unsigned long long int)comparedResult:Different (%d)\n", "%I64u", flag[i], __LINE__); /*lint !e626*/
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I64u",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    fprintf(fStd, "-------------------------------u test end--------------------------- \n");
    fprintf(fSec, "-------------------------------u test end--------------------------- \n");

}

void test_printf_format_x(FILE* fStd, FILE* fSec)
{
    char *formats[] = {
        "%x",   
        /*"%'x",*/
        "%#x",   
        "%hx", 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%hhx",  
#endif
#if OVERFLOW_MARK        
        "%lx", 
#if UNSUPPORT_TEST
        "%llx",  
#endif
#if UNSUPPORT_TEST
        "%Lx", 
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Ix", 
#endif
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I32x",
#endif
#if OVERFLOW_MARK      
#if UNSUPPORT_TEST
        "%I64x",   
#endif
#if UNSUPPORT_TEST
        "%jx",   
#endif
#if UNSUPPORT_TEST 
        "%qx",   
#endif
#if UNSUPPORT_TEST
        "%tx",   
        "%zx",
        "%Zx",
#endif
#endif
        NULL
    };

    char *longformats[] = {
#if UNSUPPORT_TEST
        "%lx", 
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llx",
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lx", 
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64x", 
#endif
#if OVERFLOW_MARK     
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%jx",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qx",   
#endif
#if UNSUPPORT_TEST
        "%tx",   
        "%zx",
        "%Zx",
#endif
#endif
        NULL
    };

    char *kuanformats[] = {
        "%0x",   
        "%2x",   
        "%3x",   
        "%5x",   
        "%#5x", 
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%5#x", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%5#10x", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
        "%10#5x", 
#endif
        NULL
    };

    char sysBuf[BIG_BUFFER_SIZE];
    char secBuf[BIG_BUFFER_SIZE];
    int i,j;
    int secret = 0, sysret = 0;
    int issame = 0;

    fprintf(fStd, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, kuanformats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(kuanformats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, formats[i], 123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(int)normal comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(int)normal comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(formats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

        /* test %' 
        isdiff = 0;
        memset(sysBuf, 1, sizeof(sysBuf));
        memset(secBuf, 1, sizeof(secBuf));
        
        sysret = sprintf(sysBuf, "%'x", 1234);
        
        secret = sprintf_s(secBuf, sizeof(secBuf), "%'x", 1234);
        
        isdiff = memcmp(sysBuf, secBuf, 32);
        outputdataprintf(fStd, fSec, "%'x", "1234", "normal", sysret, secret, issame, sysBuf, secBuf, __LINE__);
        */

    i=0;
    while(NULL != longformats[i])
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, longformats[i], (UINT64T)123);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, longformats[i], (UINT64T)123);

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
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different\n", longformats[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different (%d)\n", longformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF(longformats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }


    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%x", samplesint1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%x", samplesint1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%x",flagint1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if OVERFLOW_MARK
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%x", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%x", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%x",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hx", samplesInt5[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hx", samplesInt5[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different (%d)\n", "%hx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hx",flagInt5[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if OVERFLOW_MARK
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hx", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hx", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
        fprintf(fSec, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hx",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 6)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%hhx", samplesInt[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hhx", samplesInt[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hhx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], sysret, sysBuf);
        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%hhx",flagInt[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if OVERFLOW_MARK
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lx", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lx", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%lx", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lx",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lx", (unsigned long)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lx", (unsigned long)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%lx", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
            if(!(issame && (sysret == secret)))
            {
                SPRINTF("%lx",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
            }
#endif
        i++;
    }

    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%lx", samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lx", samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different (%d)\n", "%lx", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf); /*lint !e415*/
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf); /*lint !e415*/
        }
        else
        {
            fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf);
            fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%lx",flagLong1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%llx", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%llx", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%llx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%llx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%llx",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
        }
#endif
        i++;
    }
#endif

#if OVERFLOW_MARK
#if UNSUPPORT_TEST
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lx", samplesint3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lx", samplesint3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%Lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%Lx", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lx",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 4)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Lx", samplesLongLong3[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Lx", samplesLongLong3[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Lx", flag[i], __LINE__);
        }
        
        if (i == 4)
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
        else
        {
            fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
            fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
        }
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Lx",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#ifdef IS_TEST_LINUX 

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%jx", (uintmax_t)samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%jx", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%jx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%jx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%jx",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%qx", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%qx", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%qx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%qx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%qx",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%tx", (ptrdiff_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%tx", (ptrdiff_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%tx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%tx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%tx",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }

    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%zx", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%zx", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%zx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%zx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%zx",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
/* wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
    i = 0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Zx", (size_t)samplesLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Zx", (size_t)samplesLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Zx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Zx", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Zx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Zx",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif
    /* wzh added end */

#endif
#endif

#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%Ix", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Ix", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Ix", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Ix", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Ix", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Ix", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%Ix",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST || !((defined(_MSC_VER) && (_MSC_VER == 1200)) || (defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 3)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I32x", samplesLongLong1[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I32x", samplesLongLong1[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I32x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I32x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I32x",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||   !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(i < 2)
    {
        issame = 1;
        memset(sysBuf, 0, sizeof(sysBuf));
        sysret = sprintf(sysBuf, "%I64x", samplesLongLong2[i]);

        memset(secBuf, 0, sizeof(secBuf));
        secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I64x", samplesLongLong2[i]);

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
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I64x", flag[i]);
            fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I64x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret)))
        {
            SPRINTF("%I64x",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
        }
#endif
        i++;
    }
#endif

    fprintf(fStd, "-------------------------------x test end--------------------------- \n");
    fprintf(fSec, "-------------------------------x test end--------------------------- \n");

}

void test_printf_format_o_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-4o",
                "%+4o",
                "% 4o",
                "%04o",
                "%.4o",
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

        fprintf(fstd, "-------------------------------o test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------o test 2 begin--------------------------- \n"); /*lint !e668*/
        
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
                        retc = sprintf(stdbuf, formats[k], sampleint32[m]);
                        /* print out secure c function result */
                        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleint32[m]);
                        /* compare the results */
                        isdiff = memcmp(stdbuf, secbuf, 32);
                        outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                                stdbuf, secbuf, __LINE__);
                        m++;
                }

                k++;
        }

#endif

        fprintf(fstd, "-------------------------------o test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------o test 2 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_o_3(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*o",
        /*"%2$*1$o",*/
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

    fprintf(fstd, "-------------------------------o test 3 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------o test 3 begin--------------------------- \n"); /*lint !e668*/

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

    fprintf(fstd, "-------------------------------o test 3 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------o test 3 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_u_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-4u",
                "%+4u",
                "% 4u",
                "%04u",
                "%.4u",
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

        fprintf(fstd, "-------------------------------u test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------u test 2 begin--------------------------- \n"); /*lint !e668*/

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
                        retc = sprintf(stdbuf, formats[k], sampleint32[m]);
                        /* print out secure c function result */
                        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleint32[m]);
                        /* compare the results */
                        isdiff = memcmp(stdbuf, secbuf, 32);
                        outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                                stdbuf, secbuf, __LINE__);
                        m++;
                }

                k++;
        }

#endif

        fprintf(fstd, "-------------------------------u test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------u test 2 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_u_3(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*u",
        /*"%2$*1$u",*/
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

    fprintf(fstd, "-------------------------------u test 3 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------u test 3 begin--------------------------- \n"); /*lint !e668*/

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

    fprintf(fstd, "-------------------------------u test 3 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------u test 3 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_x_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%-4x",
                "%+4x",
                "% 4x",
                "%04x",
                "%.4x",
                NULL
        };

        int  sampleint32[] = 
        {
                0x12,
                0x1234,
                0x12345,
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

        fprintf(fstd, "-------------------------------x test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------x test 2 begin--------------------------- \n"); /*lint !e668*/

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
                        retc = sprintf(stdbuf, formats[k], sampleint32[m]);
                        /* print out secure c function result */
                        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleint32[m]);
                        /* compare the results */
                        isdiff = memcmp(stdbuf, secbuf, 32);
                        outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                                stdbuf, secbuf, __LINE__);
                        m++;
                }

                k++;
        }

#endif

        fprintf(fstd, "-------------------------------x test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------x test 2 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_x_3(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*x",
        /*"%2$*1$x",*/
        NULL
    };

    int  sampleint32[] = 
    {
        0x12,
        0x1234,
        0x12345,
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

    fprintf(fstd, "-------------------------------x test 3 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------x test 3 begin--------------------------- \n"); /*lint !e668*/

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

    fprintf(fstd, "-------------------------------x test 3 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------x test 3 end--------------------------- \n"); /*lint !e668*/

}

void test_printf_format_X(FILE* fStd, FILE* fSec)
{
        char *formats[] = {
                "%X",   
                "%#X",   
                "%hX", 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
                "%hhX",  
#endif
#if OVERFLOW_MARK        
                "%lX", 
#if UNSUPPORT_TEST
                "%llX",  
#endif
#if UNSUPPORT_TEST
                "%LX", 
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
                "%IX", 
#endif
#endif
#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
                "%I32X",
#endif
#if OVERFLOW_MARK      
#if UNSUPPORT_TEST
                "%I64X",   
#endif
#if UNSUPPORT_TEST
                "%jX",   
#endif
#if UNSUPPORT_TEST 
                "%qX",   
#endif
#if UNSUPPORT_TEST
                "%tX",   
                "%zX",
                "%ZX",
#endif
#endif
                NULL
        };

        char *longformats[] = {
#if UNSUPPORT_TEST
                "%lX", 
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
                "%llX",
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
                "%LX", 
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
                "%I64X", 
#endif
#if OVERFLOW_MARK     
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
                "%jX",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
                "%qX",   
#endif
#if UNSUPPORT_TEST
                "%tX",   
                "%zX",
                "%ZX",
#endif
#endif
                NULL
        };

        char *kuanformats[] = {
                "%0X",   
                "%2X",   
                "%3X",   
                "%5X",   
                "%#5X", 
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
                "%5#X", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
                "%5#10X", 
#endif
#if UNSUPPORT_TEST ||  (defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) ||  defined(__hpux))
                "%10#5X", 
#endif
                NULL
        };

        char sysBuf[BIG_BUFFER_SIZE];
        char secBuf[BIG_BUFFER_SIZE];
        int i,j;
        int secret = 0, sysret = 0;
        int issame = 0;

        fprintf(fStd, "-------------------------------X test begin--------------------------- \n"); /*lint !e668*/
        fprintf(fSec, "-------------------------------X test begin--------------------------- \n"); /*lint !e668*/

        i=0;
        while(NULL != kuanformats[i])
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, kuanformats[i], 123);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, kuanformats[i], 123);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
                }
                fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
                fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF(kuanformats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

        i=0;
        while(NULL != formats[i])
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, formats[i], 123);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, formats[i], 123);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-(int)normal comparedResult:Equal\n", formats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-(int)normal comparedResult:Equal\n", formats[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-(int)normal comparedResult:Different\n", formats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-(int)normal comparedResult:Different (%d)\n", formats[i], __LINE__);
                }
                fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
                fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF(formats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

        i=0;
        while(NULL != longformats[i])
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, longformats[i], (UINT64T)123);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, longformats[i], (UINT64T)123);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Equal\n", longformats[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different\n", longformats[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-(unsigned long long int)normal  comparedResult:Different (%d)\n", longformats[i], __LINE__);
                }
                fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%s\n\n", sysret, sysBuf);
                fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%s\n\n", secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF(longformats[i],"123","normal",sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }


        i=0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%X", samplesint1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%X", samplesint1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%X", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%X", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%X", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%X", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%X",flagint1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

#if OVERFLOW_MARK
        i=0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%X", samplesLongLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%X", samplesLongLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%X", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%X", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%X", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%X", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%X",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%hX", samplesInt5[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hX", samplesInt5[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Equal\n", "%hX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different\n", "%hX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (short)comparedResult:Different (%d)\n", "%hX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], sysret, sysBuf);
                fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt5[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%hx",flagInt5[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

#if OVERFLOW_MARK
        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%hx", samplesint3[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hX", samplesint3[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
                fprintf(fSec, "input value:%ld\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%hx",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        i=0;
        while(i < 6)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%hhX", samplesInt[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%hhX", samplesInt[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%hhX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%hhX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%hhX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], sysret, sysBuf);
                fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesInt[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%hhX",flagInt[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if OVERFLOW_MARK
        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%lX", samplesint3[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lX", samplesint3[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%lX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%lX", flag[i], __LINE__);
                }

                if (i == 4)
                {
                        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
                }
                else
                {
                        fprintf(fStd, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%d\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
                }
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%lX",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%lX", (unsigned long)samplesLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lX", (unsigned long)samplesLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%lX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%lX", flag[i], __LINE__);
                }

                if (i == 4)
                {
                        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
                }
                else
                {
                        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
                }
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%lX",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%lX", samplesLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%lX", samplesLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Equal\n", "%lX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different\n", "%lX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long int)comparedResult:Different (%d)\n", "%lX", flag[i], __LINE__);
                }

                if (i == 4)
                {
                        fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf); /*lint !e415*/
                        fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf); /*lint !e415*/
                }
                else
                {
                        fprintf(fStd, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%lu\nreturn value :%2d\noutput value:%s\n\n", samplesLong1[i], secret, secBuf);
                }
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%lX",flagLong1[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        i=0;
        while(i < 2)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%llX", samplesLongLong2[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%llX", samplesLongLong2[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%llX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%llX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%llX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%llX",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,(long unsigned)__LINE__);
                }
#endif
                i++;
        }
#endif

#if OVERFLOW_MARK
#if UNSUPPORT_TEST
        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%LX", samplesint3[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%LX", samplesint3[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%LX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Equal\n", "%LX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different\n", "%LX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (int)comparedResult:Different (%d)\n", "%LX", flag[i], __LINE__);
                }

                if (i == 4)
                {
                        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
                }
                else
                {
                        fprintf(fStd, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%u\nreturn value :%2d\noutput value:%s\n\n", samplesint3[i], secret, secBuf);
                }
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%LX",flagint3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        i=0;
        while(i < 4)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%LX", samplesLongLong3[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%LX", samplesLongLong3[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%LX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%LX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%LX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%LX", flag[i], __LINE__);
                }

                if (i == 4)
                {
                        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
                }
                else
                {
                        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], sysret, sysBuf);
                        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong3[i], secret, secBuf);
                }
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%LX",flagLongLong3[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#ifdef IS_TEST_LINUX 

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        i=0;
        while(i < 2)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%jX", (uintmax_t)samplesLongLong2[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%jX", samplesLongLong2[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%jX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%jX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%jX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%jX",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        i=0;
        while(i < 2)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%qX", samplesLongLong2[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%qX", samplesLongLong2[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%qX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%qX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%qX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%qX",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        i=0;
        while(i < 2)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%tX", (ptrdiff_t)samplesLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%tX", (ptrdiff_t)samplesLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%tX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%tX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%tX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%tX",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }

        i=0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%zX", (size_t)samplesLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%zX", (size_t)samplesLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%zX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%zX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%zX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%zX",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
/* wzh added 20141217 */
#if !(defined(__SOLARIS) || defined(_AIX))
        i = 0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%ZX", (size_t)samplesLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%ZX", (size_t)samplesLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%ZX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%ZX", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%ZX", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%ZX", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%ZX",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif
        /* wzh added end */
#endif
#endif

#if UNSUPPORT_TEST ||  !((defined(_MSC_VER) && (_MSC_VER == 1200))  ||(defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        i=0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%Ix", samplesLongLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%Ix", samplesLongLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Ix", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%Ix", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%Ix", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%Ix", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%Ix",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if UNSUPPORT_TEST || !((defined(_MSC_VER) && (_MSC_VER == 1200)) || (defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        i=0;
        while(i < 3)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%I32x", samplesLongLong1[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I32x", samplesLongLong1[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32x", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I32x", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I32x", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I32x", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong1[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%I32x",flagLongLong1[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

#if UNSUPPORT_TEST ||   !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        i=0;
        while(i < 2)
        {
                issame = 1;
                memset(sysBuf, 0, sizeof(sysBuf));
                sysret = sprintf(sysBuf, "%I64x", samplesLongLong2[i]);

                memset(secBuf, 0, sizeof(secBuf));
                secret = sprintf_s(secBuf, BIG_BUFFER_SIZE, "%I64x", samplesLongLong2[i]);

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
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64x", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Equal\n", "%I64x", flag[i]);
                }
                else
                {
                        fprintf(fStd, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different\n", "%I64x", flag[i]);
                        fprintf(fSec, "Expression:sprintf-(%s)-%s  (unsigned long long int)comparedResult:Different (%d)\n", "%I64x", flag[i], __LINE__);
                }
                fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], sysret, sysBuf);
                fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%s\n\n", flagLongLong2[i], secret, secBuf);
#endif
#if SCREEN_PRINT
                if(!(issame && (sysret == secret)))
                {
                        SPRINTF("%I64x",flagLongLong2[i],flag[i],sysret,secret,sysBuf,secBuf,__LINE__);
                }
#endif
                i++;
        }
#endif

        fprintf(fStd, "-------------------------------X test end--------------------------- \n");
        fprintf(fSec, "-------------------------------X test end--------------------------- \n");

}

void test_printf_format_X_2(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

        char *formats[] = {
                "%X",
                "%-4X",
                "%04X",
                "%#4X",
                "%.4X",
                NULL
        };

        int  sampleint32[] = 
        {
                0x12,
                0x1234,
                0x12345,
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

        fprintf(fstd, "-------------------------------X test 2 begin--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------X test 2 begin--------------------------- \n"); /*lint !e668*/

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
                        retc = sprintf(stdbuf, formats[k], sampleint32[m]);
                        /* print out secure c function result */
                        rets = sprintf_s(secbuf, sizeof(secbuf), formats[k], sampleint32[m]);
                        /* compare the results */
                        isdiff = memcmp(stdbuf, secbuf, 32);
                        outputdataprintf(fstd, fsec, formats[k], flagint32[m][0], flagint32[m][1], retc, rets, isdiff, 
                                stdbuf, secbuf, __LINE__);
                        m++;
                }

                k++;
        }

#endif

        fprintf(fstd, "-------------------------------X test 2 end--------------------------- \n"); /*lint !e668*/
        fprintf(fsec, "-------------------------------X test 2 end--------------------------- \n"); /*lint !e668*/

}


void test_printf_format_X_3(FILE *fstd, FILE *fsec)
{
#if 1/*(defined(COMPATIBLE_LINUX_FORMAT))*/

    char *formats[] = {
        "%*X",
        /*"%2$*1$X",*/
        NULL
    };

    int  sampleint32[] = 
    {
        0x12,
        0x1234,
        0x12345,
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

    fprintf(fstd, "-------------------------------X test 3 begin--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------X test 3 begin--------------------------- \n"); /*lint !e668*/

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

    fprintf(fstd, "-------------------------------X test 3 end--------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------X test 3 end--------------------------- \n"); /*lint !e668*/

}
