
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


void outputint(FILE *fstd, 
               FILE *fsec, 
               char *formats, 
               char *sample, 
               char *sampletype,
               int stdresult,
               int secresult,
               int isequal,
               int stdnumber,
               int secnumber,
               unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %d\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %d\n\n", secnumber);
#endif
#if SCREEN_PRINT
if(!(isequal)) 
    SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%d",secnumber,"%d",(long unsigned)line);
#endif
}

void outputld(FILE *fstd, 
              FILE *fsec, 
              char *formats, 
              char *sample, 
              char *sampletype,
              int stdresult,
              int secresult,
              int isequal,
              long int stdnumber,
              long int secnumber,
              unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %ld\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", (long unsigned)line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %ld\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%ld",secnumber,"%ld",(long unsigned)line);
#endif
}


#if !(defined(_MSC_VER)||defined(SECUREC_VXWORKS_PLATFORM) ||defined(__UNIX))
void outputLd(FILE *fstd, 
              FILE *fsec, 
              char *formats, 
              char *sample, 
              char *sampletype,
              int stdresult,
              int secresult,
              int isequal,
              long long int stdnumber,
              long long int  secnumber,
              unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %Ld\n\n", stdnumber); /*lint !e566*/

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %Ld\n\n", secnumber); /*lint !e566*/
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%lld",secnumber,"%lld",(long unsigned)line);
#endif
}
#endif
#if defined(_MSC_VER)
void outputLd(FILE *fstd, 
              FILE *fsec, 
              char *formats, 
              char *sample, 
              char *sampletype,
              int stdresult,
              int secresult,
              int isequal,
              int stdnumber,
              int secnumber,
              unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %Ld\n\n", stdnumber); /*lint !e566*/

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %Ld\n\n", secnumber); /*lint !e566*/
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%d",secnumber,"%d",(long unsigned)line);
#endif
}
#endif
void outputlld(FILE *fstd, 
               FILE *fsec, 
               char *formats, 
               char *sample, 
               char *sampletype,
               int stdresult,
               int secresult,
               int isequal,
               INT64T stdnumber,
               INT64T secnumber,
               unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %lld\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %lld\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%lld",secnumber,"%lld",(long unsigned)line);
#endif
} 
void outputhd(FILE *fstd, 
              FILE *fsec, 
              char *formats, 
              char *sample, 
              char *sampletype,
              int stdresult,
              int secresult,
              int isequal,
              short int stdnumber,
              short int secnumber,
              unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %hd\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %hd\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%hd",secnumber,"%hd",(long unsigned)line);
#endif
}
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
void outputhhd(FILE *fstd, 
               FILE *fsec, 
               char *formats, 
               char *sample, 
               char *sampletype,
               int stdresult,
               int secresult,
               int isequal,
               char stdnumber,
               char secnumber,
               unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %hhd\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %hhd\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%d",secnumber,"%d",(long unsigned)line);
#endif
} 
#endif
#if defined(_MSC_VER)
void outputI64d(FILE *fstd, 
                FILE *fsec, 
                char *formats, 
                char *sample, 
                char *sampletype,
                int stdresult,
                int secresult,
                int isequal,
                __int64 stdnumber,
                __int64 secnumber,
                unsigned long line)
{
#if TXT_DOCUMENT_PRINT
    /* print out the compare result to stdard function result file */
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %I64d\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %I64d\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%I64d",secnumber,"%I64d",(long unsigned)line);
#endif
}
#endif

void test_sscanf_format_d(FILE *fstd, FILE *fsec)
{
    char *samplesint[][64]= 
     {/* 0.d */
            {"74565",            "normal"},
            {"2147483647",        "edge"},
            {"-2147483648",        "edge"},
#if OVERFLOW_MARK
            {"2147483648",        "overflow(long long int)"},
            {"-2147483649",        "overflow(long long int)"},
            {"4294967295",        "overflow(long long int)"},
            {"4294967296",        "overflow(long long int)"},
            {"-4294967295",        "overflow(long long int)"},
            {"-4294967296",        "overflow(long long int)"},
            {"9223372036854775807","overflow(long long int)"},
            {"-9223372036854775808","overflow(long long int)"},
            {"9223372036854775808","overflow(unsigned long long int)"},
            {"-9223372036854775809","overflow(unsigned long long int)"},
            {"18446744073709551615","overflow(unsigned long long int)"},
            {"-18446744073709551616","overflow(unsigned long long int)"},
            {"18446744073709551616","overflow(unsigned long long int)"},
            {"-18446744073709551617","overflow(unsigned long long int)"},
#endif
            {NULL,        NULL    },
       };
    char *sampleslonglong[][64]=
            {/* 2.lld */
                {"4886718345",          "normal"}, 
                {"9223372036854775807", "edge"},
                {"-9223372036854775808","edge"},
#if OVERFLOW_MARK
                {"9223372036854775808", "overflow(unsigned long long int)"},
                {"-9223372036854775809","overflow(unsigned long long int)"},
                {"18446744073709551615","overflow(unsigned long long int)"},
                {"-18446744073709551616","overflow(unsigned long long int)"},
                {"18446744073709551616","overflow(unsigned long long int)"},
                {"-18446744073709551617","overflow(unsigned long long int)"},
#endif
                {NULL,        NULL    },
            };
    char *samplesshortint[][64]=
            {/* 3.hd */
                {"12345",       "normal"},
                {"32767",       "edge"},
                {"-32768",      "edge"},
#if OVERFLOW_MARK
                {"32768",       "overflow(int)"},
                {"-32769",      "overflow(int)"},
                {"2147483647",        "overflow(int)"},
                {"-2147483648",        "overflow(int)"},
                {"2147483648",        "overflow(long long int)"},
                {"-2147483649",        "overflow(long long int)"},
                {"4294967295",        "overflow(long long int)"},
                {"4294967296",        "overflow(long long int)"},
                {"-4294967295",        "overflow(long long int)"},
                {"-4294967296",        "overflow(long long int)"},
                {"9223372036854775807","overflow(long long int)"},
                {"-9223372036854775808","overflow(long long int)"},
                {"9223372036854775808","overflow(unsigned long long int)"},
                {"-9223372036854775809","overflow(unsigned long long int)"},
                {"18446744073709551615","overflow(unsigned long long int)"},
                {"-18446744073709551616","overflow(unsigned long long int)"},
                {"18446744073709551616","overflow(unsigned long long int)"},
                {"-18446744073709551617","overflow(unsigned long long int)"},
#endif
                {NULL,        NULL    },
                };
     /*  6.hhd */
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char *sampleschar[][64]=
                {
                        {"55",                  "normal"},
                        {"127",                 "edge"},
                        {"-128",                "edge"},
#if OVERFLOW_MARK
                        {"128",                 "overflow(short int)"},
                        {"-129",                "overflow(short int)"},
                        {"2147483647",        "overflow(int)"},
                        {"-2147483648",        "overflow(int)"},
                        {"2147483648",        "overflow(long long int)"},
                        {"-2147483649",        "overflow(long long int)"},
                        {"4294967295",        "overflow(long long int)"},
                        {"4294967296",        "overflow(long long int)"},
                        {"-4294967295",        "overflow(long long int)"},
                        {"-4294967296",        "overflow(long long int)"},
                        {"9223372036854775807","overflow(long long int)"},
                        {"-9223372036854775808","overflow(long long int)"},
                        {"9223372036854775808","overflow(unsigned long long int)"},
                        {"-9223372036854775809","overflow(unsigned long long int)"},
                        {"18446744073709551615","overflow(unsigned long long int)"},
                        {"-18446744073709551616","overflow(unsigned long long int)"},
                        {"18446744073709551616","overflow(unsigned long long int)"},
                        {"-18446744073709551617","overflow(unsigned long long int)"},
#endif
                        {NULL, NULL},
                    };
#endif

    short int hd[2] = {0};
    int d[2] = {0};    
    long int ld[2] = {0};
    INT64T lld[2]= {0};
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int Ld[3]= {0};
#endif
#if defined(_MSC_VER)
    int Ld[3]= {0};
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    long long int qd[2]= {0};
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    ptrdiff_t td[2] = {0};
    size_t    zd[2] = {0};
    intmax_t  jd[2]={0};
    char      hhd[2]= {0};
#endif

#if defined(_MSC_VER) 
    __int64 I64d[2] = {0}; 
#endif

    int m=0,isdiff=0;
    int retc, rets;

    fprintf(fstd, "-------------------------------d test begin-------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------d test begin-------------------------- \n"); /*lint !e668*/
    /*0.d*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%d", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, d[0], d[1], __LINE__);
        m++;
    }
    /*1.ld*/
    if( 8 == sizeof(long int)) /*lint !e506*/
    {
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        ld[0] = ld[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%ld", &ld[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%ld", &ld[1]);
        /* compare the results */
        isdiff = (ld[0] == ld[1] && retc == rets);
        outputld(fstd, fsec, "%ld", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, ld[0], ld[1], __LINE__);
        m++;
    }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            ld[0] = ld[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%ld", &ld[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%ld", &ld[1]);
            /* compare the results */
            isdiff = (ld[0] == ld[1] && retc == rets);
            outputld(fstd, fsec, "%ld", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, ld[0], ld[1], __LINE__);
            m++;
        }
    }
    /*2.lld*/
#if !(defined(_MSC_VER) && 1200 == _MSC_VER)
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%lld", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%lld", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%lld", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, lld[0], lld[1], __LINE__);
        m++;
    }
#endif
    /*3.hd*/
    m = 0;
    while(samplesshortint[m][0] != NULL)
    {
        isdiff = 0;
        hd[0] = hd[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesshortint[m][0],"%hd", &hd[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesshortint[m][0], "%hd", &hd[1]);
        /* compare the results */
        isdiff = (hd[0] == hd[1] && retc == rets);
        outputhd(fstd, fsec, "%hd", samplesshortint[m][0], samplesshortint[m][1], retc, rets, isdiff, hd[0], hd[1], __LINE__);
        m++;
    }

#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    /*4.qd*/
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        qd[0] = qd[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%qd", &qd[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%qd", &qd[1]);
        /* compare the results */
        isdiff = (qd[0] == qd[1] && retc == rets);
        outputlld(fstd, fsec, "%qd", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, qd[0], qd[1], __LINE__);
        m++;
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    /*td 64*/
    if(8 == sizeof(ptrdiff_t))
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            td[0] = td[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%td", &td[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%td", &td[1]);
            /* compare the results */
            isdiff = (td[0] == td[1] && retc == rets);
            outputlld(fstd, fsec, "%td", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, td[0], td[1], __LINE__);
            m++;
        }
    }
    /*td 32*/
    if(4 == sizeof(ptrdiff_t))
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            td[0] = td[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%td", &td[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%td", &td[1]);
            /* compare the results */
            isdiff = (td[0] == td[1] && retc == rets);
            outputint(fstd, fsec, "%td", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, td[0], td[1], __LINE__);
            m++;
        }
    }
    /*zd 64*/
    if(8 == sizeof(size_t))
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            zd[0] = zd[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%zd", &zd[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%zd", &zd[1]);
            /* compare the results */
            isdiff = (zd[0] == zd[1] && retc == rets);
            outputlld(fstd, fsec, "%zd", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, zd[0], zd[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            zd[0] = zd[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%zd", &zd[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%zd", &zd[1]);
            /* compare the results */
            isdiff = (zd[0] == zd[1] && retc == rets);
            outputint(fstd, fsec, "%zd", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, zd[0], zd[1], __LINE__);
            m++;
        }
    }
    /*jd 64*/
    if(8 == sizeof(intmax_t))/* jd */
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            jd[0] = jd[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%jd", &jd[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%jd", &jd[1]);
            /* compare the results */
            isdiff = (jd[0] == jd[1] && retc == rets);
            outputlld(fstd, fsec, "%jd", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, jd[0], jd[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            jd[0] = jd[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%jd", &jd[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%jd", &jd[1]);
            /* compare the results */
            isdiff = (jd[0] == jd[1] && retc == rets);
            outputint(fstd, fsec, "%jd", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, jd[0], jd[1], __LINE__);
            m++;
        }
    }

    {/* hhd */
        m = 0;
        while(sampleschar[m][0] != NULL)
        {
            isdiff = 0;
            hhd[0] = hhd[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleschar[m][0], "%hhd", &hhd[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleschar[m][0], "%hhd", &hhd[1]);
            /* compare the results */
            isdiff = (hhd[0] == hhd[1] && retc == rets);
            outputhhd(fstd, fsec, "%hhd", sampleschar[m][0], sampleschar[m][1], retc, rets, isdiff, hhd[0], hhd[1], __LINE__);
            m++;
        }
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))    
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        Ld[0] = Ld[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%Ld", &Ld[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%Ld", &Ld[1]);
        /* compare the results */
        isdiff = (Ld[0] == Ld[1] && retc == rets);
        outputLd(fstd, fsec, "%Ld", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, Ld[0], Ld[1], __LINE__);
        m++;
    }
#endif
#if defined(_MSC_VER)
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        Ld[0] = Ld[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%Ld", &Ld[0]); /*lint !e566*/
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%Ld", &Ld[1]);
        /* compare the results */
        isdiff = (Ld[0] == Ld[1] && retc == rets);
        outputLd(fstd, fsec, "%Ld", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, Ld[0], Ld[1], __LINE__);
        m++;
    }
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        I64d[0] = I64d[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%I64d", &I64d[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%I64d", &I64d[1]);
        /* compare the results */
        isdiff = (I64d[0] == I64d[1] && retc == rets);
        outputI64d(fstd, fsec, "%I64d", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, I64d[0], I64d[1], __LINE__);
        m++;
    }
#endif
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%4d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%4d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%4d", "12345", "normal", retc, rets, isdiff, d[0], d[1], __LINE__);
    }
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%5d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%5d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%5d", "12345", "normal", retc, rets, isdiff, d[0], d[1], __LINE__);
    }
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%6d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%6d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%6d", "12345", "normal", retc, rets, isdiff, d[0], d[1], __LINE__);
    }

    /* ***********not support veritify***************** */
#if UNSUPPORT_TEST
#if defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux)
    {
        isdiff = 0;
        hd[0] = hd[1] = 0;
        /* print out standard c function result */
        retc = sscanf("32767", "%hhd", &hd[0]);
        /* print out secure c function result */
        rets = sscanf_s("32767", "%hhd", &hd[1]);
        /* compare the results */
        isdiff = (hd[0] == hd[1] && retc == rets);
        outputhd(fstd, fsec, "%hhd", "32767", "edge", retc, rets, isdiff, hd[0], hd[1], __LINE__);    
    }

    /*td 64*/
    if(8 == sizeof(long int))
    {
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%td", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%td", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%td", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
    else
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf("2147483647", "%td", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s("2147483647", "%td", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%td", "2147483647", "edge", retc, rets, isdiff, d[0], d[1], __LINE__);
    }
    /*zd 64*/
    if(8 == sizeof(size_t))
    {
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%zd", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%zd", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%zd", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
    else
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf("2147483647", "%zd", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s("2147483647", "%zd", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%zd", "2147483647", "edge", retc, rets, isdiff, d[0], d[1], __LINE__);
    }
    /*jd 64*/
    isdiff = 0;
    lld[0] = lld[1] = 0;
    /* print out standard c function result */
    retc = sscanf("9223372036854775807", "%jd", &lld[0]);
    /* print out secure c function result */
    rets = sscanf_s("9223372036854775807", "%jd", &lld[1]);
    /* compare the results */
    isdiff = (lld[0] == lld[1] && retc == rets);
    outputlld(fstd, fsec, "%jd","9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
#endif

#if defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX)
    {
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%qd", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%qd", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%qd", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
#endif 
#if defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX)
    {  
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%Ld", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%Ld", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%Ld", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
#endif
#if (defined(_MSC_VER) && 1200 == _MSC_VER)
    {  
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%lld", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%lld", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%lld", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
#endif
#if !(defined(_MSC_VER))
    {  
        isdiff = 0;
        lld[0] = lld[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%I64d", &lld[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%I64d", &lld[1]);
        /* compare the results */
        isdiff = (lld[0] == lld[1] && retc == rets);
        outputlld(fstd, fsec, "%I64d", "9223372036854775807", "edge", retc, rets, isdiff, lld[0], lld[1], __LINE__);
    }
#endif
#endif
    fprintf(fstd, "-------------------------------d test end--------------------------- \n");
    fprintf(fsec, "-------------------------------d test end--------------------------- \n");

} /*lint !e529*/
void test_sscanf_format_o(FILE* fStd, FILE* fSec)
{
#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
  char *formats[] = {
        "%o",   
        "%ho",   
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%hho",   
#endif  
        "%lo", 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llo",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lo", 
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64o",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%jo", 
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qo",   
        "%to",   
        "%zo",
#endif
        NULL
    };
#endif
    char *kuanformats[] = {
        "%0o",   
        "%2o",   
        "%3o",   
        "%5o",   
        NULL
    };

    char *samplesInt[] = {
        "0",   
        "37777777777",   
        "-1",   
        "40000000000", 
        "2000000000000000000000", 
        "-37777777777",   
        "-40000000000", 
        "-40000000001", 
        "-2000000000000000000000", 
        NULL
    };

    char *samplesShort[] = {
        "0",   
        "177777",   
        "-1",   
        "200000", 
        "2000000000000000000000", 
        "-177777",   
        "-200000", 
        "-2000000000000000000000", 
        NULL
    };
#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    char *samplesChar[] = {
        "0",   
        "377",   
        "-1",   
        "400", 
        "177777", 
        "200000", 
        "2000000000000000000000", 
        "-377",   
        "-400", 
        "-177777", 
        "-200000", 
        "-2000000000000000000000", 
        NULL
    };
#endif
#endif
    char *samplesLong[] = {
        "0",   
        "1777777777777777777777",   
        "-1",   
        "2000000000000000000000",   
        "-1777777777777777777777",   
        "-2000000000000000000000",   
        NULL
    };

char *flag[] = 
{
    "edge",
    "edge",     
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "NULL"
};

    int i;
    int secret = 0, sysret = 0;
    int issame = 0;
    unsigned int sec_i, sys_i;
    unsigned short int sec_si, sys_si;
    unsigned long  int sec_li, sys_li;
    UINT64T sec_ll, sys_ll;


    fprintf(fStd, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf("123", kuanformats[i], &sys_i);

        sec_i = 0;
        secret = sscanf_s("123", kuanformats[i], &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT       
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%o\n\n", sysret, sys_i);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%o\n\n", secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame)) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }

#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf("123", formats[i], &sys_ll);

        sec_ll = 0;
        secret = sscanf_s("123", formats[i], &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%llo\n\n", sysret, sys_ll);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%llo\n\n", secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(formats[i],"123","normal",sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%o", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%o", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%o",samplesInt[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesShort[i], "%ho", &sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesShort[i], "%ho", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT        
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%ho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%ho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%ho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesShort[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesShort[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%ho",samplesShort[i],flag[i],sysret,secret,sys_si,"%o",sec_si,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }
#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST || !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesChar[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesChar[i], "%hho", (unsigned char *)&sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesChar[i], "%hho", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT      
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesChar[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesChar[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lo",samplesChar[i],flag[i],sysret,secret,sys_si,"%o",sec_si,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesLong[i], "%lo", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesLong[i], "%lo", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT   
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesLong[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesLong[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lo",samplesLong[i],flag[i],sysret,secret,sys_li,"%lo",sec_li,"%lo",(long unsigned)__LINE__);
#endif
        i++;
    }
#else
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesChar[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesChar[i], "%hho", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesChar[i], "%hho", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hho", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hho", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hho", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesChar[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesChar[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hho",samplesChar[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%lo", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%lo", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lo",samplesInt[i],flag[i],sysret,secret,sys_li,"%lo",sec_li,"%lo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))

    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%llo", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%llo", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
 #if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%llo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%llo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%llo",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
#ifndef IS_TEST_LINUX 

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesInt[i], "%Lo", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesInt[i], "%Lo", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT    
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s (long long int)comparedResult:Equal\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s (long long int)comparedResult:Equal\n", "%Lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s (long long int)comparedResult:Different\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s (long long int)comparedResult:Different (%d)\n", "%Lo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesInt[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesInt[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lo",samplesInt[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }


#if OVERFLOW_MARK && 0 /*Lo is equal of unsigned long long int,this programm is not useful*/
    i = 0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%Lo", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%Lo", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s (int)comparedResult:Equal\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s (int)comparedResult:Equal\n", "%Lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s (int)comparedResult:Different\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s (int)comparedResult:Different (%d)\n", "%Lo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lo",samplesInt[i],flag[i],sysret,secret,sys_i,"%llo",sec_i,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#else
    i = 0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%Lo", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%Lo", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lo",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif


#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%jo", (uintmax_t *)&sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%jo", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%jo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%jo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%jo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%jo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%jo",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%qo", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%qo", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT 
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%qo",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif 
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%to", (ptrdiff_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%to", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%to", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%to", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%to", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%to", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%to",samplesInt[i],flag[i],sysret,secret,sys_li,"%lo",sec_li,"%lo",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%zo", (size_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%zo", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zo", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%zo", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%zo", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lo\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%zo",samplesInt[i],flag[i],sysret,secret,sys_li,"%lo",sec_li,"%lo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#endif

#ifndef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%I64o", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%I64o", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%I64o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%I64o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llo\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%I64o",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llo",sec_ll,"%llo",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

    fprintf(fStd, "-------------------------------o test end--------------------------- \n");
    fprintf(fSec, "-------------------------------o test end--------------------------- \n");

} /*lint !e529*/

void test_sscanf_format_u(FILE* fStd, FILE* fSec)
{
#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
    char *formats[] = {
        "%u",   
        "%hu",   
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) ||  defined(__hpux))
        "%hhu", 
#endif 
        "%lu",   
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llu",  
#endif 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lu", 
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64u",   
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%ju",   
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qu",   
        "%tu",   
        "%zu",
#endif
        NULL
    };
#endif
    char *kuanformats[] = {
        "%0u",   
        "%2u",   
        "%3u",   
        "%5u",   
        NULL
    };

    char *samplesInt[] = {
        "0",   
        "4294967295",   
        "-1",   
        "4294967296",
        "18446744073709551616",   
        "-4294967295",   
        "-4294967296",
        "-18446744073709551616",   
        NULL
    };

    char *samplesShort[] = {
        "0",   
        "65535",   
        "-1",   
        "65536",   
        "18446744073709551616",   
        "-65535",   
        "-65536",   
        "-18446744073709551616",   
        NULL
    };

    char *samplesLong[] = {
        "0",   
        "18446744073709551615",   
        "-1",   
        "18446744073709551616",   
        "-18446744073709551615",   
        "-18446744073709551616",   
        NULL
    };
    char *flag[] = 
    {
        "edge",
        "edge",     
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "NULL"
    };

    int i;
    int secret = 0, sysret = 0;
    int issame = 0;
    unsigned int sec_i, sys_i;
    unsigned short int sec_si, sys_si;
    unsigned long  int sec_li, sys_li;
    UINT64T sec_ll, sys_ll;

    fprintf(fStd, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf("123", kuanformats[i], &sys_i);

        sec_i = 0;
        secret = sscanf_s("123", kuanformats[i], &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%u\n\n", sysret, sys_i);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%u\n\n", secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }

#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf("123", formats[i], &sys_ll);

        sec_ll = 0;
        secret = sscanf_s("123", formats[i], &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%llu\n\n", sysret, sys_ll);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%llu\n\n", secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(formats[i],"123","normal",sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%u", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%u", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%u",samplesInt[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesShort[i], "%hu", &sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesShort[i], "%hu", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hu",samplesShort[i],flag[i],sysret,secret,sys_si,"%u",sec_si,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }
#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) ||  defined(__hpux))
    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesShort[i], "%hhu", (unsigned char *)&sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesShort[i], "%hhu", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hhu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hhu",samplesShort[i],flag[i],sysret,secret,sys_si,"%u",sec_si,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesLong[i], "%lu", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesLong[i], "%lu", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesLong[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesLong[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lu",samplesLong[i],flag[i],sysret,secret,sys_li,"%lu",sec_li,"%lu",(long unsigned)__LINE__);
#endif
        i++;
    }
#else

#if OVERFLOW_MARK
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) ||  defined(__hpux))
    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesShort[i], "%hhu", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesShort[i], "%hhu", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hhu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hhu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesShort[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hhu",samplesShort[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif
    
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%lu", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%lu", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
            if(!(issame && (sysret == secret))) 
                SSCANF("%lu",samplesInt[i],flag[i],sysret,secret,sys_li,"%lu",sec_li,"%lu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%llu", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%llu", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%llu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%llu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%llu",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
#ifndef IS_TEST_LINUX 
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesInt[i], "%Lu", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesInt[i], "%Lu", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesInt[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesInt[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lu",samplesInt[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#else
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%Lu", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%Lu", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lu",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%ju", (uintmax_t *)&sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%ju", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%ju", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%ju", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%ju", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%ju", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%ju",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%qu", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%qu", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%qu",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%tu", (ptrdiff_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%tu", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%tu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%tu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%tu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%tu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%tu",samplesInt[i],flag[i],sysret,secret,sys_li,"%lu",sec_li,"%lu",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%zu", (size_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%zu", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zu", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%zu", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%zu", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lu\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%zu",samplesInt[i],flag[i],sysret,secret,sys_li,"%lu",sec_li,"%lu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#endif
#ifndef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%I64u", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%I64u", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%I64u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%I64u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llu\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%I64u",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llu",sec_ll,"%llu",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

    fprintf(fStd, "-------------------------------u test end--------------------------- \n");
    fprintf(fSec, "-------------------------------u test end--------------------------- \n");

}

void test_sscanf_format_x(FILE* fStd, FILE* fSec)
{
#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
    char *formats[] = {
        "%x",   
        "%hx",   
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%hhx",  
#endif   
        "%lx",   
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llx",  
#endif  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%Lx", 
#endif 
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux)))||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64x",   
#endif  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%jx",   
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qx",   
        "%tx",   
        "%zx",
#endif
        NULL
    };
#endif
    char *formatsBig[] = {
        "%X",   
        "%hX",  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%hhX",   
#endif
        "%lX",  
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
        "%llX",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%LX",  
#endif
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%I64X",  
#endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        "%jX", 
 #endif
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
        "%qX",   
        "%tX",   
        "%zX",
#endif
        NULL
    };

    char *kuanformats[] = {
        "%0x",   
        "%2x",   
        "%3x",   
        "%5x",   
        NULL
    };

    char *samplesInt[] = {
        "0",   
        "ffffffff",   
        "-1",   
        "100000000",  
        "10000000000000000",  
        "-ffffffff",   
        "-100000000",  
        "-10000000000000000",  
        NULL
    };

    char *samplesShort[] = {
        "0",   
        "ffff",   
        "-1",   
        "10000",  
        "10000000000000000",  
        "-ffff",   
        "-10000",  
        "-10000000000000000",  
        NULL
    };

    char *samplesLong[] = {
        "0",   
        "ffffffffffffffff",   
        "-1",   
        "10000000000000000",   
        "-ffffffffffffffff",   
        "-10000000000000000",   
        NULL
    };
char *flag[] = 
{
    "edge",
    "edge",     
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "overflow",
    "NULL"
};

    int i;
    int secret = 0, sysret = 0;
    int issame = 0;
    unsigned int sec_i, sys_i;
    unsigned short int sec_si, sys_si;
    unsigned long  int sec_li, sys_li;
    UINT64T sec_ll, sys_ll;

    fprintf(fStd, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/

    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf("123", kuanformats[i], &sys_i);

        sec_i = 0;
        secret = sscanf_s("123", kuanformats[i], &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%x\n\n", sysret, sys_i);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%x\n\n", secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }

#if (OVERFLOW_MARK)&&(defined( COMPATIBLE_LINUX_FORMAT) ||(defined(_WIN32) || defined(_WIN64)))
    i=0;
    while(NULL != formats[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf("123", formats[i], &sys_ll);

        sec_ll = 0;
        secret = sscanf_s("123", formats[i], &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", formats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", formats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%llx\n\n", sysret, sys_ll);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%llx\n\n", secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(formats[i],"123","normal",sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%x", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%x", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%x",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesShort[i], "%hx", &sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesShort[i], "%hx", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hx",samplesShort[i],flag[i],sysret,secret,sys_si,"%x",sec_si,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }
#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_si = 0;
        sysret = sscanf(samplesShort[i], "%hhx", (unsigned char *)&sys_si);

        sec_si = 0;
        secret = sscanf_s(samplesShort[i], "%hhx", &sec_si);

        if(sys_si != sec_si)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hhx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], sysret, sys_si);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], secret, sec_si);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hhx",samplesShort[i],flag[i],sysret,secret,sys_si,"%x",sec_si,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesLong[i], "%lx", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesLong[i], "%lx", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesLong[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesLong[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lx",samplesLong[i],flag[i],sysret,secret,sys_li,"%lx",sec_li,"%lx",(long unsigned)__LINE__);
#endif
        i++;
    }
#else

#if OVERFLOW_MARK
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesShort[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesShort[i], "%hhx", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesShort[i], "%hhx", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%hhx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%hhx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%hhx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesShort[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%hhx",samplesShort[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%lx", &sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%lx", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%lx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%lx",samplesInt[i],flag[i],sysret,secret,sys_li,"%lx",sec_li,"%lx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) && (_MSC_VER == 1200))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%llx", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%llx", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%llx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%llx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%llx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%llx",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
#ifndef IS_TEST_LINUX 
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesInt[i], "%Lx", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesInt[i], "%Lx", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesInt[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesInt[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lx",samplesInt[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#else
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%Lx", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%Lx", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%Lx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%Lx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%Lx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%Lx",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

#ifdef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%jx", (uintmax_t *)&sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%jx", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%jx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%jx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%jx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%jx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%jx",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#if UNSUPPORT_TEST ||  !(defined(_MSC_VER) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%qx", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%qx", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%qx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%qx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%qx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%qx",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%tx", (ptrdiff_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%tx", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%tx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%tx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%tx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%tx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%tx",samplesInt[i],flag[i],sysret,secret,sys_li,"%lx",sec_li,"%lx",(long unsigned)__LINE__);
#endif
        i++;
    }

    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_li = 0;
        sysret = sscanf(samplesInt[i], "%zx", (size_t *)&sys_li);

        sec_li = 0;
        secret = sscanf_s(samplesInt[i], "%zx", &sec_li);

        if(sys_li != sec_li)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%zx", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%zx", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%zx", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], sysret, sys_li);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%lx\n\n", samplesInt[i], secret, sec_li);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%zx",samplesInt[i],flag[i],sysret,secret,sys_li,"%lx",sec_li,"%lx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif

#endif
#ifndef IS_TEST_LINUX 
#if UNSUPPORT_TEST ||  !((defined(COMPATIBLE_LINUX_FORMAT) && !(defined(__SOLARIS)) && !(defined(_AIX)) && !(defined(__hpux))) ||defined(SECUREC_VXWORKS_PLATFORM) || defined(__SOLARIS) || defined(_AIX) || defined(__hpux))
    i=0;
    while(NULL != samplesLong[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf(samplesLong[i], "%I64x", &sys_ll);

        sec_ll = 0;
        secret = sscanf_s(samplesLong[i], "%I64x", &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%I64x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%I64x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%I64x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], sysret, sys_ll);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%llx\n\n", samplesLong[i], secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%I64x",samplesLong[i],flag[i],sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }
#endif
#endif

    fprintf(fStd, "-------------------------------x test end--------------------------- \n");
    fprintf(fSec, "-------------------------------x test end--------------------------- \n");

    fprintf(fStd, "-------------------------------X test begin--------------------------- \n");
    fprintf(fSec, "-------------------------------X test begin--------------------------- \n");

    i=0;
    while(NULL != formatsBig[i])
    {
        issame = 1;
        sys_ll = 0;
        sysret = sscanf("123", formatsBig[i], &sys_ll);

        sec_ll = 0;
        secret = sscanf_s("123", formatsBig[i], &sec_ll);

        if(sys_ll != sec_ll)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formatsBig[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", formatsBig[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", formatsBig[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", formatsBig[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%llx\n\n", sysret, sys_ll);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%llx\n\n", secret, sec_ll);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(formatsBig[i],"123","normal",sysret,secret,sys_ll,"%llx",sec_ll,"%llx",(long unsigned)__LINE__);
#endif
        i++;
    }

    fprintf(fStd, "-------------------------------X test end--------------------------- \n");
    fprintf(fSec, "-------------------------------X test end--------------------------- \n");

}

/*#if(defined(COMPATIBLE_LINUX_FORMAT))*/
#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))

void test_sscanf_format_d_add(FILE *fstd, FILE *fsec)
{
    char *samplesint[][16]= 
    {/* 0.d */
        {"123745",            "normal"},
        {"2147483647",        "edge"},
        {"-2147483648",        "edge"},
        {NULL,        NULL    },
    }; 

    char *samplesint_interval[][16]= 
    {/* 0.d */
        {"123,745",            "normal"},
        {"2147483647,2147483647",        "edge"},
        {"-2147483648,-2147483648",        "edge"},
        {NULL,        NULL    },
    };                  


    int d[2] = {0}; 
    int temp = 0;
    int m=0,isdiff=0;
    int retc, rets;

    fprintf(fstd, "-------------------------------d test begin-------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------d test begin-------------------------- \n"); /*lint !e668*/            
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM)) 
    /*0.*d*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%*d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%*d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%*d", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, d[0], d[1], __LINE__);
        m++;
    }
#endif
    /*1.   %d*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "   %d", &d[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "   %d", &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "   %d", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, d[0], d[1], __LINE__);
        m++;
    }    

    /*2.%d,%d*/
    m = 0;
    while(samplesint_interval[m][0] != NULL)
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint_interval[m][0], "%d,%d", &temp, &d[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint_interval[m][0], "%d,%d", &temp, &d[1]);
        /* compare the results */
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%d,%d", samplesint_interval[m][0], samplesint_interval[m][1], retc, rets, isdiff, d[0], d[1], __LINE__);
        m++;
    }     


    /*2.%2$d
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        d[0] = d[1] = 0;
        
        retc = sscanf(samplesint[m][0], "%2$d", &temp, &d[0]);
        
        rets = sscanf_s(samplesint[m][0], "%2$d", &temp, &d[1]);
        
        isdiff = (d[0] == d[1] && retc == rets);
        outputint(fstd, fsec, "%2$d", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, d[0], d[1], __LINE__);
        m++;
    }  
    */
    
    fprintf(fstd, "-------------------------------d test end--------------------------- \n");
    fprintf(fsec, "-------------------------------d test end--------------------------- \n");      
}            

void test_sscanf_format_D_add(FILE *fstd, FILE *fsec)
{
    char *sampleslonglong[][64]=
            {/* 1.D = 1d */
                {"4886718345",          "normal"}, 
                {"9223372036854775807", "edge"},
                {"-9223372036854775808","edge"},
                {NULL,        NULL    },
            }; 

    char *samplesint[][64]= 
     {/* 0.d */
            {"74565",            "normal"},
            {"2147483647",        "edge"},
            {"-2147483648",        "edge"},
            {NULL,        NULL    },
       };               


    long int ld[2] = {0};
    int m=0,isdiff=0;
    int retc, rets;

    fprintf(fstd, "-------------------------------D test begin-------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------D test begin-------------------------- \n"); /*lint !e668*/            
    
    /*1.D*/
    if( 8 == sizeof(long int)) /*lint !e506*/
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            ld[0] = ld[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%D", &ld[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%D", &ld[1]);
            /* compare the results */
            isdiff = (ld[0] == ld[1] && retc == rets);
            outputld(fstd, fsec, "%D", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, ld[0], ld[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            printf("size = %d\n", sizeof(long int) );
            isdiff = 0;
            ld[0] = ld[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%D", &ld[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%D", &ld[1]);
            /* compare the results */
            isdiff = (ld[0] == ld[1] && retc == rets);
            outputld(fstd, fsec, "%D", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, ld[0], ld[1], __LINE__);
            m++;
        }
    }
    
    fprintf(fstd, "-------------------------------D test end--------------------------- \n");
    fprintf(fsec, "-------------------------------D test end--------------------------- \n");    
}   

void test_sscanf_format_o_add(FILE* fStd, FILE* fSec)
{
    char *samplesInt[] = {
        "0",  
        "12345",  
        "37777777777",   
        "-1",   
        "40000000000", 
        "2000000000000000000000", 
        "-37777777777",   
        "-40000000000", 
        "-40000000001", 
        "-2000000000000000000000", 
        NULL
    };

    char *samplesint_interval[]= 
    {
        "0,0",  
        "12345,12345",  
        "37777777777,37777777777",   
        "-1,-1",   
        "40000000000,40000000000", 
        "2000000000000000000000,2000000000000000000000", 
        "-37777777777,-37777777777",   
        "-40000000000,-40000000000", 
        "-40000000001,-40000000001", 
        "-2000000000000000000000,-2000000000000000000000", 
        NULL
    };     

    char *flag[] = 
    {
        "edge",
        "normal",
        "edge",     
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "NULL"
    };    
    
    int i;
    int secret = 0, sysret = 0;
    int temp = 0;
    int issame = 0;
    unsigned int sec_i, sys_i;

    fprintf(fStd, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------o test begin--------------------------- \n"); /*lint !e668*/
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    /*0.*o*/    
    i = 0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%*o", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%*o", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%*o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%*o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%o",samplesInt[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }   
#endif  
    /*1.   %*3o%o*/    
    i = 0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "   %*3o%o", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "   %*3o%o", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3o%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3o%o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "   %*3o%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "   %*3o%o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("   %*3o%o",samplesInt[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }  
    
    /*2. %o,%o*/    
    i = 0;
    while(NULL != samplesint_interval[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesint_interval[i], "%o,%o", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesint_interval[i], "%o,%o", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%o,%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%o,%o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%o,%o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%o,%o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesint_interval[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesint_interval[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%o,%o",samplesint_interval[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    } 
    

  /*3. %2$o   
    i = 0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%2$o", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%2$o", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$o", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%2$o", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%2$o", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%o\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%2$o",samplesInt[i],flag[i],sysret,secret,sys_i,"%o",sec_i,"%o",(long unsigned)__LINE__);
#endif
        i++;
    }                 
    */ 
}     

void test_sscanf_format_u_add(FILE* fStd, FILE* fSec)
{
    char *samplesInt[] = {
        "0", 
        "123456",  
        "4294967295",   
        "-1",   
        "4294967296",
        "18446744073709551616",   
        "-4294967295",   
        "-4294967296",
        "-18446744073709551616",   
        NULL
    };

    char *samplesint_interval[]= 
    {
        "0,0", 
        "123456,123456",  
        "4294967295,4294967295",   
        "-1,-1",   
        "4294967296,4294967296",
        "18446744073709551616,18446744073709551616",   
        "-4294967295,-4294967295",   
        "-4294967296,-4294967296",
        "-18446744073709551616,-18446744073709551616",   
        NULL
    };    

    char *flag[] = 
    {
        "edge",
        "normal",        
        "edge",     
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "NULL"
    };  

    int i;
    int secret = 0, sysret = 0;
    int temp = 0;
    int issame = 0;
    unsigned int sec_i, sys_i; 
    
    fprintf(fStd, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------u test begin--------------------------- \n"); /*lint !e668*/ 
#if !(defined(SECUREC_VXWORKS_PLATFORM))    
    /*0. %*u*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%*u", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%*u", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%*u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%*u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%*u",samplesInt[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }    
#endif
    /*1.   %*3u%u*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "   %*3u%u", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "   %*3u%u", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3u%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3u%u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "   %*3u%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "   %*3u%u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("   %*3u%u",samplesInt[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }         

    /*2.%u,%u*/
    i=0;
    while(NULL != samplesint_interval[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesint_interval[i], "%u,%u", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesint_interval[i], "%u,%u", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%u,%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%u,%u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%u,%u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%u,%u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesint_interval[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesint_interval[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%u,%u",samplesint_interval[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }    

    /*3. %2$u
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%2$u", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%2$u", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$u", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%2$u", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%2$u", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%u\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%2$u",samplesInt[i],flag[i],sysret,secret,sys_i,"%u",sec_i,"%u",(long unsigned)__LINE__);
#endif
        i++;
    }*/  
           
}  

void test_sscanf_format_x_add(FILE* fStd, FILE* fSec)
{
    char *samplesInt[] = {
        "0",   
        "12345",          
        "ffffffff",   
        "-1",   
        "100000000",  
        "10000000000000000",  
        "-ffffffff",   
        "-100000000",  
        "-10000000000000000",  
        NULL
    };

    char *samplesint_interval[]= 
    {
        "0,0",   
        "12345,12345",          
        "ffffffff,ffffffff",   
        "-1,-1",   
        "100000000,100000000",  
        "10000000000000000,10000000000000000",  
        "-ffffffff,-ffffffff",   
        "-100000000,-100000000",  
        "-10000000000000000,-10000000000000000",  
        NULL
    };     
    
    char *flag[] = 
    {
        "edge",
        "normal",         
        "edge",     
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "NULL"
    }; 

    int i;
    int secret = 0, sysret = 0;
    int temp = 0;
    int issame = 0;
    unsigned int sec_i, sys_i;

    fprintf(fStd, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/    
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    /*0. %*x*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%*x", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%*x", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%*x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%*x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%*x",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }   
#endif
    /*1.    %*3x%x*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "   %*3x%x", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "   %*3x%x", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3x%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3x%x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "   %*3x%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "   %*3x%x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("   %*3x%x",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }  

    /*2. %x,%x*/
    i=0;
    while(NULL != samplesint_interval[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesint_interval[i], "%x,%x", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesint_interval[i], "%x,%x", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%x,%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%x,%x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%x,%x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%x,%x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesint_interval[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesint_interval[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%x,%x",samplesint_interval[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    } 


    /*3. %2$x
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%2$x", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%2$x", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$x", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%2$x", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%2$x", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%2$x",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }                    
    */
}  

void test_sscanf_format_X_add(FILE* fStd, FILE* fSec)
{
    char *samplesInt[] = {
        "0",   
        "12345",          
        "ffffffff",   
        "-1",   
        "100000000",  
        "10000000000000000",  
        "-ffffffff",   
        "-100000000",  
        "-10000000000000000",  
        NULL
    };

    char *samplesint_interval[]= 
    {
        "0,0",   
        "12345,12345",          
        "ffffffff,ffffffff",   
        "-1,-1",   
        "100000000,100000000",  
        "10000000000000000,10000000000000000",  
        "-ffffffff,-ffffffff",   
        "-100000000,-100000000",  
        "-10000000000000000,-10000000000000000",  
        NULL
    };     
    
    char *flag[] = 
    {
        "edge",
        "normal",         
        "edge",     
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "overflow",
        "NULL"
    }; 

    char *kuanformats[] = {
        "%0X",   
        "%2X",   
        "%3X",   
        "%5X",   
        NULL
    };    

    int i;
    int secret = 0, sysret = 0;
    int temp = 0;    
    int issame = 0;
    unsigned int sec_i, sys_i;

    fprintf(fStd, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/
    fprintf(fSec, "-------------------------------x test begin--------------------------- \n"); /*lint !e668*/    
#if (UNSUPPORT_TEST) || !(defined(SECUREC_VXWORKS_PLATFORM))
    /*0. %*X*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%*X", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%*X", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%*X", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%*X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%*X", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%*X",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }   
#endif
    /*1.    %*3X%X*/
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "   %*3X%X", &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "   %*3X%X", &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3X%X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "   %*3X%X", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "   %*3X%X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "   %*3X%X", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("   %*3X%X",samplesInt[i],flag[i],sysret,secret,sys_i,"%X",sec_i,"%X",(long unsigned)__LINE__);
#endif
        i++;
    }  

    /*2. %X,%X*/
    i=0;
    while(NULL != samplesint_interval[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesint_interval[i], "%X,%X", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesint_interval[i], "%X,%X", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%X,%X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%X,%X", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%X,%X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%X,%X", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesint_interval[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesint_interval[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%X,%X",samplesint_interval[i],flag[i],sysret,secret,sys_i,"%X",sec_i,"%X",(long unsigned)__LINE__);
#endif
        i++;
    }   
    
    /*3. %(kuan du)X*/
    i=0;
    while(NULL != kuanformats[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf("123", kuanformats[i], &sys_i);

        sec_i = 0;
        secret = sscanf_s("123", kuanformats[i], &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Equal\n", kuanformats[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-normal comparedResult:Different\n", kuanformats[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-normal comparedResult:Different (%d)\n", kuanformats[i], __LINE__);
        }
        fprintf(fStd, "input value:123\nreturn value :%2d\noutput value:%x\n\n", sysret, sys_i);
        fprintf(fSec, "input value:123\nreturn value :%2d\noutput value:%x\n\n", secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF(kuanformats[i],"123","normal",sysret,secret,sys_i,"%X",sec_i,"%X",(long unsigned)__LINE__);
#endif
        i++;
    } 

    /*4. %2$X
    i=0;
    while(NULL != samplesInt[i])
    {
        issame = 1;
        sys_i = 0;
        sysret = sscanf(samplesInt[i], "%2$X", &temp, &sys_i);

        sec_i = 0;
        secret = sscanf_s(samplesInt[i], "%2$X", &temp, &sec_i);

        if(sys_i != sec_i)
        {
            issame = 0;
        }
#if TXT_DOCUMENT_PRINT
        if(issame && (sysret == secret))
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Equal\n", "%2$X", flag[i]);
        }
        else
        {
            fprintf(fStd, "Expression:sscanf-(%s)-%s comparedResult:Different\n", "%2$X", flag[i]);
            fprintf(fSec, "Expression:sscanf-(%s)-%s comparedResult:Different (%d)\n", "%2$X", flag[i], __LINE__);
        }
        fprintf(fStd, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], sysret, sys_i);
        fprintf(fSec, "input value:%s\nreturn value :%2d\noutput value:%x\n\n", samplesInt[i], secret, sec_i);
#endif
#if SCREEN_PRINT
        if(!(issame && (sysret == secret))) 
            SSCANF("%2$X",samplesInt[i],flag[i],sysret,secret,sys_i,"%x",sec_i,"%x",(long unsigned)__LINE__);
#endif
        i++;
    }*/                   
    
} 



#endif
