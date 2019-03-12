#include "securec.h"
#include "testutil.h"
#include "comp_funcs.h"
#include <string.h>

#ifdef COMPATIBLE_LINUX_FORMAT
#include <stdint.h>
#include <stddef.h>
#endif

void makeoutputint(FILE *fstd, 
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
    fprintf(fstd, "output value: %i\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %i\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%i",secnumber,"%i",line);
#endif
}

void makeoutputli(FILE *fstd, 
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
    fprintf(fstd, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fstd, "comparedResult:Different\n");
    else
        fprintf(fstd, "comparedResult:Equal\n");
    fprintf(fstd, "input  value : %s\n", sample);
    fprintf(fstd, "return value : %-2d\n", stdresult);
    fprintf(fstd, "output value: %li\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %li\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%li",secnumber,"%li",line);
#endif
} 

#if !(defined(_MSC_VER)||defined(SECUREC_VXWORKS_PLATFORM) ||defined(__UNIX))
void makeoutputLi(FILE *fstd, 
                  FILE *fsec, 
                  char *formats, 
                  char *sample, 
                  char *sampletype,
                  int stdresult,
                  int secresult,
                  int isequal,
                  long long int stdnumber,
                  long long  int secnumber,
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
    fprintf(fstd, "output value: %Li\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %Li\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%lli",secnumber,"%lli",line);
#endif
} 
#endif
#if defined(_MSC_VER)
void makeoutputLi(FILE *fstd, 
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
    fprintf(fstd, "output value: %Li\n\n", stdnumber); /*lint !e566*/

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%u)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %Li\n\n", secnumber); /*lint !e566*/
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%i",secnumber,"%i",line);
#endif
} 
#endif
void makeoutputlli(FILE *fstd, 
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
    fprintf(fstd, "output value: %lli\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %lli\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%lli",secnumber,"%lli",line);
#endif
} 
void makeoutputhi(FILE *fstd, 
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
    fprintf(fstd, "output value: %hi\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %hi\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%hi",secnumber,"%hi",line);
#endif
} 
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
void makeoutputhhi(FILE *fstd, 
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
    fprintf(fstd, "output value: %hhi\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype);
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%lu)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %hhi\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%hhi",secnumber,"%hhi",line);
#endif
} 
#endif
#if defined(_MSC_VER)
void makeoutputI64i(FILE *fstd, 
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
    fprintf(fstd, "output value: %I64i\n\n", stdnumber);

    /* print out the compare result to securec function result file */
    fprintf(fsec, "Expression:sscanf-(%-5s)-%-12s", formats, sampletype); /*lint !e668*/
    if(!(isequal))
        fprintf(fsec, "comparedResult:Different(%u)\n", line);
    else
        fprintf(fsec, "comparedResult:Equal\n");
    fprintf(fsec, "input  value : %s\n", sample);
    fprintf(fsec, "return value : %-2d\n", secresult);
    fprintf(fsec, "output value: %I64i\n\n", secnumber);
#endif
#if SCREEN_PRINT
    if(!(isequal)) 
        SSCANF(formats,sample,sampletype,stdresult,secresult,stdnumber,"%I64i",secnumber,"%I64i",line);
#endif
}
#endif

void test_sscanf_format_i(FILE *fstd, FILE *fsec)
{
    char *samplesint[][64]= 
        {/* 0.i */
            /* 10 */
            {"74565",            "normal"},
            {"2147483647",        "edge"},
            {"-2147483648",        "edge"},
#if OVERFLOW_MARK
            {"2147483648",        "overflow(long long int)"},
            {"-2147483649",        "overflow(long longint)"},
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
            /* 16 */
            {"0x12345",                "normal"},
            {"0x7FFFFFFF",            "edge"},
            {"-0x80000000",            "edge"},
#if OVERFLOW_MARK
            {"0x80000000",            "overflow(long long int)"},
            {"0xFFFFFFFFF",            "overflow(long long int)"},
            {"0x7ffffffff",            "overflow(long long int)"},
#endif
            /* 8 */
            {"0221505",              "normal"},
            {"017777777777",         "edge"},
            {"-020000000000",        "edge"},
#if OVERFLOW_MARK
            {"020000000000",         "overflow(long long int)"},
            {"0177777777777",        "overflow(long long int)"},
            {"0200000000000",        "overflow(long long int)"},
#endif
            {NULL,        NULL   },
        };

        char *sampleslonglong[][64]=
            {/* 2.lli */
                /* 10 */
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
                /* 16 */
                {"0x123456789",         "normal"},
                {"0x7fffffffffffffff",  "edge"  },
                {"-0x8000000000000000",  "edge"  },
#if OVERFLOW_MARK
                {"0x8000000000000000",  "overflow(unsigned long long int)"  },
                {"0x7ffffffffffffffff", "overflow(unsigned long long int)"},
                {"0x80000000000000000", "overflow(unsigned long long int)"},
#endif
                /* 8 */
                {"044321263611",         "normal"},
                {"0777777777777777777777","edge" },
                {"-01000000000000000000000","edge" },
#if OVERFLOW_MARK
                {"01000000000000000000000","overflow(unsigned long long int)" },
                {"07777777777777777777777","overflow(unsigned long long int)" },
                {"010000000000000000000000","overflow(unsigned long long int)" },
#endif
                {NULL,        NULL    },
            };

        char *samplesshortint[][64]=
            {/* 3.hi */
                /* 10 */
                {"12345",       "normal"},
                {"32767",       "edge"},
                {"-32768",      "edge"},
#if OVERFLOW_MARK
                {"32768",       "overflow(int)"},
                {"-32769",      "overflow(int)"},
                {"2147483647",        "overflow(int)"},
                {"-2147483648",        "overflow(int)"},
                {"2147483648",        "overflow(long long int)"},
                {"-2147483649",        "overflow(long long  int)"},
                {"4294967295",        "overflow(long long  int)"},
                {"4294967296",        "overflow(long long  int)"},
                {"-4294967295",        "overflow(long long  int)"},
                {"-4294967296",        "overflow(long long  int)"},
                {"9223372036854775807","overflow(long long int)"},
                {"-9223372036854775808","overflow(long long int)"},
                {"9223372036854775808","overflow(unsigned long long int)"},
                {"-9223372036854775809","overflow(unsigned long long int)"},
                {"18446744073709551615","overflow(unsigned long long int)"},
                {"-18446744073709551616","overflow(unsigned long long int)"},
                {"18446744073709551616","overflow(unsigned long long int)"},
                {"-18446744073709551617","overflow(unsigned long long int)"},
#endif
                /* 16 */
                {"0x3039",         "normal"},
                {"0x7FFF",         "edge"},
                {"-0x8000",        "edge"},
#if OVERFLOW_MARK
                {"0x8000",         "overflow(int)"},
                {"0xFFFFF",        "overflow(int)"},
                {"0x80000",        "overflow(int)"},
#endif
                /* 8 */
                {"030071",        "normal"},
                {"077777",        "edge"},
                {"-0100000",      "edge"},
#if OVERFLOW_MARK
                {"0100000",       "overflow(int)"},
                {"07777777",      "overflow(int)"},
                {"01000000",      "overflow(int)"},
#endif
                {NULL,        NULL},
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
                        /* 16 */
                        {"0x12345",                "normal"},
                        {"0x7FFFFFFF",            "edge"},
                        {"-0x80000000",            "edge"},
#if OVERFLOW_MARK
                        {"0x80000000",            "overflow(long long int)"},
                        {"0xFFFFFFFFF",            "overflow(long long int)"},
                        {"0x7ffffffff",            "overflow(long long int)"},
#endif
                        /* 8 */
                        {"0221505",              "normal"},
                        {"017777777777",         "edge"},
                        {"-020000000000",        "edge"},
#if OVERFLOW_MARK
                        {"020000000000",         "overflow(long long int)"},
                        {"0177777777777",        "overflow(long long int)"},
                        {"0200000000000",        "overflow(long long int)"},
#endif
                        {NULL, NULL},
                    };
#endif
                
        short int hi[2] = {0};
        int i[2] = {0};    
        long int li[2] = {0};
        INT64T lli[2]= {0};
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        long long int Li[3]= {0};
#endif
#if defined(_MSC_VER)
        int Li[3]= {0};
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
        long long int qi[2]= {0};
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
        ptrdiff_t ti[2] = {0};
        size_t    zi[2] = {0};
        intmax_t  ji[2]={0};
        char      hhi[2]= {0};
#endif

#if defined(_MSC_VER) 
        __int64 I64i[2] = {0}; 
#endif

    int m=0,isdiff=0;
    int retc, rets;

    fprintf(fstd, "-------------------------------i test begin-------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------i test begin-------------------------- \n"); /*lint !e668*/
    /*0.i*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%i", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, i[0], i[1], __LINE__);
        m++;
    }
    /*1.li*/
    if( 8 == sizeof(long int)) /*lint !e506*/
    {
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        li[0] = li[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%li", &li[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%li", &li[1]);
        /* compare the results */
        isdiff = (li[0] == li[1] && retc == rets);
        makeoutputli(fstd, fsec, "%li", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, li[0], li[1], __LINE__);
        m++;
    }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            li[0] = li[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%li", &li[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%li", &li[1]);
            /* compare the results */
                isdiff = (li[0] == li[1] && retc == rets);
            makeoutputli(fstd, fsec, "%li", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, li[0], li[1], __LINE__);
            m++;
        }
    }
    /*2.lli*/
#if !(defined(_MSC_VER) && 1200 == _MSC_VER)
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%lli", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%lli", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%lli", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, lli[0], lli[1], __LINE__);
        m++;
    }
#endif
    /*3.hi*/
    m = 0;
    while(samplesshortint[m][0] != NULL)
    {
        isdiff = 0;
        hi[0] = hi[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesshortint[m][0], "%hi", &hi[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesshortint[m][0], "%hi", &hi[1]);
        /* compare the results */
        isdiff = (hi[0] == hi[1] && retc == rets);
        makeoutputhi(fstd, fsec, "%hi", samplesshortint[m][0], samplesshortint[m][1], retc, rets, isdiff, hi[0], hi[1], __LINE__);
        m++;
    }
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))
    /*4.qi*/
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        qi[0] = qi[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%qi", &qi[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%qi", &qi[1]);
        /* compare the results */
        isdiff = (qi[0] == qi[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%qi", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, qi[0], qi[1], __LINE__);
        m++;
    }
#endif
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux))
    /*ti 64*/
    if(8 == sizeof(ptrdiff_t))
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            ti[0] = ti[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%ti", &ti[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%ti", &ti[1]);
            /* compare the results */
            isdiff = (ti[0] == ti[1] && retc == rets);
            makeoutputlli(fstd, fsec, "%ti", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, ti[0], ti[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            ti[0] =ti[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%ti", &ti[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%ti", &ti[1]);
            /* compare the results */
            isdiff = (ti[0] == ti[1] && retc == rets);
            makeoutputint(fstd, fsec, "%ti", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, ti[0], ti[1], __LINE__);
            m++;
        }
    }
    /*zi 64*/
    if(8 == sizeof(size_t))
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            zi[0] = zi[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%zi", &zi[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%zi", &zi[1]);
            /* compare the results */
            isdiff = (zi[0] == zi[1] && retc == rets);
            makeoutputlli(fstd, fsec, "%zi", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, zi[0], zi[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            zi[0] = zi[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%zi", &zi[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%zi", &zi[1]);
            /* compare the results */
            isdiff = (zi[0] == zi[1] && retc == rets);
            makeoutputint(fstd, fsec, "%zi", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, zi[0], zi[1], __LINE__);
            m++;
        }
    }
    /*ji 64*/
    if(8 == sizeof(intmax_t))/* ji */
    {
        m = 0;
        while(sampleslonglong[m][0] != NULL)
        {
            isdiff = 0;
            ji[0] = ji[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleslonglong[m][0], "%ji", &ji[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleslonglong[m][0], "%ji", &ji[1]);
            /* compare the results */
            isdiff = (ji[0] == ji[1] && retc == rets);
            makeoutputlli(fstd, fsec, "%ji", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, ji[0], ji[1], __LINE__);
            m++;
        }
    }
    else
    {
        m = 0;
        while(samplesint[m][0] != NULL)
        {
            isdiff = 0;
            ji[0] = ji[1] = 0;
            /* print out standard c function result */
            retc = sscanf(samplesint[m][0], "%ji", &ji[0]);
            /* print out secure c function result */
            rets = sscanf_s(samplesint[m][0], "%ji", &ji[1]);
            /* compare the results */
            isdiff = (ji[0] == ji[1] && retc == rets);
            makeoutputint(fstd, fsec, "%ji", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, ji[0], ji[1], __LINE__);
            m++;
        }
    }

    {/* hhi */
        m = 0;
        while(sampleschar[m][0] != NULL)
        {
            isdiff = 0;
            hhi[0] = hhi[1] = 0;
            /* print out standard c function result */
            retc = sscanf(sampleschar[m][0], "%hhi", &hhi[0]);
            /* print out secure c function result */
            rets = sscanf_s(sampleschar[m][0], "%hhi", &hhi[1]);
            /* compare the results */
            isdiff = (hhi[0] == hhi[1] && retc == rets);
            makeoutputhhi(fstd, fsec, "%hhi", sampleschar[m][0], sampleschar[m][1], retc, rets, isdiff, hhi[0], hhi[1], __LINE__);
            m++;
        }
    }
#endif
    /*Li*/
#if !(defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX))  
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        Li[0] = Li[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%Li", &Li[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%Li", &Li[1]);
        /* compare the results */
        isdiff = (Li[0] == Li[1] && retc == rets);
        makeoutputLi(fstd, fsec, "%Li", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, Li[0], Li[1], __LINE__);
        m++;
    }
#endif
#if defined(_MSC_VER)
    /*Li */
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        Li[0] = Li[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%Li", &Li[0]); /*lint !e566*/
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%Li", &Li[1]);
        /* compare the results */
        isdiff = (Li[0] == Li[1] && retc == rets);
        makeoutputLi(fstd, fsec, "%Li", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, Li[0], Li[1], __LINE__);
        m++;
    }
    /*I64i*/
    m = 0;
    while(sampleslonglong[m][0] != NULL)
    {
        isdiff = 0;
        I64i[0] = I64i[1] = 0;
        /* print out standard c function result */
        retc = sscanf(sampleslonglong[m][0], "%I64i", &I64i[0]);
        /* print out secure c function result */
        rets = sscanf_s(sampleslonglong[m][0], "%I64i", &I64i[1]);
        /* compare the results */
        isdiff = (I64i[0] == I64i[1] && retc == rets);
        makeoutputI64i(fstd, fsec, "%I64i", sampleslonglong[m][0], sampleslonglong[m][1], retc, rets, isdiff, I64i[0], I64i[1], __LINE__);
        m++;
    }
#endif
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%4i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%4i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%4i", "12345", "normal", retc, rets, isdiff, i[0], i[1], __LINE__);
    }
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%5i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%5i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%5i", "12345", "normal", retc, rets, isdiff, i[0], i[1], __LINE__);
    }
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf("12345", "%6i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s("12345", "%6i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%6i", "12345", "normal", retc, rets, isdiff, i[0], i[1], __LINE__);
    }
    /* ***********not support veritify***************** */
#if UNSUPPORT_TEST
#if defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__hpux)
    {
        isdiff = 0;
        hi[0] = hi[1] = 0;
        /* print out standard c function result */
        retc = sscanf("32767", "%hhi", &hi[0]);
        /* print out secure c function result */
        rets = sscanf_s("32767", "%hhi", &hi[1]);
        /* compare the results */
        isdiff = (hi[0] == hi[1] && retc == rets);
        makeoutputhi(fstd, fsec, "%hhi", "32767", "edge", retc, rets, isdiff, hi[0], hi[1], __LINE__);    
    }
    /*td 64*/
    if(8 == sizeof(long int))
    {
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%ti", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%ti", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%ti", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
    else
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf("2147483647", "%ti", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s("2147483647", "%ti", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%ti", "2147483647", "edge", retc, rets, isdiff, i[0], i[1], __LINE__);
    }
    /*zd 64*/
    if(8 == sizeof(size_t))
    {
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%zi", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%zi", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%zi", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
    else
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf("2147483647", "%zi", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s("2147483647", "%zi", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%zi", "2147483647", "edge", retc, rets, isdiff, i[0], i[1], __LINE__);
    }
    /*jd 64*/
    isdiff = 0;
    lli[0] = lli[1] = 0;
    /* print out standard c function result */
    retc = sscanf("9223372036854775807", "%ji", &lli[0]);
    /* print out secure c function result */
    rets = sscanf_s("9223372036854775807", "%ji", &lli[1]);
    /* compare the results */
    isdiff = (lli[0] == lli[1] && retc == rets);
    makeoutputlli(fstd, fsec, "%ji","9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
#endif
#if defined(_MSC_VER) || defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX)
    {
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%qi", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%qi", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%qi", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
#endif
#if defined(SECUREC_VXWORKS_PLATFORM) || defined(__UNIX)
    {  
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%Li", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%Li", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%Li", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
#endif
#if (defined(_MSC_VER) && 1200 == _MSC_VER)
    {  
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%lli", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%lli", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%lli", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
#endif
#if !(defined(_MSC_VER))
    {  
        isdiff = 0;
        lli[0] = lli[1] = 0;
        /* print out standard c function result */
        retc = sscanf("9223372036854775807", "%I64i", &lli[0]);
        /* print out secure c function result */
        rets = sscanf_s("9223372036854775807", "%I64i", &lli[1]);
        /* compare the results */
        isdiff = (lli[0] == lli[1] && retc == rets);
        makeoutputlli(fstd, fsec, "%I64i", "9223372036854775807", "edge", retc, rets, isdiff, lli[0], lli[1], __LINE__);
    }
#endif
#endif
    fprintf(fstd, "-------------------------------i test end--------------------------- \n");
    fprintf(fsec, "-------------------------------i test end--------------------------- \n");
} /*lint !e529*/


/*#if(defined(COMPATIBLE_LINUX_FORMAT))*/
#if (defined(COMPATIBLE_TESTCASE_LINUX_MANUAL))

void test_sscanf_format_i_add(FILE *fstd, FILE *fsec)
{
    char *samplesint[][64]= 
        {/* 0.i */
            /* 10 */
            {"74565",            "normal"},
            {"2147483647",        "edge"},
            {"-2147483648",        "edge"},
#if OVERFLOW_MARK
            {"2147483648",        "overflow(long long int)"},
            {"-2147483649",        "overflow(long longint)"},
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
            /* 16 */
            {"0x12345",                "normal"},
            {"0x7FFFFFFF",            "edge"},
            {"-0x80000000",            "edge"},
#if OVERFLOW_MARK
            {"0x80000000",            "overflow(long long int)"},
            {"0xFFFFFFFFF",            "overflow(long long int)"},
            {"0x7ffffffff",            "overflow(long long int)"},
#endif
            /* 8 */
            {"0221505",              "normal"},
            {"017777777777",         "edge"},
            {"-020000000000",        "edge"},
#if OVERFLOW_MARK
            {"020000000000",         "overflow(long long int)"},
            {"0177777777777",        "overflow(long long int)"},
            {"0200000000000",        "overflow(long long int)"},
#endif
            {NULL,        NULL   },
        };

    char *samplesint_interval[][64]= 
        {/* 0.i */
            /* 10 */
            {"74565,74565",            "normal"},
            {"2147483647,2147483647",        "edge"},
            {"-2147483648,-2147483648",        "edge"},

            /* 16 */
            {"0x12345,0x12345",                "normal"},
            {"0x7FFFFFFF,0x7FFFFFFF",            "edge"},
            {"-0x80000000,-0x80000000",            "edge"},

            /* 8 */
            {"0221505,0221505",              "normal"},
            {"017777777777,017777777777",         "edge"},
            {"-020000000000,-020000000000",        "edge"},

            {NULL,        NULL   },
        };
 
    int i[2] = {0};  
    int temp = 0;   
    int m=0,isdiff=0;
    int retc, rets;

    fprintf(fstd, "-------------------------------i test begin-------------------------- \n"); /*lint !e668*/
    fprintf(fsec, "-------------------------------i test begin-------------------------- \n"); /*lint !e668*/
#if !(defined(SECUREC_VXWORKS_PLATFORM))
    /*0.*i*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "%*i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "%*i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%*i", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, i[0], i[1], __LINE__);
        m++;
    }   
#endif
    /*1.   %*3i%i*/
    m = 0;
    while(samplesint[m][0] != NULL)
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint[m][0], "   %*3i%i", &i[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint[m][0], "   %*3i%i", &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "   %*3i%i", samplesint[m][0], samplesint[m][1], retc, rets, isdiff, i[0], i[1], __LINE__);
        m++;
    }  

    /*2.%i,%i*/
    m = 0;
    while(samplesint_interval[m][0] != NULL)
    {
        isdiff = 0;
        i[0] = i[1] = 0;
        /* print out standard c function result */
        retc = sscanf(samplesint_interval[m][0], "%i,%i", &temp, &i[0]);
        /* print out secure c function result */
        rets = sscanf_s(samplesint_interval[m][0], "%i,%i", &temp, &i[1]);
        /* compare the results */
        isdiff = (i[0] == i[1] && retc == rets);
        makeoutputint(fstd, fsec, "%i,%i", samplesint_interval[m][0], samplesint_interval[m][1], retc, rets, isdiff, i[0], i[1], __LINE__);
        m++;
    }          
}

#endif
