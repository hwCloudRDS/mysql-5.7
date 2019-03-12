#include "securec.h"
#include "base_funcs.h"
#include <assert.h>
#include <string.h>

#if !(defined(SECUREC_VXWORKS_PLATFORM))
#include <wchar.h>
#endif

#define LEN   ( 1024 )



void memmove_s_test()
{
    errno_t rc;
    unsigned int i;
    unsigned int len;
    UINT8T  mem1[LEN];
    UINT8T  mem2[LEN];

/*--------------------------------------------------*/

    rc = memmove_s(mem1, LEN, mem2, 0); /*lint !e603*/
    assert(rc == EOK );
/*--------------------------------------------------*/

    rc = memmove_s(NULL, LEN, mem2, LEN);
    assert(rc == EINVAL );

/*--------------------------------------------------*/

    rc = memmove_s(mem1, 0, mem2, LEN);
    assert(rc == ERANGE);

/*--------------------------------------------------*/

    rc = memmove_s(mem1, SECUREC_STRING_MAX_LEN+1, mem2, LEN);
    assert( rc == ERANGE );

/*--------------------------------------------------*/

    rc = memmove_s(mem1, LEN, NULL, LEN);
    assert(rc == EINVAL_AND_RESET);

/*--------------------------------------------------*/

    rc = memmove_s(mem1, 10, mem2, 0);
    assert(rc == EOK);  /*error*/

/*--------------------------------------------------*/

    rc = memmove_s(mem1, LEN, mem2, SECUREC_STRING_MAX_LEN+1);

    assert(rc == ERANGE_AND_RESET); 

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* a valid move */
    len = LEN;
    rc = memmove_s(mem1, len, mem2, LEN);

    assert(rc == EOK);

    for (i=0; i<len; i++) {
        if (mem1[i] != mem2[i]) {
            printf("%u m1=%d  m2=%d  \n",
                 i, mem1[i], mem2[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* length error */
    len = LEN/2;
    rc = memmove_s(mem1, len, mem2, LEN);

    assert(rc == ERANGE_AND_RESET);

    /* verify mem1 was zeroed */
    for (i=0; i<len; i++) {
        if (mem1[i] != 0) {
            printf("%d - %u m1=%d \n",
                 __LINE__, i, mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* invalid length - zero dest */
    len = LEN;
    rc = memmove_s(mem1, len, mem2, 0);

    assert(rc == EOK);


/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* invalid length - zero dest */
    len = LEN;
    rc = memmove_s(mem1, len, mem2, SECUREC_STRING_MAX_LEN+1);

    assert(rc == ERANGE_AND_RESET);

    /* verify mem1 was zeroed */
    for (i=0; i<len; i++) {
        if (mem1[i] != 0) {
            printf("%d - %u m1=%d \n",
                 __LINE__, i, mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* same ptr - no move */
    rc = memmove_s(mem1, LEN, mem1, LEN);

    assert(rc == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem1[i] = 35; }

    /* overlap move */
    len = 20;
    rc = memmove_s(&mem1[0], len, &mem1[10], len);

    assert(rc == EOK);

    for (i=0; i<len; i++) {
        if (mem1[i] != 35) {
            printf("%d - %u m1=%d \n",
                 __LINE__, i, mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem1[i] = 35; }

    /* overlap move */
    len = 20;
    rc = memmove_s(&mem1[10], len, &mem1[0], len);

    assert(rc == EOK);

    for (i=0; i<LEN; i++) { mem2[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem2[i] = 35; }

    for (i=0; i<10; i++) {
        if (mem1[i] != 25) {
            printf("%d - %u m1=%d \n",
                 __LINE__, i, mem1[i]);
        }
    }
}

#ifndef SECUREC_VXWORKS_PLATFORM
void wmemmove_s_test()
{
    errno_t rc;
    uint32_t i;
    uint32_t len;
    wchar_t  mem1[LEN];
    wchar_t  mem2[LEN];

    rc = wmemmove_s(mem1, LEN, mem2, 0); /*lint !e603*/
    assert(rc == EOK );

/*--------------------------------------------------*/

    rc = wmemmove_s(NULL, LEN, mem2, LEN);
    assert(rc == EINVAL );

/*--------------------------------------------------*/

    rc = wmemmove_s(mem1, 0, mem2, LEN);
    assert(rc == ERANGE);

/*--------------------------------------------------*/

    rc = wmemmove_s(mem1, SECUREC_STRING_MAX_LEN+1, mem2, LEN);
    assert( rc == ERANGE );

/*--------------------------------------------------*/

    rc = wmemmove_s(mem1, LEN, NULL, LEN);
    assert(rc == EINVAL_AND_RESET);

/*--------------------------------------------------*/

    rc = wmemmove_s(mem1, 10, mem2, 0);
    assert(rc == EOK);  /*error*/

/*--------------------------------------------------*/

    rc = wmemmove_s(mem1, LEN, mem2, SECUREC_STRING_MAX_LEN+1);
    assert(rc == ERANGE_AND_RESET); 

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* a valid move */
    len = LEN;
    rc = wmemmove_s(mem1, len, mem2, LEN);

    assert(rc == EOK);

    for (i=0; i<len; i++) {
        if (mem1[i] != mem2[i]) {
            printf("%d m1=%d  m2=%d  \n", (int)i, (int)mem1[i], (int)mem2[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* length error */
    len = LEN/2;
    rc = wmemmove_s(mem1, len, mem2, LEN);

    assert(rc == ERANGE_AND_RESET);

    /* verify mem1 was zeroed */
    for (i=0; i<len; i++) {
        if (mem1[i] != 0) {
            printf("%d - %d m1=%d \n",
                 __LINE__, (int)i, (int)mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* invalid length - zero dest */
    len = LEN;
    rc = wmemmove_s(mem1, len, mem2, 0);
    assert(rc == EOK);



/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* invalid length - zero dest */
    len = LEN;
    rc = wmemmove_s(mem1, len, mem2, SECUREC_STRING_MAX_LEN+1);
    assert(rc == ERANGE_AND_RESET);

    /* verify mem1 was zeroed */
    for (i=0; i<len; i++) {
        if (mem1[i] != 0) {
            printf("%d - %d m1=%d \n",
                 __LINE__, (int)i, (int)mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 33; }
    for (i=0; i<LEN; i++) { mem2[i] = 44; }

    /* same ptr - no move */
    rc = wmemmove_s(mem1, LEN, mem1, LEN);

    assert(rc == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem1[i] = 35; }

    /* overlap move */
    len = 20;
    rc = wmemmove_s(&mem1[0], len, &mem1[10], len);

    assert(rc == EOK);

    for (i=0; i<len; i++) {
        if (mem1[i] != 35) {
            printf("%d - %d m1=%d \n",
                 __LINE__, (int)i, (int)mem1[i]);
        }
    }

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem1[i] = 35; }

    /* overlap move */
    len = 20;
    rc = wmemmove_s(&mem1[10], len, &mem1[0], len);

    assert(rc == EOK);

    for (i=0; i<LEN; i++) { mem2[i] = 25; }
    for (i=10; i<LEN-10; i++) { mem2[i] = 35; }

    for (i=0; i<10; i++) {
        if (mem1[i] != 25) {
            printf("%d - %d m1=%d \n",
                 __LINE__, (int)i, (int)mem1[i]);
        }
    }
}
#endif
