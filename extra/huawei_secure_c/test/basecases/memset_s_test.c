#include "securec.h"
#include "base_funcs.h"
#include <assert.h>
#include <string.h>

#define LEN   ( 256 )

void test_memset_s(void)
{
    errno_t rc;
    uint32_t len;
    uint32_t i;

    UINT8T value;
    UINT8T mem1[LEN];
    char hugeBuf[2072];
    char *p = hugeBuf;

    /* wzh add, declare */
    //int i = 0;
    char pp[300] = {0};
    char *pp2 = NULL;
    //char *pp3 = NULL;
    /* declare end */

    rc = memset_s(mem1, LEN, 2, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1, LEN, 0, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1, LEN, 3, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1, LEN, 0, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1, LEN, 5, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1, LEN, 0, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1+ 1, LEN, 5, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1 +1, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1+ 3, LEN, 0x23, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1 +3, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1+ 1, LEN, 0x45, 73);
    assert((rc & 0x7F) == EOK);

    rc = memset_s(mem1 +1, LEN,  0, 73);
    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_s(NULL, LEN, value, LEN);

    assert((rc & 0x7F) == EINVAL);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_s(mem1, 0, value, LEN);

    assert((rc & 0x7F) == ERANGE);


/*--------------------------------------------------*/

    value = 34;

    rc = memset_s(hugeBuf, SECUREC_MEM_MAX_LEN , 0xFF, 2072);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 1;
    value = 34;

    rc = memset_s(mem1, len, value, len);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 12;
    value = 34;

    rc = memset_s(mem1, len, value, 99 );

    assert((rc & 0x7F) == ERANGE);

    rc = memset_s((char*)(((size_t)p+16) & ((size_t)(~0x7))), 3, 2, 3);
    assert(*(char*)(((size_t)p+16) & ((size_t)(~0x7))) == 2);
    assert((rc & 0x7F) == EOK);

/*-------- wzh add begin 20150408----------------- */
    pp2 = (char *)( ( (long)pp & -8) + 16);
    printf("pp2 addr:%p\n", pp2);
    
    /* Test 0 */
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp2[i-1]);
    }

    /* Test 0xFF */
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0xFF, i);
        assert((rc & 0x7F) == EOK);
        assert( (char)0xFF == pp2[i-1]);
    }

    /* Test 'a' */
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 'a', i);
        assert((rc & 0x7F) == EOK);
        assert( 'a' == pp2[i-1]);
    }

    pp2 = (char *)(((long)pp & -8) + 16 + 1);
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp2[i-1]);
    }
    pp2 = (char *)(((long)pp & -8) + 16 + 2);
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp2[i-1]);
    }
    pp2 = (char *)(((long)pp & -8) + 16 + 4);
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp2[i-1]);
    }
    pp2 = (char *)(((long)pp & -8) + 16 + 5);
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_s(pp2, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp2[i-1]);
    }
    /* wzh add end */
}

#if defined(WITH_PERFORMANCE_ADDONS)
static void test_memset_sOptAsm(void)
{
    errno_t rc;
    uint32_t len;
    uint32_t i;

    UINT8T value;
    UINT8T mem1[LEN];
    char hugeBuf[2072];
    char *p = hugeBuf;

    /* wzh add, declare */
    //int i = 0;
    char pp[300] = {0};
    //char *pp2 = NULL;
    char *pp3 = NULL;
    /* declare end */

    rc = memset_sOptAsm(mem1, LEN, 2, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1, LEN, 0, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1, LEN, 3, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1, LEN, 0, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1, LEN, 5, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1, LEN, 0, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1+ 1, LEN, 5, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1 +1, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1+ 3, LEN, 0x23, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1 +3, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1+ 1, LEN, 0x45, 73);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptAsm(mem1 +1, LEN,  0, 73);
    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_sOptAsm(NULL, LEN, value, LEN);

    assert((rc & 0x7F) == EINVAL);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_sOptAsm(mem1, 0, value, LEN);

    assert((rc & 0x7F) == ERANGE);


/*--------------------------------------------------*/

    value = 34;

    rc = memset_sOptAsm(hugeBuf, SECUREC_MEM_MAX_LEN , 0xFF, 2072);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 1;
    value = 34;

    rc = memset_sOptAsm(mem1, len, value, len);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 12;
    value = 34;

    rc = memset_sOptAsm(mem1, len, value, 99 );

    assert((rc & 0x7F) == ERANGE);

    rc = memset_sOptAsm((char*)(((size_t)p+16) & ((size_t)(~0x7))), 3, 2, 3);
    assert(*(char*)(((size_t)p+16) & ((size_t)(~0x7))) == 2);
    assert((rc & 0x7F) == EOK);

/*----- Test memset_sOptTc, wzh add 20150408--------- */
    pp3 = (char *)( ( (long)pp & -8) + 16);
    printf("pp3 addr:%p\n", pp3);

    /* Test 0 */
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp3[i-1]);
    }

    /* Test 0xFF */
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0xFF, i);
        assert((rc & 0x7F) == EOK);
        assert( (char)0xFF == pp3[i-1]);
    }

    /* Test 'a' */
    for(i = 1 ; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 'a', i);
        assert((rc & 0x7F) == EOK);
        assert( 'a' == pp3[i-1]);
    }

    pp3 = (char *)(((long)pp & -8) + 16 + 1);
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp3[i-1]);
    }

    pp3 = (char *)(((long)pp & -8) + 16 + 2);
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp3[i-1]);
    }

    pp3 = (char *)(((long)pp & -8) + 16 + 4);
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp3[i-1]);
    }

    pp3 = (char *)(((long)pp & -8) + 16 + 5);
    for(i = 1; i <= 32; i++)
    {
        rc = memset_sOptTc(pp3, 256, 0, i);
        assert((rc & 0x7F) == EOK);
        assert( 0 == pp3[i-1]);
    }

    /* wzh add end */
}
void test_memset_sp(void)
{
    errno_t rc;
    uint32_t len;
    uint32_t i;
    char * temp = NULL;

    UINT8T value;
    UINT8T mem1[LEN];
        char hugeBuf[2072];

    rc = memset_sp(mem1, LEN, 2, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1, LEN, 0, 3);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1, LEN, 3, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1, LEN, 0, 7);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1, LEN, 5, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1, LEN, 0, 24);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1+ 1, LEN, 5, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1 +1, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1+ 3, LEN, 0x23, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1 +3, LEN, 0, 5);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1+ 1, LEN, 0x45, 73);
    assert((rc & 0x7F) == EOK);

    rc = memset_sp(mem1 +1, LEN,  0, 73);
    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_sp(temp, LEN, value, LEN);

    assert((rc & 0x7F) == EINVAL);

/*--------------------------------------------------*/

    value = 34;

    rc = memset_sp(mem1, 0, value, LEN);

    assert((rc & 0x7F) == ERANGE);


/*--------------------------------------------------*/

    value = 34;

    rc = memset_sp(hugeBuf, SECUREC_MEM_MAX_LEN , 0xFF, 2072);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 1;
    value = 34;

    rc = memset_sp(mem1, len, value, len);

    assert((rc & 0x7F) == EOK);

/*--------------------------------------------------*/

    for (i=0; i<LEN; i++) { mem1[i] = 99; }

    len = 12;
    value = 34;

    rc = memset_sp(mem1, len, value, 99 );

    assert((rc & 0x7F) == ERANGE);

/*--------------------------------------------------*/
    value = 0xa;
    len = 1;
    rc = memset_sp(mem1, value, value, len);/*will make complie warning: comparison is always true due to limited range of data type*/

    assert((rc & 0x7F) == EOK);

     rc = memset_sOptTc(mem1,48,1,40);
    assert((rc & 0x7F) == EOK);

    rc = memset_sOptTc(mem1,32,1,40);
    assert(rc == ERANGE_AND_RESET);
    test_memset_sOptAsm();

}
#endif

