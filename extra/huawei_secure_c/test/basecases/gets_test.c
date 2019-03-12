/******************************************************************************

Copyright (C), 2001-2012, Huawei Tech. Co., Ltd.

******************************************************************************
File Name     :
Version       :
Author        :
Created       : 2010/9/1
Last Modified :
Description   :
Function List :

History       :
1.Date        : 2010/9/1
Author      :
Modification: Created file

******************************************************************************/


#include "securec.h"
#include "base_funcs.h"
#include <assert.h>
#include <string.h>

#define LEN (10)



void test_gets_s(void)
{
    char buff[LEN];

    char *rc = NULL;

    rc = gets_s(NULL, LEN);
    assert(rc == NULL);

    /*--------------------------------------------------*/

    rc = gets_s(buff, 0);
    assert(rc == NULL);
    /*--------------------------------------------------*/



    rc = gets_s(buff, SECUREC_STRING_MAX_LEN + 1);
    assert(rc == NULL);

    /*--------------------------------------------------*/

    rc = gets_s(NULL, 0);
    assert(rc == NULL);

    /*--------------------------------------------------*/

    rc = gets_s(NULL, SECUREC_STRING_MAX_LEN + 1);
    assert(rc == NULL);

    /*--------------------------------------------------*/

    rc = gets_s(buff, LEN-1);
    printf("%s", rc);

}


