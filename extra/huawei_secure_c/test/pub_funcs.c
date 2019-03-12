#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define oneLineLen 96
#define cfgNameLen 48  /*Configure switch name length*/
#define cfgMaxNum 50   /*The total number of configuration switch*/

/*�ṹ��*/
struct testSwitch
{
    char name[cfgNameLen];
    int value;
};
struct testSwitch tSwitch[cfgMaxNum];

void substing(char *pSrc,char *pDes,int StartPos,int len)
{
    if(StartPos > (int)strlen(pSrc))
        return ;
    len = ( (int)(strlen(pSrc)) - StartPos) > len ? len:( (int)(strlen(pSrc)) - StartPos);
    (void)strncpy(pDes, pSrc+StartPos, (size_t)len);
    pDes[len] = '\0';

} 

char * Trim( char * str ) 
{
    int len = (int)strlen(str);     
    int i = 0;

    int j = 1; 

    char *newStr = NULL;

    int p = 0;

    /*ͳ���ַ���ǰ�˿ո���*/
    while(*(str + i) == ' ')     
    {
        i++;
    }

    /*ͳ���ַ�����˿ո���*/
    while ( *(str + len - j) == ' ')
    {
        j++;
    }

    /*���¼����޼�����ַ�����*/
    len = len - i - j + 1;      
    newStr = (char*)malloc(len+1);
    if (newStr == NULL)
    {
        return NULL;
    }

    for (p = 0; p < len; p++)     
    {         
        *(newStr + p) = *(str + i + p);
    }

    newStr[len] = '\0'; 

    return newStr; 
}

void initSwitch()
{
    int i = 0;
    for(i = 0; i <cfgMaxNum; i++) {
        memset(tSwitch[i].name, 0, cfgNameLen);
        tSwitch[i].value = 0;
    }
}

int readSwitch()
{
    /*���ڱ����ȡ�����ļ���һ������*/
    char lineData[oneLineLen]={0};
    char lineDataSubA[oneLineLen]={0};
    char lineDataSubB[oneLineLen]={0};
    char *pSubA = NULL;
    char *pSubB = NULL;
    int effect = 0;
    int len = 0;
    /*ѭ������*/
    int loop = 0;

    FILE *fp = fopen("../test/switch.ini","r");
    if (fp == NULL)
    {
        (void)printf("switch.ini open fail.\n");
        return -1;
    }

    while (1)
    {
        if (effect >= cfgMaxNum)
        {
            (void)printf("tSwitch is full.\n");
            break;
        }

        /*���ļ���β*/
        if (fgets(lineData, oneLineLen, fp) == NULL )
        {
            /*(void)printf("switch.ini file is end.\n");*/
            break ;
        }

        /*ע����*/
        if ('#' == lineData[0])
        {
            continue;
        }

        /*��ֹ����*/
        len = strlen(lineData);
        if (len <= 0)
        {
            (void)printf("00000000.\n");
            continue;
        }

        /************************************************************************/
        /*�Ե�һ����=��Ϊ���޷���aa=1     
        aa������testSwitch.name
        1������value
        */
        /************************************************************************/
        for (loop=0;loop<len;loop++)
        {
            /*�ҵ�*/
            if (lineData[loop]=='=')
            {
                break;
            }
        }

        substing(lineData, lineDataSubA, 0, loop);
        substing(lineData, lineDataSubB, loop+1, len-(loop+1));  

        /*ȥ�����˵Ŀո񲢱���*/
        pSubA = Trim(lineDataSubA);
        if (pSubA==NULL)
        {
            (void)printf("Trim return null.\n");
            continue;
        }
        strcpy(tSwitch[effect].name, pSubA);
        free(pSubA);

        pSubB = Trim(lineDataSubB);
        if (pSubB==NULL)
        {
            (void)printf("Trim return null.\n");
            continue;
        }
        tSwitch[effect].value = atol(pSubB);
        free(pSubB);

        effect++;
    }

    fclose(fp);

    return 0;
}

int getSwitch(char *name, int value)
{
    int i = 0;
    for(i = 0; i <cfgMaxNum; i++) 
    {
        if ( strcmp(name,tSwitch[i].name )==0)
        {
            return tSwitch[i].value;
        }
    }               
    return value;
}
