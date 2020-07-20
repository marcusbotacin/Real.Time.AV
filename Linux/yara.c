#include<stdio.h>
#include<yara.h>

// YARA callback for matching rules
int callback_function(int message,void* message_data, void* user_data)
{
    if(message == CALLBACK_MSG_RULE_MATCHING)
    {
        YR_RULE *rule = (YR_RULE*)message_data;
        fprintf(stderr,"\033[1;31m");
        fprintf(stderr,">>> Matched %s!\n",rule->identifier);
        fprintf(stderr,"\033[0m");
    }
    return CALLBACK_CONTINUE;
}
