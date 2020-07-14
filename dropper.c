#include<stdio.h>

#define PAYLOAD "\x4d\x5a\x90\x01\x03\x01\x01\x01\x04\x01\x01\x01\xff\xff\x01\x01"

int main()
{
    FILE *f = fopen("payload.bin","wb");
    fprintf(f,PAYLOAD);
    fclose(f);
    return 0;
}
