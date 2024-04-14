#include<stdbool.h>

struct leafNode{
    int path[256];
    bool includingFlag[256];
};



bool searchStr(char* str);

void insertStr(char* str);


int compareStrings(const char* str1, const char* str2);


void initDB();

