#include<stdio.h>
#include<stdbool.h>
#include"Search.h"
#include<string.h>
#include <sqlite3.h>


int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    NotUsed = 0;
    // for (int i = 0; i < argc; i++) {
        // printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    // }
    // printf("\n");

    return argc;
}

#define MAX_LEAFNODE 256

struct leafNode ROOT[MAX_LEAFNODE];
sqlite3 *db;
char *errMsg = 0;
int rc;

bool initsettingCnt = 0;

void initDB(){
    char* sql;
    rc = sqlite3_open("./db/test.db", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return(0);
    } else {
        fprintf(stdout, "Opened database successfully\n");
    }

    // SQL 쿼리: 테이블 생성
    sql = "CREATE TABLE DOMAINNAME("  \
          "ID INTEGER  PRIMARY KEY     AUTOINCREMENT," \
          "DOMAIN varchar(100)    NOT NULL UNIQUE);";
    
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        fprintf(stdout, "Table created successfully\n");
    }

    sql = "CREATE INDEX idx_domain ON DOMAINNAME(DOMAIN);";
    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating index: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        fprintf(stdout, "Index created successfully\n");
    }

}

int callback2(void *NotUsed, int argc, char **argv, char **azColName) {
    int *result = NotUsed;
    int i;
    for (i = 0; i < argc; i++) {
        // printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        *result = 1;
    }
    return 0;
}

bool searchStr(char* str){

    if(initsettingCnt == 0){
        initsettingCnt +=1;
        initDB();
    }

    char sql[200];
    str[strlen(str)-1] ='\0';

    snprintf( sql ,sizeof(sql), "SELECT * FROM DOMAINNAME WHERE DOMAIN = \'%s\';", str);

    int result=0;
    rc = sqlite3_exec(db, sql, callback2, &result, &errMsg);

    if (rc != SQLITE_OK) {
        // fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        // fprintf(stdout, "Operation done successfully\n");
    }
    
    return result;
}



void insertStr(char* str){
    if(initsettingCnt == 0){
        initsettingCnt +=1;
        initDB();
    }

    char sql[100];
    sprintf(sql, "INSERT INTO DOMAINNAME (DOMAIN) VALUES ( '%s' ); ", str);

    rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        // fprintf(stdout, "Records created successfully\n");
    }



    // sqlite3_close(db);
    return 0;
}


int compareStrings(const char* str1, const char* str2){
    while(*str1 && *str2 && *str1 == *str2){
        str1++;
        str2++;
    }

    return *str1 - *str2;
}








