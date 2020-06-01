#if 0

#include <stdio.h>
#include <stdlib.h>
#include <string>

#ifdef __cplusplus
extern "C" {
#include "../sdk/include/sqlite3.h"
#endif
#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

using namespace std;

#define DB_FILE  "test.db"
#define DB_ERR	sqlite3_errmsg 
int main()
{
	sqlite3 *db;
	char *errmsg;
	int ret = 0;
	if (SQLITE_OK != sqlite3_open(DB_FILE, &db))
	{
		printf("can't open database.err:%s\n",DB_ERR(db));
	}
	else
	{
		printf("open database successfully!\n");
	}
	sqlite3_busy_timeout(db, 1000);
	//create sql statement
	string sql = "create table company("\
		"ID INT PRIMARY KEY NOT NULL,"\
		"NAME TEXT NOT NULL,"\
		"AGE INT NOT NULL,"\
		"ADDRESS CHAR(50),"\
		"SALARY REAL);";
	//execute sql statement
	if (SQLITE_OK !=sqlite3_exec(db, sql.c_str(), NULL, NULL, &errmsg))
	{
		printf("create table failed! err:%s\n",errmsg);
	}
	else
	{
		printf("create table succesfully!\n");
	}
	//insert data to table company
	sql = "insert into company(ID, NAME, AGE, ADDRESS, SALARY) "\
		"values(1, 'Paul', 32, 'California', 20000.0);"\
		"insert into company(ID, NAME, AGE, ADDRESS, SALARY) "\
		"values(2, 'Allen', 25, 'Texas', 21000.0);"\
		"insert into company(ID, NAME, AGE, ADDRESS, SALARY) "\
		"values(3, 'Teddy', 31, 'Norway', 23000.0);";
	sqlite3_busy_timeout(db, 1000);
	if (SQLITE_OK != sqlite3_exec(db,sql.c_str(), NULL, NULL, &errmsg))
	{
		printf("insert data to database failed! err:%s\n",errmsg);
	}
	else
	{
		printf("insert data to database table succesfully!\n");
	}
	sqlite3_close(db);
	return 0;
};
#else
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
	int i;
	for(i=0; i<argc; i++){
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	printf("\n");
	return 0;
}

int main(int argc, char* argv[])
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char *sql;

	/* Open database */
	rc = sqlite3_open("test.db", &db);
	if( rc ){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		exit(0);
	}else{
		fprintf(stderr, "Opened database successfully\n");
	}

	/* Create SQL statement */
	sql = "CREATE TABLE COMPANY("  \
		"ID INT PRIMARY KEY     NOT NULL," \
		"NAME           TEXT    NOT NULL," \
		"AGE            INT     NOT NULL," \
		"ADDRESS        CHAR(50)," \
		"SALARY         REAL );";

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}else{
		fprintf(stdout, "Table created successfully\n");
	}

	/* Create SQL statement */
	sql = "INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
		"VALUES (1, 'Paul', 32, 'California', 20000.00 ); " \
		"INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) "  \
		"VALUES (2, 'Allen', 25, 'Texas', 15000.00 ); "     \
		"INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
		"VALUES (3, 'Teddy', 23, 'Norway', 20000.00 );" \
		"INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY)" \
		"VALUES (4, 'Mark', 25, 'Rich-Mond ', 65000.00 );";

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}else{
		fprintf(stdout, "Records created successfully\n");
	}
	sqlite3_close(db);
	return 0;
}
#endif