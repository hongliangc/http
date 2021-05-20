#pragma once
#include <vector>
#include "utility.h"
#include "sqlite3.h"
#ifdef WIN32

int test_sqlite()
{
	sqlite3 * pDB;
	int iReturn = sqlite3_open("./Test.db", &pDB);
	if (iReturn != SQLITE_OK) {
		return 1;
	}


	char buf[65535] = "232302FE202020202020202020202020202020202001016515031F0A133201FFFF01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF020101FFFFFFFFFFFFFFFFFFFFFF050100000000000000000601FFFFFF01FFFFFF01FFFF01FFFF0703000408200603CD0359F340BA09550000BD03D30359F4C0000000000000000000080101FFFFFFFF0060000160FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0901010030FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF47";
	string out;

	int len = strlen(buf);
	if (len % 2 != 0)
	{
		cout << "buf len is not even number!" << endl;
		return -1;
	}
	_utility::ConvertHex2Str((unsigned char*)buf, len, out);

	// create table
	{
		std::string str = "CREATE TABLE if not exists Names(ID INTEGER PRIMARY KEY, Name text, Data text)";
		iReturn = sqlite3_exec(pDB, str.c_str(), NULL, NULL, NULL);
		if (iReturn != SQLITE_OK) {
			sqlite3_close(pDB);
			return 1;
		}
	}



	{
		/*²åÈë*/
		std::string sql = "INSERT INTO Names(Data) VALUES(?)";
		sqlite3_stmt * pStmt = nullptr;
		sqlite3_prepare_v2(pDB, sql.c_str(), sql.length() + 1, &pStmt, nullptr);
		for (int i = 0; i < 4; i++)
		{
			sqlite3_bind_blob(pStmt, 1, out.c_str(), out.length(), nullptr);
			if (sqlite3_step(pStmt) != SQLITE_DONE)
				printf("Error message: %s\n", sqlite3_errmsg(pDB));
			printf("len:%d, %s\n", out.length(), out.c_str());
			sqlite3_reset(pStmt);
		}
		sqlite3_finalize(pStmt);
	}
	{
		/*²éÑ¯*/
		std::string sql = "select Name, Data from Names";
		sqlite3_stmt * pStmt = nullptr;
		// compile sql statement to binary
		if (sqlite3_prepare_v2(pDB, sql.c_str(), sql.length() + 1, &pStmt, nullptr) != SQLITE_OK) {
			printf("ERROR: while compiling sql: %s\n", sqlite3_errmsg(pDB));
			sqlite3_close(pDB);
			sqlite3_finalize(pStmt);
		}

		// execute sql statement, and while there are rows returned, print ID
		int row = 1;
		while (sqlite3_step(pStmt) == SQLITE_ROW)
		{
			int len = sqlite3_column_bytes(pStmt, 0);
			const unsigned char *ptr = sqlite3_column_text(pStmt, 0);
			printf("row:%d  len:%d, data:%s\n", row, len, ptr);

			int len1 = sqlite3_column_bytes(pStmt, 1);
			const unsigned char *ptr1 = sqlite3_column_text(pStmt, 1);

			//_utility::ConvertStr2Hex((unsigned char*)ptr1, len1, hex);
			if (memcmp(out.c_str(), ptr1, len1) != 0)
			{
				printf("query data error!\n");
			}
			printf("row:%d  len1:%d, data1:%s\n", row, len1, ptr1);
			row++;
		}

		//release resources
		sqlite3_finalize(pStmt);
	}

	// insert data using binding
	{
		std::string str = "INSERT INTO Names(Name,Data) VALUES(?,?)";
		sqlite3_stmt * pStmt = nullptr;

		iReturn = sqlite3_prepare_v2(pDB, str.c_str(), str.size() + 1, &pStmt, nullptr);
		if (iReturn != SQLITE_OK) {
			sqlite3_close(pDB);
			return 1;
		}

		printf("The statement %s has %d parameter(s).\n", str.c_str(), sqlite3_bind_parameter_count(pStmt));

		std::vector<std::string> vecNames;
		vecNames.push_back("Smith");
		vecNames.push_back("Morpheus");
		vecNames.push_back("Neo");

		for (unsigned int i = 0, iEnd = vecNames.size(); i != iEnd; ++i)
		{
			iReturn = sqlite3_bind_text(pStmt, 1, vecNames[i].c_str(), -1, nullptr);
			if (iReturn != SQLITE_OK) {
				return 1;
			}
			iReturn = sqlite3_bind_text(pStmt, 2, out.c_str(), out.length(), nullptr);

			if (sqlite3_step(pStmt) != SQLITE_DONE) {
				sqlite3_finalize(pStmt);
				sqlite3_close(pDB);
				return 1;
			}

			sqlite3_reset(pStmt);
			sqlite3_clear_bindings(pStmt);
		}

	}

	// query using one bind parameter
	{
		sqlite3_stmt * pStmt = nullptr;
		string str = "SELECT ID FROM Names WHERE Name=?1";
		iReturn = sqlite3_prepare_v2(pDB, str.c_str(), str.size() + 1, &pStmt, nullptr);
		if (iReturn != SQLITE_OK) {
			return 1;
		}

		printf("The statement %s has %d parameters(s).\n", str.c_str(), sqlite3_bind_parameter_count(pStmt));

		// fourth parameter is length = position of \0
		iReturn = sqlite3_bind_text(pStmt, 1, "Neo", 3, NULL);
		if (iReturn != SQLITE_OK) {
			return 1;
		}

		vector<string> vecResults;
		char cBuffer[1024];
		string strBuffer;
		while (sqlite3_step(pStmt) == SQLITE_ROW)
		{
			sprintf(cBuffer, "%s", sqlite3_column_text(pStmt, 0));
			strBuffer = cBuffer;
			vecResults.push_back(strBuffer);
		}

		sqlite3_finalize(pStmt);

		printf("Found %d results.\n", vecResults.size());
		for (unsigned int i = 0, iEnd = vecResults.size(); i != iEnd; ++i)
		{
			printf("%d: %s\n", i, vecResults[i].c_str());
		}
	}

	// query using two bind parameters
	{
		sqlite3_stmt * pStmt = nullptr;
		string str = "SELECT ID FROM Names WHERE Name=?1 AND ID=?2";
		iReturn = sqlite3_prepare_v2(pDB, str.c_str(), str.size() + 1, &pStmt, nullptr);
		if (iReturn != SQLITE_OK) {
			return 1;
		}

		printf("The statement %s has %d parameters(s).\n", str.c_str(), sqlite3_bind_parameter_count(pStmt));

		// fourth parameter is length = position of \0
		iReturn = sqlite3_bind_text(pStmt, 1, "Neo", 3, NULL);
		if (iReturn != SQLITE_OK) {
			return 1;
		}


		//iReturn = sqlite3_bind_text(pStmt, 2, "3", 2, NULL);
		iReturn = sqlite3_bind_int(pStmt, 2, 3);
		if (iReturn != SQLITE_OK) {
			return 1;
		}


		vector<string> vecResults;
		char cBuffer[1024];
		string strBuffer;
		while (sqlite3_step(pStmt) == SQLITE_ROW)
		{
			sprintf(cBuffer, "%s", sqlite3_column_text(pStmt, 0));
			strBuffer = cBuffer;
			vecResults.push_back(strBuffer);
		}

		sqlite3_finalize(pStmt);

		printf("Found %d results.\n", vecResults.size());
		for (unsigned int i = 0, iEnd = vecResults.size(); i != iEnd; ++i)
		{
			printf("%d: %s\n", i, vecResults[i].c_str());
		}
	}

	sqlite3_close(pDB);

	return 0;
}
#endif