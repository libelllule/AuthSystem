#ifndef DATABASE_H
#define DATABASE_H

#include <postgresql/libpq-fe.h>

PGconn* db_connect();
int db_check_credentials(const char* username, const char* password_hash);
int db_add_user(const char* username, const char* password_hash);

#endif
