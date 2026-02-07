#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <postgresql/libpq-fe.h>

static PGconn *db_conn = NULL;

PGconn* db_connect() {
    if (db_conn != NULL && PQstatus(db_conn) == CONNECTION_OK) {
        return db_conn;
    }

    const char *conninfo = "host=localhost port=5432 dbname=auth_system user=rao008";

    db_conn = PQconnectdb(conninfo);

    if (PQstatus(db_conn) != CONNECTION_OK) {
        fprintf(stderr, "Database connection failed: %s\n", PQerrorMessage(db_conn));
        PQfinish(db_conn);
        db_conn = NULL;
        return NULL;
    }
    return db_conn;
}

int db_check_credentials(const char *username, const char *password_hash) {
    PGconn *conn = db_connect();
    if (!conn) {
        return 0;
    }

    const char *query = "SELECT password_hash FROM users WHERE username = $1";
    const char *params[1] = { username };

    PGresult *res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return 0;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        return 0;
    }

    char *stored_hash = PQgetvalue(res, 0, 0);
    int result = (strcmp(password_hash, stored_hash) == 0);
    PQclear(res);
    return result;
}

