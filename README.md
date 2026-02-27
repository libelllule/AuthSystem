# Secure Authentication System (HTTPS + UNIX Socket Daemon)

Secure two-component authentication system for Linux. Includes a UNIX socket daemon for credential verification and an HTTPS server for handling user login requests.

## Architecture

1.  **Authentication Daemon (auth_daemon)**:
    *   Background daemon listening on `/tmp/auth_daemon.sock`.
    *   Receives requests in `username:password_hash\n` format.
    *   Validates credentials against PostgreSQL.
    *   Returns: `SUCCESS`, `INVALID_PASSWORD`, `USER_NOT_FOUND`, or `ERROR`.

2.  **HTTPS Server (server)**:
    *   Web server listening on port 8443.
    *   Serves static HTML from `./html`.
    *   Hashes passwords with SHA-256.
    *   Communicates with daemon via UNIX socket.

3.  **Database Layer (database.c/h)**:
    *   PostgreSQL interface used by the authentication daemon.

## Features

*   HTTPS/TLS encryption.
*   Isolated authentication logic.
*   SHA-256 password hashing.
*   Non-blocking I/O using poll().
*   Proper daemonization and signal handling.
*   Efficient file serving via mmap().

## Project Structure

*   `auth_daemon.c` - Authentication daemon source.
*   `database.c/h` - PostgreSQL database helpers.
*   `server.c` - HTTPS server source.
*   `schema.sql` - Database schema.
*   `Makefile` - Build system.
*   `html/` - Web root directory.
*   `server.crt/key` - SSL/TLS certificates.

## System Requirements

### Platform
*   **Linux**: Uses fork(), UNIX domain sockets (AF_UNIX), and poll().

### Dependencies
*   gcc, make, libpq-dev, libssl-dev, postgresql.

## Installation

1.  **Database Setup**:
    ```bash
    sudo systemctl start postgresql
    sudo -u postgres psql -f schema.sql
    ```

2.  **Configuration**:
    Update the connection string in `database.c`:
    ```c
    const char *conninfo = "host=localhost port=5432 dbname=auth_system user=USER password=PASS";
    ```

3.  **Build**:
    ```bash
    make certs
    make html_dir
    make all
    ```

## Usage

1.  **Start Daemon**:
    ```bash
    ./auth_daemon
    ```

2.  **Start Server**:
    ```bash
    ./server
    ```

3.  **Access**:
    Navigate to `https://localhost:8443`.
    Default test users: `alice` or `bob` (password: `password123`).

## Security Notes

*   **Credentials**: Change default PostgreSQL and test user passwords.
*   **Socket**: If connection fails, check `/tmp/auth_daemon.sock` permissions.

## Maintenance

*   **Stop Services**: `pkill auth_daemon` and `Ctrl+C` for server.
*   **Clean Build**: `make clean` or `make distclean`.

