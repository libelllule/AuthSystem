# Secure Authentication System (HTTPS + UNIX Socket Daemon)

Secure two-component authentication system for Linux. Includes a UNIX socket daemon for credential verification and an HTTPS server for handling user login requests.

## Architecture

1. **Authentication Daemon (auth_daemon)**:
    * Background daemon listening on `/tmp/auth_daemon.sock`.
    * Receives requests in `username:password_hash\n` format.
    * Validates credentials against PostgreSQL.
    * Returns: `SUCCESS`, `INVALID_PASSWORD`, `USER_NOT_FOUND`, or `ERROR`.

2. **HTTPS Server (server)**:
    * Web server listening on port 8443.
    * Serves static HTML from `./html`.
    * Hashes passwords with SHA-256.
    * Communicates with daemon via UNIX socket.

3. **Database Layer (database.c/h)**:
    * PostgreSQL interface used by the authentication daemon.

## Features

* HTTPS/TLS encryption.
* Isolated authentication logic.
* SHA-256 password hashing.
* Non-blocking I/O using poll().
* Proper daemonization and signal handling.
* Efficient file serving via mmap().

## Project Structure

* `auth_daemon.c` - Authentication daemon source.
* `database.c/h` - PostgreSQL database helpers.
* `server.c` - HTTPS server source.
* `schema.sql` - Database schema.
* `Makefile` - Build system.
* `html/` - Web root directory.
* `server.crt/key` - SSL/TLS certificates.

## System Requirements

### Platform
* **Linux**: Uses fork(), UNIX domain sockets (AF_UNIX), and poll().

### Dependencies
* gcc, make, libpq-dev, libssl-dev, openssl, postgresql.

## Installation

### 1. Install Dependencies
Install all necessary libraries and tools:
~~~bash
make install_deps
~~~

### 2. Database Setup
Create the required PostgreSQL user, database, and schema:
~~~bash
# Create database user
sudo -u postgres psql -c "CREATE USER rao008;"

# Create database and grant ownership
sudo -u postgres psql -c "CREATE DATABASE auth_system OWNER rao008;"

# Initialize schema and test data
sudo -u postgres psql -d auth_system -f schema.sql
~~~

### 3. Preparation
Generate SSL certificates and prepare the web directory:
~~~bash
make certs
make html_dir
~~~

### 4. Build
Compile both components:
~~~bash
make all
~~~

## Usage

1. **Start Daemon**:
~~~bash
./auth_daemon
~~~

2. **Start Server**:
~~~bash
./server
~~~

3. **Access**:
Navigate to `https://localhost:8443`.
Default test users: `alice` or `bob` (password: `password123`).

## Security Notes

* **Credentials**: The system uses SHA-256 for password verification. Change default test user passwords in `schema.sql` for production.
* **Socket**: If the server cannot connect to the daemon, check `/tmp/auth_daemon.sock` permissions.
* **SSL**: Certificates are self-signed by default. Browsers will show a security warning.

## Maintenance

* **Stop Services**: Use `pkill auth_daemon` to stop the background process and `Ctrl+C` for the server.
* **Cleanup**: Use `make clean` to remove binaries or `make distclean` to remove certificates.
