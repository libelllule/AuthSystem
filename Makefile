CC = gcc
CFLAGS = -Wall -Wextra -I/usr/include/postgresql
LDFLAGS = -lpq -lssl -lcrypto

all: auth_daemon server

database.o: database.c database.h
	$(CC) $(CFLAGS) -c database.c -o database.o

auth_daemon.o: auth_daemon.c database.h
	$(CC) $(CFLAGS) -c auth_daemon.c -o auth_daemon.o

server.o: server.c
	$(CC) $(CFLAGS) -c server.c -o server.o

auth_daemon: auth_daemon.o database.o
	$(CC) auth_daemon.o database.o -o auth_daemon $(LDFLAGS)

server: server.o
	$(CC) server.o -o server $(LDFLAGS)

clean:
	rm -f *.o auth_daemon server
	-rm /tmp/auth_daemon.sock

distclean: clean
	rm -f server.crt server.key

install_deps:
	sudo apt-get update
	sudo apt-get install -y gcc make libpq-dev libssl-dev postgresql postgresql-contrib

certs:
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
	  -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"
	chmod 600 server.key

html_dir:
	mkdir -p html
	-cp -n *.html html/

.PHONY: all clean distclean html_dir certs install_deps
