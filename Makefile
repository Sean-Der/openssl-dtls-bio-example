all:
	cc `pkg-config openssl --libs --cflags` -g -o server server.c
	cc `pkg-config openssl --libs --cflags` -g -o client client.c
