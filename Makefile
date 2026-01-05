CC := gcc
CFLAGS := -Wall -Wextra -O2 -D_GNU_SOURCE
LDLIBS := -lssl -lcrypto

.PHONY: all clean

all: edge_client

edge_client: edge_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f edge_client *.o
