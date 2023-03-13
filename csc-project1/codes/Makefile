CC = gcc
CFLAGS = -std=gnu11 -Wall -I include
DFLAG = -g


HIJACK = ipsec_hijack

DEPS = \
	src/dev.c             \
	src/net.c             \
	src/esp.c             \
	src/hmac.c            \
	src/transport.c       \
	src/replay.c          \
	src/sha1.c

all: $(HIJACK)

$(HIJACK): src/main.c $(DEPS)
	$(CC) $^ -o $@ $(CFLAGS) $(DFLAG)

clean:
	rm -f $(HIJACK)
