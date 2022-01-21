# build an executable named system-services-example from system-services-example.c
# Cross compiler defined in soc_app.mk
# CC=$(CROSS_COMPILE)gcc
CFLAGS = -g -Werror -Wall # -Wpedantic ISO C forbids zero-size array 'keys' [-Werror=pedantic]

.PHONY: clean

all: sel4_test.c
	$(CC) $(CFLAGS) -o sel4-demo sel4_test.c sel4_tty_rpmsg.c

clean:
	$(RM) sel4-demo
