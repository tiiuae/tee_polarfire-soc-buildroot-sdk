# build an executable named system-services-example from system-services-example.c
# Cross compiler defined in soc_app.mk
# CC=$(CROSS_COMPILE)gcc
CFLAGS = -g -Wall -Wpedantic

.PHONY: clean

all: sel4_test.c 
	$(CC) -o sel4-demo sel4_test.c

clean: 
	$(RM) sel4-demo
