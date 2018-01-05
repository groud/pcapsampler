CC=gcc
EXTRA= -g -fdiagnostics-color=always

CFLAGS= -std=c11 -Wall -Wextra -pedantic  -D _BSD_SOURCE `pkg-config --cflags glib-2.0`$(EXTRA)

LDFLAGS=-std=c++11 -xc++ -lstdc++ -shared-libgcc -lpcap -lm $(EXTRA)

SRCPATH=src
OBJPATH=.

CSRC=pcapsampler.c

OBJ=$(patsubst %.c, %.o, $(CSRC));

all: pcapsampler

pcapsampler: $(OBJ)
	@$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	rm -rf $(OBJ)

mrproper: clean
	rm -rf aatac
