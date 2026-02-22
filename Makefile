BCC = ./bcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.obj)

all: $(OBJS)

src/%.obj: src/%.c
	$(BCC) -c -O1 -o$@ $<

clean:
	rm -f $(OBJS)

.PHONY: all clean
