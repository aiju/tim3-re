BCC = ./bcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.obj)

all: $(OBJS)

src/%.obj: src/%.c
	$(BCC) -c -Od -k -o$@ $<

clean:
	rm -f $(OBJS)

.PHONY: all clean
