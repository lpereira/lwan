CFLAGS=-g -Wall -Wextra
OBJECTS=lwan.o

all: lwan

lwan: $(OBJECTS)
	$(CC) -o lwan $(OBJECTS) -lpthread

clean:
	rm -f $(OBJECTS)