CFLAGS=-g -Wall -Wextra
OBJECTS=lwan.o lwan-serve-files.o lwan-hello-world.o

all: lwan

lwan: $(OBJECTS)
	$(CC) -o lwan $(OBJECTS) -lpthread

clean:
	rm -f $(OBJECTS)