CFLAGS=-g -Wall -Wextra -Werror
OBJECTS=lwan.o \
	lwan-trie.o \
	lwan-serve-files.o \
	lwan-hello-world.o \
	int-to-str.o

all: lwan

lwan: $(OBJECTS)
	$(CC) -o lwan $(OBJECTS) -lpthread

clean:
	rm -f $(OBJECTS)

benchmark-prepare: clean all
	pkill -9 lwan || true
	./lwan &

benchmark-finalize:
	pkill -9 lwan

ab-normal:
	ab -n100000 -c10 http://localhost:8080/hello | grep 'Requests per second'

ab-keep-alive:
	ab -k -n100000 -c10 http://localhost:8080/hello | grep 'Requests per second'

benchmark: benchmark-prepare ab-normal benchmark-finalize

benchmark-keep-alive: benchmark-prepare ab-keep-alive benchmark-finalize
