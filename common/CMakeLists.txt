if (NOT USE_HARDWARE_CRC32)
	set(GENERIC_SOURCES
		murmur3.c
	)
endif ()

add_library(lwan-common STATIC
	hash.c
	list.c
	int-to-str.c
	lwan.c
	lwan-cache.c
	lwan-config.c
	lwan-coro.c
	lwan-io-wrappers.c
	lwan-job.c
	lwan-request.c
	lwan-response.c
	lwan-serve-files.c
	lwan-socket.c
	lwan-status.c
	lwan-tables.c
	lwan-template.c
	lwan-thread.c
	lwan-trie.c
	realpathat.c
	strbuf.c
	${GENERIC_SOURCES}
)
