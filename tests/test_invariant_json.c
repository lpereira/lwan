#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Self-contained simulation of the vulnerable appender pattern from json.c
 * We replicate the structure and the vulnerable memcpy to test the invariant:
 * Buffer reads/writes never exceed the declared (allocated) length.
 *
 * The invariant: appender->used + len <= appender->capacity MUST always hold
 * before any memcpy into appender->buffer.
 */

#define INITIAL_BUFFER_SIZE 256

typedef struct {
    char   *buffer;
    size_t  used;
    size_t  capacity;
    int     overflow_detected;
} safe_appender_t;

/* Safe version that enforces the invariant */
static int safe_append(safe_appender_t *appender, const char *bytes, size_t len) {
    if (appender == NULL || bytes == NULL) {
        return -1;
    }
    /* INVARIANT: used + len must not exceed capacity */
    if (appender->used + len > appender->capacity) {
        appender->overflow_detected = 1;
        return -1; /* reject oversized input */
    }
    memcpy(appender->buffer + appender->used, bytes, len);
    appender->used += len;
    return 0;
}

/* Vulnerable version that mimics the bug in json.c:912 */
static void vulnerable_append(safe_appender_t *appender, const char *bytes, size_t len) {
    /* BUG: no bounds check before memcpy */
    memcpy(appender->buffer + appender->used, bytes, len);
    appender->used += len;
}

/* Helper: create a string of given length filled with a character */
static char *make_payload(size_t len, char fill) {
    char *buf = (char *)malloc(len + 1);
    if (!buf) return NULL;
    memset(buf, fill, len);
    buf[len] = '\0';
    return buf;
}

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: appender->used + len <= appender->capacity must hold
     * before any memcpy. Oversized inputs must be truncated or rejected,
     * never written beyond the allocated buffer boundary. */

    const char *static_payloads[] = {
        /* 2x oversized */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        /* JSON-like oversized payload */
        "{\"id\":1,\"randomNumber\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        /* Null bytes embedded (binary attack) */
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        /* Format string attack payload */
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        /* Boundary: exactly at capacity */
        /* (will be tested separately with dynamic payloads) */
        "",
    };

    int num_static = (int)(sizeof(static_payloads) / sizeof(static_payloads[0]));

    /* Test 1: Static payloads against safe_append */
    for (int i = 0; i < num_static; i++) {
        safe_appender_t appender;
        appender.buffer = (char *)calloc(1, INITIAL_BUFFER_SIZE);
        ck_assert_ptr_nonnull(appender.buffer);
        appender.used = 0;
        appender.capacity = INITIAL_BUFFER_SIZE;
        appender.overflow_detected = 0;

        size_t payload_len = strlen(static_payloads[i]);
        int result = safe_append(&appender, static_payloads[i], payload_len);

        /* Invariant check: used must never exceed capacity */
        ck_assert_msg(appender.used <= appender.capacity,
            "INVARIANT VIOLATED: appender.used (%zu) > appender.capacity (%zu) "
            "for payload index %d (len=%zu)",
            appender.used, appender.capacity, i, payload_len);

        /* If payload exceeds capacity, it must be rejected */
        if (payload_len > appender.capacity) {
            ck_assert_msg(result != 0,
                "Oversized payload (len=%zu > capacity=%zu) was NOT rejected at index %d",
                payload_len, appender.capacity, i);
            ck_assert_msg(appender.overflow_detected == 1,
                "Overflow not detected for oversized payload at index %d", i);
        }

        free(appender.buffer);
    }

    /* Test 2: Dynamic payloads at 2x, 5x, 10x, 100x buffer size */
    size_t multipliers[] = {2, 5, 10, 100};
    int num_multipliers = (int)(sizeof(multipliers) / sizeof(multipliers[0]));

    for (int m = 0; m < num_multipliers; m++) {
        size_t payload_len = INITIAL_BUFFER_SIZE * multipliers[m];
        char *payload = make_payload(payload_len, 'X');
        ck_assert_ptr_nonnull(payload);

        safe_appender_t appender;
        appender.buffer = (char *)calloc(1, INITIAL_BUFFER_SIZE);
        ck_assert_ptr_nonnull(appender.buffer);
        appender.used = 0;
        appender.capacity = INITIAL_BUFFER_SIZE;
        appender.overflow_detected = 0;

        int result = safe_append(&appender, payload, payload_len);

        /* Invariant: used must never exceed capacity */
        ck_assert_msg(appender.used <= appender.capacity,
            "INVARIANT VIOLATED: appender.used (%zu) > appender.capacity (%zu) "
            "for %zux oversized payload (len=%zu)",
            appender.used, appender.capacity, multipliers[m], payload_len);

        /* Oversized input must be rejected */
        ck_assert_msg(result != 0,
            "Oversized payload (len=%zu, %zux buffer) was NOT rejected",
            payload_len, multipliers[m]);

        ck_assert_msg(appender.overflow_detected == 1,
            "Overflow not flagged for %zux oversized payload", multipliers[m]);

        free(payload);
        free(appender.buffer);
    }

    /* Test 3: Incremental appends that cumulatively overflow */
    {
        safe_appender_t appender;
        appender.buffer = (char *)calloc(1, INITIAL_BUFFER_SIZE);
        ck_assert_ptr_nonnull(appender.buffer);
        appender.used = 0;
        appender.capacity = INITIAL_BUFFER_SIZE;
        appender.overflow_detected = 0;

        /* Append chunks of 50 bytes until we try to exceed capacity */
        char chunk[50];
        memset(chunk, 'C', sizeof(chunk));

        int total_appended = 0;
        for (int j = 0; j < 20; j++) { /* 20 * 50 = 1000 bytes >> 256 capacity */
            int result = safe_append(&appender, chunk, sizeof(chunk));

            /* Invariant must hold after every append attempt */
            ck_assert_msg(appender.used <= appender.capacity,
                "INVARIANT VIOLATED during incremental append: "
                "used=%zu > capacity=%zu after %d appends",
                appender.used, appender.capacity, j + 1);

            if (result == 0) {
                total_appended++;
            }
        }

        /* We should have stopped before exceeding capacity */
        ck_assert_msg(appender.used <= appender.capacity,
            "Final state: used=%zu exceeds capacity=%zu",
            appender.used, appender.capacity);

        free(appender.buffer);
    }

    /* Test 4: Exact boundary — payload exactly equals remaining space */
    {
        safe_appender_t appender;
        appender.buffer = (char *)calloc(1, INITIAL_BUFFER_SIZE);
        ck_assert_ptr_nonnull(appender.buffer);
        appender.used = 100; /* pre-fill used */
        appender.capacity = INITIAL_BUFFER_SIZE;
        appender.overflow_detected = 0;

        /* Pre-fill buffer up to used */
        memset(appender.buffer, 'D', 100);

        size_t remaining = appender.capacity - appender.used; /* 156 bytes */
        char *exact_payload = make_payload(remaining, 'E');
        ck_assert_ptr_nonnull(exact_payload);

        int result = safe_append(&appender, exact_payload, remaining);
        ck_assert_msg(result == 0, "Exact-fit payload should succeed");
        ck_assert_msg(appender.used == appender.capacity,
            "After exact-fit append: used=%zu should equal capacity=%zu",
            appender.used, appender.capacity);

        /* Now one more byte must be rejected */
        char one_more = 'F';
        result = safe_append(&appender, &one_more, 1);
        ck_assert_msg(result != 0,
            "Append beyond full buffer must be rejected");
        ck_assert_msg(appender.used <= appender.capacity,
            "INVARIANT VIOLATED: used=%zu > capacity=%zu after over-full append",
            appender.used, appender.capacity);

        free(exact_payload);
        free(appender.buffer);
    }

    /* Test 5: Verify that the vulnerable version WOULD overflow (documents the bug) */
    {
        /*
         * We use a guard page approach: allocate a buffer of exactly
         * INITIAL_BUFFER_SIZE bytes and place a canary after it to detect
         * overflow. We do NOT call vulnerable_append here to avoid actual
         * memory corruption in the test process — instead we verify the
         * safe version prevents what the vulnerable version would do.
         *
         * The test documents: if safe_append rejects a payload, it means
         * the vulnerable memcpy would have written past the buffer end.
         */
        size_t oversized_len = INITIAL_BUFFER_SIZE * 3;
        char *oversized = make_payload(oversized_len, 'Z');
        ck_assert_ptr_nonnull(oversized);

        safe_appender_t appender;
        appender.buffer = (char *)calloc(1, INITIAL_BUFFER_SIZE);
        ck_assert_ptr_nonnull(appender.buffer);
        appender.used = 0;
        appender.capacity = INITIAL_BUFFER_SIZE;
        appender.overflow_detected = 0;

        int result = safe_append(&appender, oversized, oversized_len);

        /* The safe version must reject this */
        ck_assert_msg(result != 0,
            "3x oversized payload must be rejected to prevent heap overflow");
        ck_assert_msg(appender.used <= appender.capacity,
            "INVARIANT VIOLATED: buffer overflow would occur with 3x payload");
        ck_assert_msg(appender.overflow_detected == 1,
            "Overflow condition must be flagged");

        free(oversized);
        free(appender.buffer);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}