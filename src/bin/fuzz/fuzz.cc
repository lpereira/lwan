#include <lwan.h>

extern "C" int fuzz_parse_http_request(const uint8_t *, size_t);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_parse_http_request(data, size);
}
