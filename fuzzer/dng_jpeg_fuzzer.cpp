#include <stddef.h>
#include <stdint.h>

#if __has_feature(address_sanitizer)
#include <sanitizer/asan_interface.h>
#endif

#include "dng_exceptions.h"
#include "dng_host.h"
#include "dng_memory_stream.h"
#include "dng_lossless_jpeg.h"

extern "C" void* __asan_region_is_poisoned(void* data, size_t count);

class FuzzingSpooler: public dng_spooler
{
    void Spool (const void *data, uint32 count) {
#if __has_feature(address_sanitizer)
        if (__asan_region_is_poisoned((void*)data, count)) {
            abort();
        }
#else
        uint8_t sum = 0;
        for (uint32_t i = 0; i < count; i ++) {
            sum += ((uint8_t*)data)[i];
        }

#endif
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  dng_host host;
  dng_memory_stream stream(host.Allocator());
  FuzzingSpooler spooler;

  stream.Put(data, size);

  try {
    stream.SetReadPosition(0);
    DecodeLosslessJPEG(stream, spooler, 0x01, 0x100000, 0);
    stream.SetReadPosition(0);
    DecodeLosslessJPEG(stream, spooler, 0x01, 0x100000, 1);
  } catch (dng_exception &e) {
    // dng_sdk throws C++ exceptions on errors
    // catch them here to prevent libFuzzer from crashing.
  }

  return 0;
}
