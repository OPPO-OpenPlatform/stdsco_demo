#ifdef __aarch64__
#include "curlbuild-64.h"
#elif __arm__
#include "curlbuild-32.h"
#elif __i386__
#include "curlbuild-32.h"
#elif __x86_64__
#include "curlbuild-64.h"
#else
#error "Unsupported architecture!"
#endif
