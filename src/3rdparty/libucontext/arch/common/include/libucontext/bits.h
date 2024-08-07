#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

#ifndef FREESTANDING

#include <ucontext.h>

typedef greg_t libucontext_greg_t;
typedef ucontext_t libucontext_ucontext_t;

#endif

#endif
