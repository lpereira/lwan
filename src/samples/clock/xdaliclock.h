#pragma once

#include <stdint.h>
#include "gifenc.h"

struct xdaliclock;

struct xdaliclock *xdaliclock_new(ge_GIF *gif);
void xdaliclock_free(struct xdaliclock *xdaliclock);

void xdaliclock_update(struct xdaliclock *xdaliclock);
uint32_t xdaliclock_get_frame_time(const struct xdaliclock *xdc);


