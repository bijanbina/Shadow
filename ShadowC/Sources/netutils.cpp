#include <math.h>

#include "netutils.h"
#include "utils.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

extern int verbose;

static const char valid_label_bytes[] =
    "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";





