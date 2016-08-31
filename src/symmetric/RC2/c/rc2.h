/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the RC2 encryption algorithm. See docs for the
 * specification.
*/

#pragma once
#ifndef CC_RC2_H
#define CC_RC2_H

#include "stdint.h"
#include "stdlib.h"

struct rc2 {
    uint16_t K[64];
};

#endif
