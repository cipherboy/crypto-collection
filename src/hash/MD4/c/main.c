/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the md4 hash algorithm.
**/

#include "md4.h"
#include "stdio.h"

int main() {
	cc_md4 m;
	cc_md4_sum(&m, "Hello World!");
}
