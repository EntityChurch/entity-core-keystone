/*
 * IoEntityCodecInit.c — addon init for the EntityCodec addon, following the
 * AddonLoader convention: `DynLib call("Io" .. name .. "Init", context)`.
 * Same shape as containers/io-toolchain/IoSocketInit.c (the S1-proven pattern).
 * Apache-2.0 (keystone S9).
 */

#include "IoState.h"
#include "IoObject.h"

IoObject *IoEntityCodec_proto(void *state);

void IoEntityCodecInit(IoObject *context)
{
	IoState *self = IoObject_state(context);

	IoObject_setSlot_to_(context, SIOSYMBOL("EntityCodec"), IoEntityCodec_proto(self));
}
