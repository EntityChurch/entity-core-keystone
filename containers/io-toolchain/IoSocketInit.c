/*
 * IoSocketInit.c — hand-written addon init for the IoLanguage Socket addon
 * (archived repo IoLanguage/Socket @ e348c23f1916c80e1344fc6895a1df67b0263429).
 *
 * The frozen native Io tree (2026.04.20-native-final) ships no generated
 * per-addon init files and `eerie` does not bootstrap from it; this file is
 * the ~30-line generated-style init the AddonLoader convention expects:
 * `DynLib clone setPath(dllPath) open call("Io" .. name .. "Init", context)`
 * (libs/iovm/io/AddonLoader.io). It registers every C proto the addon's
 * io/ layer references, in dependency order (EventManager first — the
 * libevent loop the Event/Socket protos wait on).
 *
 * Proven at S1 (2026-07-15, research/evaluations/oz-io-viability.md §S1).
 * Apache-2.0 (keystone S9).
 */

#include "IoState.h"
#include "IoObject.h"

IoObject *IoEventManager_proto(void *state);
IoObject *IoEvent_proto(void *state);
IoObject *IoSocket_proto(void *state);
IoObject *IoIPAddress_proto(void *state);
IoObject *IoDNS_proto(void *state);
IoObject *IoEvConnection_proto(void *state);
IoObject *IoEvHttpServer_proto(void *state);
IoObject *IoEvOutRequest_proto(void *state);
IoObject *IoEvOutResponse_proto(void *state);
IoObject *IoUnixPath_proto(void *state);

void IoSocketInit(IoObject *context)
{
	IoState *self = IoObject_state(context);

	IoObject_setSlot_to_(context, SIOSYMBOL("EventManager"), IoEventManager_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("Event"), IoEvent_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("Socket"), IoSocket_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("IPAddress"), IoIPAddress_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("DNS"), IoDNS_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("EvConnection"), IoEvConnection_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("EvHttpServer"), IoEvHttpServer_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("EvOutRequest"), IoEvOutRequest_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("EvOutResponse"), IoEvOutResponse_proto(self));
	IoObject_setSlot_to_(context, SIOSYMBOL("UnixPath"), IoUnixPath_proto(self));
}
