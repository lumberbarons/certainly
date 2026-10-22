/* Minimal stand-in for the Universal Interfaces headers so src/certainly.c
 * can be built and driven on the host. Only what the library names. */
#ifndef FAKE_OPENTRANSPORT_H
#define FAKE_OPENTRANSPORT_H

#include <stdint.h>
#include <stdbool.h>

typedef int32_t  OSStatus;
typedef int32_t  OTResult;
typedef void    *EndpointRef;
typedef void    *InetSvcRef;
typedef uint32_t InetHost;
typedef struct { InetHost addrs[1]; } InetHostInfo;

#define noErr 0

#endif
