/**
 * File: hmipv6_support.h
 *
 * Description: Support file for Hierarchal Mobile IPv6 (HMIPv6)
 *              Data structures and macro's for implementation.
 *
 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
 *
 * Terminology:
 *  HA - Home Agent
 *  CN - Coresponding Node
 *  MN - Mobile Node
 *  BU - Binding Update
 *  MAP - Mobility Anchor Point
 */

#ifndef _HMIPV6_MAP_H_
#define _HMIPV6_MAP_H_

#include <opnet.h>
#include <prg_bin_hash.h>
#include "ip_addr_v4.h"
#include "ipv6_extension_headers_defs.h"
#ifndef HDR_IP_RTE_SUPPORT_H
# include "ip_rte_support.h"
#endif
#include "hmipv6_defs.h"

#define MAP_ADVERTISED   864

EXTERN_C_BEGIN
EXTERN_C_END

#endif /* _HMIPV6_SUPPORT_H_ */
