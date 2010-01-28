/* hmipv6_defs.h: Header file with HMIPv6 definitions.  */

/* 
 * File: hmipv6_support.h
 *
 * Modified MIPv6 for use with HMIPv6:
 *
 * Description: Support file for Hierarchal Mobile IPv6 (HMIPv6)
 *              Data structures and macro's for implementation.
 *
 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
 *
 * Terminology:
 *  HA - Home Agent
 *  CN - Corespondent Node
 *  MN - Mobile Node
 *  BU - Binding Update
 *  MAP - Mobility Anchor Point
 */

#ifndef _HMIPV6_DEFS_H_INCL_
#define _HMIPV6_DEFS_H_INCL_

#include <opnet.h>
#include <prg_bin_hash.h>

#define HMIPV6C_MOB_MSG_COUNT 8 

EXTERN_C_BEGIN

/* Define the binding cache table as a binary hash table. */  
typedef PrgT_Bin_Hash_Table hmipv6_bind_cache;

/* Define the binding update list as a binary hash table. */
typedef PrgT_Bin_Hash_Table hmipv6_bu_list;
  
/*********  Enumeration types.  *********/

/* Values used by the status field in an Ack mobility message. */
typedef enum
{
  BU_ACCEPTED,
  ACCEPTED_BUT_PREFIX_DISC_NECCESARY,
  REASON_UNESPECIFIED = 128,
  ADMINISTRATIVELY_PROHIBITED,
  INSUFFCIENT_RESOURCES,
  HOME_REGISTRATION_NOT_SUPPORTED,
  NOT_HOME_SUBNET,
  NOT_HA_FOR_THIS_MN,
  DUP_ADDRESS_DETECTION_FAILED,
  SEQ_NUMBER_OUT_OF_WINDOW,
  EXPIRED_HOME_NONCE_INDEX,
  EXPIRED_CARE_OF_NONCE_INDEX,
  EXPIRED_NONCES,
  REG_TYPE_CHANCE_DISALLOWED
} hmipv6_bind_ack_status;

/* Values in the status field of a error mobility message. */
typedef enum
{
  UNKNOWN_BIND_ADDRESS = 1,
  UNRECOGNIZED_MH_TYPE_VALUE
} hmipv6_bind_err_status;

/* Constants that identify the mobility message types. */
typedef enum 
{
  BIND_REF_REQ = 0,
  HOME_TEST_INIT = 1,
  CARE_OF_TEST_INIT = 2,
  HOME_TEST = 3,
  CARE_OF_TEST = 4,
  BIND_UPDATE = 5,
  BIND_ACK = 6,
  BIND_ERR = 7
} hmipv6_hdr_t;

/* Constants to set the status of a BU list entry. */
typedef enum 
{
  BU_ENTRY_NOT_FOUND         = 0,
  BU_ENTRY_ROUTE_PENDING     = 1,
  BU_ENTRY_REG_PENDING       = 2, 
  BU_ENTRY_BINDING_COMPLETE  = 3,
  BU_ENTRY_UNREG_PENDING     = 4, 
  BU_ENTRY_NO_FUTURE_BINDING = 5
} hmipv6_bu_entry_status;

/* HMIPv6 node types definition.*/
typedef enum 
{
  NONE = 0, /* Not a HMIPv6 node */
  MN   = 1, /* Mobile Node */
  MR   = 2, /* Mobile Router */
  HA   = 3, /* Home Agent */
  CN   = 4, /* Correspondent Node */
  FR   = 5, /* Foreign Router */
  MAP  = 6  /* Mobility Anchor Point */
} hmipv6_node_t;    
  
EXTERN_C_END

#endif /* #ifndef _HMIPV6_SUPPORT_H_INCL_ */
