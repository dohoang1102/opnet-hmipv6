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

#ifndef _HMIPV6_SUPPORT_H_
#define _HMIPV6_SUPPORT_H_

#include <opnet.h>
#include <prg_bin_hash.h>
#include "ip_addr_v4.h"
#include "ipv6_extension_headers_defs.h"
#ifndef HDR_IP_RTE_SUPPORT_H
# include "ip_rte_support.h"
#endif
#include "hmipv6_defs.h"

/* HMIPv6 Packet format's */
#define BINDING_UPDATE_PK       "hmipv6_binding_update"
#define BINDING_UPDATE_ACK_PK   "hmipv6_binding_update_ack"
#define HMIPV6_ADVERTISEMENT_PK "hmipv6_advertisement"
#define CARE_OF_ADDRESS_PK      "hmipv6_care_of_address"

EXTERN_C_BEGIN
/********* Binding tables definitions. **********/

typedef InetT_Address address_t;

/* Binding Cache Table used by HA and CN. */
typedef struct 
{
  InetT_Address        co_address;
  Evhandle             lifetime_ev;
  IpT_Interface_Info*  serving_ha_iface_ptr;
} hmipv6_cache_entry;

/* Binding Cache Table used by HA and CN. */
typedef struct
{
  InetT_Address          bind_address;
  Evhandle               lifetime_ev;
  Boolean                home_test_ok;
  Boolean                care_of_test_ok;
  Boolean                home_agent_entry;
  Evhandle               retx_ev;
  double                 retx_time;
  hmipv6_bu_entry_status status;
} hmipv6_bu_entry;


/********* Hierarchal IPv6 Mobility Header messages. *******/
/* This messages are carried by the mobility header. */

/* Binding Update Message. */ 
typedef struct
{
  hmipv6_bind_ack_status status;
  OpT_uInt16             seq;
  /* Time units before the binding MUST be considered expired. One time unit => 4sec. */  
  OpT_uInt16             lifetime;  
} hmipv6_bind_ack_msg;

/* Binding Update (BU) Acknowledgement Message. */
typedef struct 
{
  OpT_uInt16    seq;
  /* Is the mobile request a binding acknowledgement. */
  Boolean       ack; 
  /* Is the mobile requesting HA services to the receiving node. */
  Boolean       home_reg;   
  /* Time units before the binding MUST be considered expired. 1 time unit = 4sec. */ 
  OpT_uInt16    lifetime;   
  InetT_Address home_address;
} hmipv6_bu_msg;

/* Binding Error Message. */
typedef struct
{
  /* The home address contained in the destination header. */
  InetT_Address          home_address;
  hmipv6_bind_err_status status;
} hmipv6_bind_err;

/* Define a union that represents all mobility messages.
 * The messages included are those relevant to the simulation 
 * (e.g. routability test messages not needed). */
typedef union hmipv6_moblty_msg 
{
  hmipv6_bu_msg       bind_update;
  hmipv6_bind_err     bind_error;
  hmipv6_bind_ack_msg bind_ack;
} hmipv6_mobility_msg;

/* Parameters for a Binding Update (BU) */
typedef struct
{
  double     timeout;
  OpT_uInt16 max_attempts;
  OpT_uInt16 lifetime_requested;
} hmipv6_bind_param;

/* Route Test parameters */
typedef struct
{
  double     timeout;
  OpT_uInt16 max_attempts;
} hmipv6_route_test_param;  

/* Shared memory across Mobile Nodes (MN) */
typedef struct
{
  /* Prohandle for ip_dispatch process. */
  Prohandle                 ip_phndl;       
  Prohandle                 pro_hndl;
  hmipv6_node_t             node_type;
  Boolean                   route_optimization_enabled;
  InetT_Address             home_agent_address;
  IpT_Interface_Info*       intf_info_ptr;
  hmipv6_bind_param*        bind_params_ptr;
  hmipv6_route_test_param*  route_test_params_ptr;  

} hmipv6_mn_sharedmem;

typedef struct
{
  InetT_Address cn_address;
} hmipv6_route_opt_evnt;

typedef struct
{
  Ipv6T_Mobility_Hdr_Info *mob_hdr_ptr;
  InetT_Address     src_addr;
  InetT_Address     dest_addr;
} hmipv6_mob_msg_proc_comm;

void    hmipv6_proc_mgr_create( IpT_Rte_Module_Data* module_data_ptr );
Boolean hmipv6_configuration_is_enabled( IpT_Rte_Module_Data* module_data_ptr );
void    hmipv6_sup_mobile_ipv6_packet_process( IpT_Rte_Module_Data* iprmd_ptr,   IpT_Dgram_Fields** pk_fd_pptr, Packet **pkpptr, Boolean packet_from_lower_layer );
void    hmipv6_ctrl_traffic_received_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr );
void    hmipv6_ctrl_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr );
void    hmipv6_tunnel_traffic_received_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr );
void    hmipv6_tunnel_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet** pkptr, double inner_pkt_size );
void    hmipv6_binding_update_list_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr );
void    hmipv6_binding_cache_table_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr );
void    hmipv6_route_optimization_sent_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr, double orig_pkt_size, double new_pkt_size );
void    hmipv6_route_optimization_received_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr, double pkt_size );
 
EXTERN_C_END

#endif /* _HMIPV6_SUPPORT_H_ */
