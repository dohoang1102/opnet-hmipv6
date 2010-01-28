/* hmipv6_signaling_sup.h: Header file for HMIPv6 protocol support. */

/****************************************/
/*      Copyright (c) 2004-2008       */
/*      by OPNET Technologies, Inc.     */
/*       (A Delaware Corporation)       */
/*    7255 Woodmont Av., Suite 250      */
/*          Bethesda, MD, U.S.A.        */
/*       All Rights Reserved.           */
/****************************************/

#ifndef _HMIPV6_SIGNALING_SUP_H_INCL_
#define _HMIPV6_SIGNALING_SUP_H_INCL_

#include <opnet.h>
#include <hmipv6_support.h>
#include <ipv6_extension_headers_sup.h>

/* A 128-bit IPv6 address.  */
typedef struct Ipv6T_Address
{
  OpT_uInt32 addr32[4];
} Ipv6T_Address;

EXTERN_C_BEGIN
  
void                      hmipv6_pooled_memory_package_init();
Ipv6T_Mobility_Hdr_Info*  hmipv6_binding_update_msg_create( InetT_Address home_addr, OpT_uInt16 seq, Boolean ack, Boolean home_reg, OpT_uInt16 lifetime );
Ipv6T_Mobility_Hdr_Info*  hmipv6_binding_ack_msg_create( Mipv6T_Bind_Ack_Status_Value status, OpT_uInt16 seq, OpT_uInt16 lifetime );
Ipv6T_Mobility_Hdr_Info*  hmipv6_route_test_msg_create( Mipv6T_Mobity_Hdr_Type msg_type );
Ipv6T_Mobility_Hdr_Info*  hmipv6_binding_error_msg_create( Mipv6T_Bind_Error_Status_Value status, InetT_Address home_address );
Boolean                   hmipv6_dest_addr_is_bound( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
hmipv6_bu_entry*          hmipv6_bind_update_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
hmipv6_bu_entry_status    hmipv6_bind_update_entry_status_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
Mipv6T_Bind_Cache_Entry*  hmipv6_bind_cache_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
Mipv6T_Bind_Cache_Entry*  hmipv6_bind_cache_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
Boolean                   hmipv6_dest_addr_is_binding_cache( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );
void                      hmipv62_packet_tunnel( IpT_Rte_Module_Data* iprmd_ptr, Packet* inner_pkptr, InetT_Address next_addr );
void                      hmipv6_tunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_pptr, InetT_Address src_addr, InetT_Address dest_address );
Boolean                   hmipv6_tunnel_end_point_pkt_process( IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_pptr, IpT_Rte_Ind_Ici_Fields** intf_ici_fdstruct_pptr );
void                      hmipv6_decapsulate_pkt( Packet** orig_ip_pk_ptr );
void                      hmipv6_sup_bind_addr_print_proc( const void* state_ptr, PrgT_List* dump_lptr );
int                       hmipv6_bind_cache_num_entries_get( IpT_Rte_Module_Data* iprmd_ptr );
int                       hmipv6_bind_update_num_entries_get( IpT_Rte_Module_Data* iprmd_ptr );

hmipv6_bu_entry*          hmipv6_bind_update_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address, hmipv6_bu_entry_status status );
hmipv6_bu_entry*          hmipv6_bind_update_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );

Mipv6T_Bind_Cache_Entry*  hmipv6_bind_cache_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address home_addr, InetT_Address co_addr, IpT_Interface_Info *current_ha_iface_info_ptr );
Mipv6T_Bind_Cache_Entry*  hmipv6_bind_cache_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_address );

EXTERN_C_END

#endif /* #ifndef _HMIPV6_SIGNALING_SUP_H_INCL_ */

