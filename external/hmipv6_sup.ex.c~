/* mipv6_sup.ex.c */
/* Support routines for processing of IPv6 mobility headers and	*/
/* used by MIPv6.												*/

/****************************************/
/*      Copyright (c) 2004-2008       */
/*      by OPNET Technologies, Inc.     */
/*       (A Delaware Corporation)       */
/*    7255 Woodmont Av., Suite 250      */
/*          Bethesda, MD, U.S.A.        */
/*       All Rights Reserved.           */
/****************************************/

#include "ip_rte_support.h"
#include "hmipv6_support.h"
#include "hmipv6_signaling_sup.h"

void 
hmipv6_proc_mgr_create( IpT_Rte_Module_Data* mod_data ) {
	/** Creates the Mobile IPv6 manager process. This 	**/
	/** is done if MIPv6 attributes exists in the node	**/
	/** and their configuration indicates that the 		**/
	/** current node is MIPv6 enabled (Mobile Node, 	**/
	/** Home Agent, Correspondent Node with Route 		**/
	/** Optimization support).							***/	
	FIN( hmipv6_proc_mgr_create( IpT_Rte_Module_Data* mod_data ) );

	/* See if the current node has Mobile IPv6 support. */
	if (hmipv6_configuration_is_enabled (mod_data)) {
		/* Allocate memory for the MIPv6 information	*/
		/* that will be shared across the IP module.	*/
		mod_data->mipv6_info_ptr = (IpT_Mipv6_Info *) op_prg_mem_alloc( sizeof(IpT_Mipv6_Info) );
		
		/* Create a mipv6_mgr process for Mobile IPv6 	*/
		/* support on this node.						*/		
		mod_data->mipv6_info_ptr->mipv6_prohandle = op_pro_create("mipv6_mgr", OPC_NIL);
		op_pro_invoke( mod_data->mipv6_info_ptr->mipv6_prohandle, OPC_NIL );
  } else {
		/* Make sure the mipv6_info_ptr is set to NIL.	*/
		mod_data->mipv6_info_ptr = OPC_NIL;				
  }
	FOUT;
}
	
Boolean 
hmipv6_configuration_is_enabled( IpT_Rte_Module_Data* mod_data ) {

	Objid	compound_attr_objid;
	int		node_type;
	int		opt_flag;	
		
	/** This function checks if MIPv6 is supported on the current	**/
	/** node. MIPv6 is considered enable if the MIPv6 attributes 	**/
	/** exits in the current node and:								**/
	/** - This node is set as Mobile Node or,						**/
	/** - This node is set as a Home Agent or,						**/
	/** - This node is set as a Correspondent Node with Route 		**/
	/**    Optimization enabled										**/
	/** Notice that this function is called by  ip_dispatch process	**/
	/** once it is verified that the current node is IPv6 enabled.	**/
	FIN( hmipv6_configuration_is_enabled( IpT_Rte_Module_Data* mod_data ) );

	/* If IPv6 is not supported by this node do not activate MIPv6.	*/
	if (!ip_rte_node_ipv6_active(mod_data))
		FRET( OPC_FALSE );
		
	/* Now check if the MIPv6 attributes exists in this node.		*/
	if (op_ima_obj_attr_exists( mod_data->node_id, "Mobile IPv6 Parameters") ) {
		/* Read the MIPv6 compound attribute.						*/
		op_ima_obj_attr_get_objid( mod_data->node_id, "Mobile IPv6 Parameters", &compound_attr_objid );

		/* There are two different cases: Host and Router.			*/
		if ( !ip_rte_node_is_gateway( mod_data ) ) {
			/* Read the only row of attributes available at a host.	*/
			compound_attr_objid = op_topo_child(compound_attr_objid, OPC_OBJTYPE_GENERIC, 0 );

			/* Get the MIPv6 node type. */
			op_ima_obj_attr_get_int32( compound_attr_objid, "Node Type", &node_type );

			/* Check if this node does not support MIPv6. */	
			if ((hmipv6_node_t) node_type == NONE )
				FRET( OPC_FALSE );

			/* Check if route optimization is supported. */	
			op_ima_obj_attr_get (compound_attr_objid, "Route Optimization", &opt_flag);	

			/* Now if this is correspondent node with no support	*/
			/* for route optimization, it is the same  as not 		*/
			/* supporting MIPv6.									*/
			if (!opt_flag && node_type == CN )
				FRET( OPC_FALSE );
    } else {
			/* If there is at least one row under the Mobile IPv6 	*/
			/* Parameters, this means that this router has been 	*/
			/* configured to support MIPv6 on at least one of its 	*/
			/* interfaces. If no rows are present consoder that 	*/
			/* MIPv6 is not enabled. For this release just Home 	*/
			/* Agent functionality is supported on a router 		*/
			/* interfaces.											*/
			if ( op_topo_child_count( compound_attr_objid, OPC_OBJTYPE_GENERIC ) == 0)
				FRET( OPC_FALSE );
    }
  } else {
		/* If the Mobile IPv6 Paramters compund attribute does not	*/
		/* exists then no MIPv6 support is available.				*/
		/* MIPv6 is not supported in this node. This node may 		*/
		/* just communicate with a Mobile Node as a Correspondent	*/
		/* Node, but without route optimization support.			*/
		/* MIPv6 is not supported.									*/
		FRET( OPC_FALSE );
  }
	
	/* After passing all possible tests this is a MIPv6 capable node. */
	FRET( OPC_TRUE );
}

void
hmipv6_sup_mobile_ipv6_packet_process( IpT_Rte_Module_Data* iprmd_ptr,
	                                      IpT_Dgram_Fields** pk_fd_pptr,
                                        Packet** pkpptr,
                                        Boolean packet_from_lower_layer ) {

	hmipv6_cache_entry*	bind_cache_entry_ptr 		= OPC_NIL;
	hmipv6_bu_entry*	  bind_update_entry_ptr 	= OPC_NIL;
	Boolean						refresh_pkt_fields 			= OPC_FALSE;
	OpT_Packet_Size				orig_pkt_size, new_pkt_size;
	Boolean						route_optimization_send 	= OPC_FALSE;
	InetT_Address				ha_iface_addr;
	
	char						addr_str [INETC_ADDR_STR_LEN];		
	char						addr2_str [INETC_ADDR_STR_LEN];		
	char						str1 [128];
	
	/** This function process IPv6 packets to perform MIPv6 data	**/
	/** plane operations. Different operations are applied based	**/
	/** on the MIPv6 mode type.										**/
	FIN( mipv6_sup_mobile_ipv6_packet_process( IpT_Rte_Module_Data* iprmd_ptr, IpT_Dgram_Fields** pk_fd_pptr, Packet **pkpptr, Boolean packet_from_lower_layer));
	
	/* Print debug trace messages. */
	if ( op_prg_odb_ltrace_active( "mipv6_rte" ) ) {
		/* Converting the IPv6 address into a string. */
		inet_address_print( addr_str, (*pk_fd_pptr)->src_addr );
	
		/* Converting the IPv6 address into a string. */
		inet_address_print( addr2_str, (*pk_fd_pptr)->dest_addr );
	
		sprintf( str1, "Source[%s], Destination [%s]", addr_str, addr2_str );
		op_prg_odb_print_major( "MIPv6. Processing IPv6 packet.", str1, OPC_NIL );
  }
		
	/* Process the packet according to the MIPv6 node type.			*/
	if ( ip_rte_node_is_mipv6_home_agent( iprmd_ptr ) ) {
		/* A Home Agent must intercept the packet if its 			*/
		/* destination is included in the Binding Cache Table. This	*/
		/* means that the destination is a Mobile Node that has 	*/
		/* registered with the HA. The HA must tunnel theose 		*/
		/* packets to the current address (Care-of Address) of the 	*/
		/* Mobile Node.												*/

		/*  This is a home agent. Check its binding cache.			*/
		if ( (bind_cache_entry_ptr = (hmipv6_bind_cache_entry *) mipv6_bind_cache_entry_info_get(iprmd_ptr, (*pk_fd_pptr)->dest_addr)) != OPC_NIL) {
			/* Obtain the IP address of the interface serving as 	*/
			/* Home Agent for the current Binding Cache entry.		*/
			/*  Get the first Ipv6 global address in the current 	*/
			/* interface.											*/
			ha_iface_addr = ip_rte_intf_ith_gbl_ipv6_addr_get_fast( 
          bind_cache_entry_ptr->serving_ha_iface_ptr , 0 );
			
			/* The destination is a Mobile Node registered in this	*/
			/* Home Agent, tunnel the packet to the Mobile Node'S	*/
			/* Care-of Address (CoA).								*/
			mipv6_tunnel_pkt( iprmd_ptr, pkpptr, ha_iface_addr,
                        bind_cache_entry_ptr->co_address );
				
			/* Refresh the IP packet fields. */
			op_pk_nfd_access( *pkpptr, "fields", pk_fd_pptr );
    }
		
		/* The packet "carrying" the original packet, will be 		*/
		/* returned to the caller so it can be forwarded to the 	*/
		/* Mobile's new location.									*/
  } else if ( ip_rte_node_is_mipv6_mobile_node( iprmd_ptr ) ) {
		/* This is a Mobile Node. Check if route optimization has 	*/
		/* been established with the destination. If not, perform 	*/
		/* reverse tunneling to	the Home Agent.						*/

		/* Make sure that:											*/
		/* - The destination does not corresponds to the Home Agent */
		/*   address serving this Mobile.							*/	
		/* - The destination does not corresponds to the IP address	*/
		/*   address of this Mobile.								*/	
		/* - The Mobile is currently "out of home".					*/
		/* - The Mobile is using its CoA as source address of this 	*/
		/*   packet.												*/ 
		if (!inet_address_equal(iprmd_ptr->mipv6_info_ptr->home_agent_addr, (*pk_fd_pptr)->dest_addr) &&
			!inet_address_equal(iprmd_ptr->mipv6_info_ptr->home_addr, 		(*pk_fd_pptr)->dest_addr) &&
			((!iprmd_ptr->mipv6_info_ptr->out_of_home) ||
			 (!inet_address_equal(*(iprmd_ptr->mipv6_info_ptr->care_of_addr_ptr), (*pk_fd_pptr)->src_addr))) ) {
			/* Obtain the size of the packet about to be sent. 
       * This	is used for traffic statistics.	*/
			orig_pkt_size = op_pk_total_size_get (*pkpptr);
				
			/* ToDo. Check if the packet is arriving from lower	or higher layer. */
				
			/* Check if the destination is a correspondent node	to 	*/
			/* this mobile.	Check the binding update list.			*/
			if ( iprmd_ptr->mipv6_info_ptr->out_of_home && 
				   ( (*pk_fd_pptr)->protocol != IpC_Procotol_Mobility_Ext_Hdr ) && 
           (bind_update_entry_ptr = (hmipv6_bu_entry *)mipv6_bind_update_entry_info_get( iprmd_ptr, (*pk_fd_pptr)->dest_addr ) ) != OPC_NIL ) {
				/* The MN has an entry in its binding update list	to the destination.	*/

				/* Verify that the binding with the CN has been	completed. */
				if ( bind_update_entry_ptr->status == BU_ENTRY_BINDING_COMPLETE ) {
					/* Check if the source address of this packet is already set. */
					if ( !inet_address_valid( (*pk_fd_pptr)->src_addr ) ) {
						/* Set the source address of the "encapsulated packet"
             * to the first IPv6 inteface address. */
						(*pk_fd_pptr)->src_addr = inet_address_copy (iprmd_ptr->mipv6_info_ptr->home_addr);
						(*pk_fd_pptr)->src_internal_addr = inet_rtab_addr_convert ((*pk_fd_pptr)->src_addr);
          }					
					
					/* Insert a destination extension header to 	*/
					/* carry the original source address of this 	*/
					/* packet (it will be replaced by this MN 		*/
					/* Care-of address).							*/
					ipv6_destination_hdr_insert( 
              pkpptr, pk_fd_pptr, *(iprmd_ptr->mipv6_info_ptr->care_of_addr_ptr) ); 
					
					/* Route optimization will be performed on this	packet.	*/
					route_optimization_send = OPC_TRUE;					
					
					/* Indicate that the packet fields container must	be refreshed. */
					refresh_pkt_fields = OPC_TRUE;
	
					/* Refresh the IP packet fields. */
					op_pk_nfd_access (*pkpptr, "fields", pk_fd_pptr);
        } else {
					/* If the binding update list entry is not		*/
					/* complete, make sure the entry pointer is set	*/
					/* to OPC_NIL, this is to allow a potential		*/
					/* reverse tunnel to the HA.					*/
					bind_update_entry_ptr = OPC_NIL;
        }
      }
				
			/* Check if this mobile node is also a correspondent node to the destination.	*/
			if (((*pk_fd_pptr)->protocol != IpC_Procotol_Mobility_Ext_Hdr) && (bind_cache_entry_ptr = (hmipv6_bind_cache_entry *) mipv6_bind_cache_entry_info_get (iprmd_ptr, (*pk_fd_pptr)->dest_addr)) != OPC_NIL) {

				/* This node (MN/CN) has binding cache entry to		*/
				/* the destination insert an IPv6 routing extension	header. */

				/* Indicate that the new destination address is the	*/
				/* the destination MN CoA (contained in the Binding	Cache table). */		
				ipv6_routing_hdr_insert( pkpptr, pk_fd_pptr, bind_cache_entry_ptr->co_address );
				route_optimization_send = OPC_TRUE;
				
				/* Indicate that the packet fields container must	be refreshed. */
				refresh_pkt_fields = OPC_TRUE;

				/* Refresh the IP packet fields. */
				op_pk_nfd_access( *pkpptr, "fields", pk_fd_pptr );
      }
			
			/* If any extension header was added, route 			*/
			/* optimization	is being used, write the corresponding	*/
			/* statistics.											*/
			if ( route_optimization_send ) {
				/* Obtain the size of the packet after inserting the*/
				/* extension headers. */
				new_pkt_size = op_pk_total_size_get( *pkpptr );
				
				/* Update the route optimization traffic statistics. */
				mipv6_route_optimization_sent_traffic_stat_update( 
            iprmd_ptr, (double) orig_pkt_size, (double) new_pkt_size );
      }

			/* When packet comes from higher layer:					*/
			/* - Tunnel all packets with no Binding Cache or	 	*/
			/*   Binding Update List entries via HA (the entry 		*/
			/*   pointers are OPC NIL).				*/
			/* - Make sure the packet has a source addresss set		*/
			/*   in the header fields.								*/ 
			if ( iprmd_ptr->mipv6_info_ptr->out_of_home &&
           packet_from_lower_layer == OPC_FALSE && 
				    ( (bind_update_entry_ptr == OPC_NIL && bind_cache_entry_ptr == OPC_NIL) ||
            (*pk_fd_pptr)->protocol == IpC_Procotol_Mobility_Ext_Hdr) ) {

				/* No entry were found either on the binding update	*/
				/* list or in the binding cache. Perform reverse	*/
				/* tunneling to the Home Agent.	If the source 		*/
				/* address is not set, set it here.					*/
				
				/* Check if the source address is set as the 		*/
				/* Care-of address and the next_header value 		*/
				/* indicates this is a mobility message.			*/
				/* If that is the case this packet cannot be 		*/
				/* tunneled.										*/
				if ( !( inet_address_valid( (*pk_fd_pptr)->src_addr ) && 
					inet_address_equal( (*pk_fd_pptr)->src_addr, *(iprmd_ptr->mipv6_info_ptr->care_of_addr_ptr) ) &&
					(*pk_fd_pptr)->protocol == IpC_Procotol_Mobility_Ext_Hdr) ) {
					/* Check if the source address of this packet is already set.	*/
					if (!inet_address_valid ((*pk_fd_pptr)->src_addr)) {
						/* Set the addres to the "encapsulated 		*/
						/* packet" to the first IPv6 inteface address. */
						(*pk_fd_pptr)->src_addr = inet_address_copy (iprmd_ptr->mipv6_info_ptr->home_addr);
						(*pk_fd_pptr)->src_internal_addr = inet_rtab_addr_convert ((*pk_fd_pptr)->src_addr);

          } else if ( (*pk_fd_pptr)->src_internal_addr == IPC_FAST_ADDR_INVALID ) {
						/* Set the internal address if it has not been set. */
						(*pk_fd_pptr)->src_internal_addr = inet_rtab_addr_convert ((*pk_fd_pptr)->src_addr);
          }
					
					/* Set te internal destination address if the 	*/
					/* inet address is already set.					*/
					if ( inet_address_valid( (*pk_fd_pptr)->dest_addr ) ) {
						(*pk_fd_pptr)->dest_internal_addr = inet_rtab_addr_convert ((*pk_fd_pptr)->dest_addr);
          }

					/* Tunnel the packet to the HA. */		
					mipv6_tunnel_pkt( iprmd_ptr, pkpptr, (*pk_fd_pptr)->src_addr,
                            iprmd_ptr->mipv6_info_ptr->home_agent_addr );
			
					/* Indicate that the packet fields container must be refreshed. */
					refresh_pkt_fields = OPC_TRUE;

					/* Check if the packet fields contents has been modified. */
					if (refresh_pkt_fields == OPC_TRUE) {
						/* Refresh the IP packet fields. */
						op_pk_nfd_access( *pkpptr, "fields", pk_fd_pptr );	
          }
        }
      }
    }
  } else if ( ip_rte_node_is_mipv6_correspondent_node( iprmd_ptr ) ) {
		/* This is Correspondent Node. Check if route optimization	*/
		/* is enabled and if there is an entry in its Binding Cache	*/
		/* Table to the destination.								*/
		
		/* Print debug trace messages. */
		if ( op_prg_odb_ltrace_active( "mipv6_cn" ) ) {
			/* Converting the IPv6 address into a string.	*/
			inet_address_print( addr_str, (*pk_fd_pptr)->src_addr );
			/* Converting the IPv6 address into a string.	*/
			inet_address_print( addr2_str, (*pk_fd_pptr)->dest_addr );
			sprintf( str1, "Source[%s], Destination [%s]", addr_str, addr2_str );
			op_prg_odb_print_major( 
          "MIPv6 CN: Search for destination in Binding Cache.", str1, OPC_NIL );
    }
	
		/* Check the binding cache table.	*/
		if ( ( (*pk_fd_pptr)->protocol != IpC_Procotol_Mobility_Ext_Hdr ) && 
        (bind_cache_entry_ptr = (hmipv6_bind_cache_entry *) mipv6_bind_cache_entry_info_get(iprmd_ptr, (*pk_fd_pptr)->dest_addr)) != OPC_NIL) {
			/* Obtain the size of the packet about to be sent. */
			orig_pkt_size = op_pk_total_size_get( *pkpptr );
			/* This node (MN or CN) has binding cache entry to */
			/* the destination insert an IPv6 routing extension	header. */
			/* Indicate that the new destination address is the	*/
			/* the destination MN CoA (contained in the Binding	Cache table). */		
			ipv6_routing_hdr_insert( pkpptr, pk_fd_pptr, bind_cache_entry_ptr->co_address );
			
			/* Obtain the size of the packetafter inserting the	extension headers. */
			new_pkt_size = op_pk_total_size_get( *pkpptr );

			/* Update the route optimization traffic statistics.	*/
			hmipv6_route_optimization_sent_traffic_stat_update( 
          iprmd_ptr, (double) orig_pkt_size, (double) new_pkt_size );
			/* Refresh the IP packet fields. */
			op_pk_nfd_access( *pkpptr, "fields", pk_fd_pptr );
    }
  }
	FOUT;
}

void
hmipv6_ctrl_traffic_received_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr ) {

	OpT_Packet_Size pkt_size;
	
	/** This function writes the statistic values for	**/
	/** the Mobile IPv6 control traffic received.		**/
	FIN( hmipv6_ctrl_traffic_sent_stat_update(IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr));

	/* Get the size of the received packet.	*/		
	pkt_size = op_pk_total_size_get(pkptr);
	
	/* Write local statistics. */
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_rcvd_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_rcvd_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_rcvd_bits_shndl, 0 );

	/* Write global statistics. */	
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_rcvd_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_rcvd_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_rcvd_bits_shndl, 0 );

	FOUT;
}

void
hmipv6_ctrl_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr ) {

	OpT_Packet_Size pkt_size;
	
	/** This function writes the statistic values for	**/
	/** the Mobile IPv6 control traffic sent.			**/
	FIN( hmipv6_ctrl_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr ) );

	/* Get the size of the received packet.	*/
  pkt_size = op_pk_total_size_get( pkptr );
	
	/* Write local statistics. */
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_sent_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_ctrl_traffic_sent_bits_shndl, 0 );

	/* Write global statistics.	*/	
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_sent_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_ctrl_traffic_sent_bits_shndl, 0 );

	FOUT;
}

void
hmipv6_tunnel_traffic_received_stat_update( IpT_Rte_Module_Data* iprmd_ptr,
                                            Packet* pkptr ) {

	double tunnel_delay;
	OpT_Packet_Size pkt_size;
	
	/** This function writes the statistic values for	**/
	/** the Mobile IPv6 tunneled traffic received.		**/
	FIN( hmipv6_tunnel_traffic_received_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet* pkptr) );

	/* Get the size of the received packet.	*/		
	pkt_size = op_pk_total_size_get( pkptr );
	
	/* Compute the the tunnel delay. */
	tunnel_delay = op_sim_time() - op_pk_stamp_time_get( pkptr );
	
	/* Write local statistics. */
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_rcvd_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_rcvd_bits_shndl, (double) pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_rcvd_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_delay_shndl, tunnel_delay );
	
	/* Write global statistics. */	
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_rcvd_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_rcvd_bits_shndl, (double) pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_rcvd_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_delay_shndl, tunnel_delay );

	FOUT;
}
	
/** 
 * This function writes the statistic values for
 * the Mobile IPv6 tunneled traffic sent.
 * @param iprmd_ptr -
 * @param pkptr -
 * @param inner_pkt_size -
 */
void
hmipv6_tunnel_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr,
                                        Packet** pkptr,
                                        double inner_pkt_size ) {

	double pkt_size;
	double overhead_ratio;

	FIN( hmipv6_tunnel_traffic_sent_stat_update( IpT_Rte_Module_Data* iprmd_ptr, Packet** pkptr, double inner_pkt_size) );

	/* Get the size of the received packet. */		
	pkt_size = (double) op_pk_total_size_get( *pkptr );
	
	/* Compute the overhead ratio. */
	overhead_ratio = ( (pkt_size / inner_pkt_size) - 1 );

	/* Write local statistics. */
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_sent_bits_shndl,  pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_sent_bits_shndl, 0 );

	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_overhead_bits_shndl, pkt_size - inner_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_overhead_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_tunnel_traffic_overhead_ratio_shndl, overhead_ratio );

	/* Write global statistics. */	
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_sent_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_sent_bits_shndl, 0 );

	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_overhead_bits_shndl, pkt_size - inner_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_overhead_bits_shndl, 0 );	
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_tunnel_traffic_overhead_ratio_shndl, overhead_ratio );

	/* Stamp the simulation time on the packet so the	*/
	/* tunnel delay can be computed at the end point of this tunnel. */
	op_pk_stamp( *pkptr );
	
	FOUT;
}

/**
 * Update the value for the statistic that represents the	
 * number of entries in the binding update list.
 *
 * @param iprmd_ptr - 
 */
void
hmipv6_binding_update_list_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr ) {

	int	table_size;
	
	FIN( hmipv6_binding_update_table_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr) );
	
	/* Get the number of entries in the binding update list in	*/
	/* the current node.										*/
	table_size = hmipv6_bind_update_num_entries_get( iprmd_ptr );

	/* Write the statistic value. */
	op_stat_write( iprmd_ptr->mipv6_info_ptr->binding_update_list_size_shndl, table_size );
	
	FOUT;
}

/**
 * Update the value for the statistic that represents the	
 * number of entries in the binding cache table.
 *
 * @param iprmd_ptr - 
 */
void
hmipv6_binding_cache_table_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr ) {

	int	table_size;
	
	FIN( hmipv6_binding_cache_table_size_stat_update( IpT_Rte_Module_Data* iprmd_ptr ) );
	
	/* Get the number of entries in the binding update list in the current node. */
	table_size = hmipv6_bind_cache_num_entries_get( iprmd_ptr );

	/* Write the statistic value.	*/
	op_stat_write( iprmd_ptr->mipv6_info_ptr->binding_cache_table_size_shndl, table_size );
	
	FOUT;
}

/**
 * Write the corresponding statistics for the traffic that is sent 
 * using Route Optimization.
 *
 * @param iprmd_ptr - 
 * @param orig_pkt_size -
 * @param new_pkt_size - 
 */
void
hmipv6_route_optimization_sent_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr,
                                                    double orig_pkt_size,
                                                    double new_pkt_size ) {
	double overhead_ratio;
	
	FIN( hmipv6_route_optimization_sent_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr, double orig_pkt_size, double new_pkt_size));
	
	/* Compute the overhead ratio due to route optimization.	*/
	overhead_ratio = (double) (((double) new_pkt_size / (double) orig_pkt_size) - 1);

	/* Write the local statistics. */				
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_sent_bits_shndl, new_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_sent_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_overhead_bits_shndl, new_pkt_size - orig_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_overhead_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_overhead_ratio_shndl, overhead_ratio );

	/* Write the global statistics. */				
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_sent_bits_shndl, new_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_sent_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_sent_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_sent_pkts_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_overhead_bits_shndl,  new_pkt_size - orig_pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_overhead_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_overhead_ratio_shndl, overhead_ratio );

	FOUT;
}

/**
 * Writes the corresponding statistics for the traffic
 * that is received using Route Optimization.	
 * @param iprmd_ptr -
 * @param pkt_size - 
 */
void
hmipv6_route_optimization_received_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr, double pkt_size ) {

	FIN( hmipv6_route_optimization_received_traffic_stat_update( IpT_Rte_Module_Data* iprmd_ptr, double pkt_size ) );
	
	/* Write the local statistics. */				
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_rcvd_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_rcvd_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->local_optimization_traffic_rcvd_pkts_shndl, 0 );
	
	/* Write the global statistics. */				
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_rcvd_bits_shndl, pkt_size );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_rcvd_bits_shndl, 0 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_rcvd_pkts_shndl, 1 );
	op_stat_write( iprmd_ptr->mipv6_info_ptr->global_optimization_traffic_rcvd_pkts_shndl, 0 );
	
	FOUT;
}
