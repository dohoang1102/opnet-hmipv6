/* Process model C form file: ip_arp_v4_2.pr.c */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char ip_arp_v4_2_pr_c [] = "MIL_3_Tfile_Hdr_ 145A 30A op_runsim 7 4B99380D 4B99380D 1 planet12 Student 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                       ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <nato.h>
#include <oms_pr.h>
#include <oms_tan.h>
#include <ip_addr_v4.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ip_dgram_sup.h>
#include <ip_sim_attr_cache.h>
#include <ip_notif_log_support.h>
#include <ip_support.h>
#include <oms_vlan_support.h>
#include <hsrp.h>
#include <ip_arp.h>
#include <ip_grouping.h>

/*	Define codes for different values for the state	*/
/*	field of an entry in the ARP cache.				*/
typedef enum
	{
	ArpC_Entry_Free = 10,
	ArpC_Entry_Pending,
	ArpC_Entry_Resolved,
	ArpC_Entry_Permanent
	} ArpT_Entry_Status;

typedef enum
	{
	ARPC_STATE_UPDATE_IGNORE = -1,
	ARPC_PHYS_ADDR_UPDATE_IGNORE = -2,
	ARPC_AGE_UPDATE_IGNORE = -3,
	ARPC_ATTEMPTS_UPDATE_IGNORE = -4,
	ARPC_ATTEMPTS_UPDATE = -5,
	ARPC_SUBINTF_INDEX_IGNORE = -6
	} ArpT_Entry_Update;

/*	Define macro which represents when the update  	*/
/*	for a particular field in a given arp entry is	*/
/*	ignored.										*/
#define		ARPC_IP_ADDR_UPDATE_IGNORE 	IpI_Default_Addr				
#define		ARPC_QUEUE_UPDATE_IGNORE	OPC_NIL	

/*	Define macro for intializing the physical 		*/
/*	address field in the ARP entry.					*/
#define		ARPC_PHYS_ADDR_UNSET		IPC_PHYS_ADDR_INVALID

/* 	Identification constant for IP protocol within 	*/
/*	Ethernet frames.								*/
#define		ARPC_BROADCAST_ADDR			-1
#define 	ADDR_INDEX_INVALID			-1

/*	Data structure to contain information about an	*/
/*	entry in the ARP cache.							*/
typedef struct
	{
	ArpT_Entry_Status	state;			/*	status of this entry					*/
	IpT_Address			ip_addr;		/*	IP address for the next hop				*/
	OpT_Int64			phys_addr;		/*	physical layer address for the next hop	*/
	int					age;			/*	age of this entry						*/
	int					num_attempts;	/*	number of times an ARP request has been	*/
										/*	sent for this entry						*/
	List*				queue;			/*	queue of packets for this entry			*/				
	int					protocol_type;	/*	protocol type							*/
	int					hardware_type;	/*	physical layer type						*/
	} IpT_Arp_Entry;

/*  Data stucture defining the entities in the		*/
/*  queue of an ARP cache entry. Each entity		*/
/*  contains the queued packet itself and any other	*/
/*  information about reception or transmission of	*/
/*  the packet.										*/
typedef struct
	{
	Packet*				queued_pkptr;	/*  queued packet							*/
	int					subintf_index;	/*	index of the subinterface from where	*/
										/*  the packet arrived						*/
	} IpT_Arp_Queue_Entity;

/*  Data structure to contain information about an	*/
/*  entry in the tables used for mapping between	*/
/*  subinterfaces of served IP interface and VLANs	*/
/*  supported by these subinterfaces.				*/
typedef struct
	{
	int					subintf_index;	/*  index of the subinterface in the 		*/
										/*  subinterface table						*/
	int					vid;			/*  VLAN to which the subinterface belongs	*/
	} ArpT_Vlan_Table_Entry;

/***** State transition macros *****/

/*	Define a transition condition corresponding 	*/
/*	to the IP datagram arrival.						*/
#define IP_ARRIVAL		(intrpt_type == OPC_INTRPT_STRM && intrpt_strm == instrm_from_ip_rte)

/*	Define a transition condition corresponding 	*/
/*	to a packet arrival from the data link layer.	*/
#define DLL_ARRIVAL		(intrpt_type == OPC_INTRPT_STRM && intrpt_strm == instrm_from_mac)

/* Condition to capture packets arriving on unknown */
/* streams or when streams to IP/MAC have not been	*/
/* discovered.										*/
#define UNKNOWN_PACKET	(intrpt_type == OPC_INTRPT_STRM && (intrpt_strm != instrm_from_ip_rte) && (intrpt_strm != instrm_from_mac))
#define DROP_PACKET		(op_pk_destroy (op_pk_get (intrpt_strm)))

/*	Define a transition condition corresponding 	*/
/*	to failure or recovery of the surrounding node,	*/
/*  received as a remote interrupt from ip_observer	*/
/*  process.										*/
#define	NODE_FAILREC	(intrpt_type == OPC_INTRPT_REMOTE)

/*	Define a transition condition corresponding 	*/
/*	to an expiration of the ARP timer.				*/
#define TIMER_EXP					intrpt_type == OPC_INTRPT_SELF
#define	SELF_NOTIF		 			intrpt_type == OPC_INTRPT_SELF

#define IP_PACKET_HANDLE			(arp_packet_from_ip_handle (intrpt_strm))
#define MAC_PACKET_HANDLE			(arp_packet_from_mac_handle (intrpt_strm))
#define ARP_TIMER_HANDLE			(arp_timer_expiry_handle ())
#define	IPv6_ND_INVOKE				(op_pro_invoke (ipv6_nd_prohandle, OPC_NIL))

/***** Macros used in statement conditions *****/

/*  Define macro for checking whether the served	*/
/*  IP physical interface has subinterfaces			*/
/*	configured.										*/
#define	SUBINTERFACES_CONFIGURED	(subintf_index_to_vlan_table != OPC_NIL)		

/*	Define constants for debugging/ltrace information*/
#define ARPC_LTRACE_DATA_ACTIVE		(op_prg_odb_ltrace_active ("arp"))
#define ARPC_LTRACE_TIMER_ACTIVE	(op_prg_odb_ltrace_active ("arp_timer"))

/* Default value used to determine whether ARP Sim	*/
/* Efficiency mode is used.							*/
#define	ARP_SIM_EFF_USED		"Enabled"

/***** Function Prototypes *****/

static void				arp_init (void);
static Compcode			arp_cache_entry_find (IpT_Address dest_ip_addr, int* index_ptr);
static int				arp_cache_entry_create (void);
static IpT_Arp_Entry*	arp_cache_entry_alloc (void);
static void				arp_cache_entry_init (IpT_Arp_Entry* temp_entry_ptr);
static Compcode			arp_cache_oldest_resolved_entry (int* oldest_entry_index);
static Compcode			arp_cache_oldest_pending_entry (int* pending_entry_index);
static void				arp_cache_entry_delete (int tbl_index);
static void				arp_cache_entry_update (int index, int state, IpT_Address ip_address, OpT_Int64 phys_addr, int age, 
							int num_attempts, Packet* pkptr, int subintf_index);
static void				arp_cache_entry_dealloc(IpT_Arp_Entry* entry_ptr);
static void				arp_request_bcast (IpT_Address dest_ip_addr, int subintf_index);
static void				arp_packet_send (Boolean is_arp_packet, Packet* pkptr, OpT_Int64 dest_phys_addr, int subintf_index, int strm_index);
static void				arp_response_ucast (Packet* pkptr, OpT_Int64 src_phys_address, 
							IpT_Address src_ip_address, IpT_Address dest_ip_address, int subintf_index, OpT_Int64 virtual_mac_addr);
static void				arp_enq_pkt_send (int index);
static void				arp_cache_entry_print (IpT_Arp_Entry* tbl_ptr);
static void				arp_cache_print (void);
static void				arp_entry_status_index_to_string_convert (int class_index, char* class_string);
static void				arp_entry_phys_addr_to_string_convert (int class_index, char* class_string);
static void				arp_vlan_tables_create (IpT_Phys_Interface_Info* intf_info_ptr);
static void				arp_vlan_table_entry_swap (ArpT_Vlan_Table_Entry* entry1_ptr, ArpT_Vlan_Table_Entry* entry2_ptr);
static int 				arp_subintf_index_from_vid_obtain (int pkt_vid);
static Boolean			arp_is_local_address (IpT_Address ip_address);
static void				ip_arp_error (const char *msg);
static void				ip_arp_warn (const char *msg);
static void				arp_connected_ip_find (IpT_Rte_Module_Data** ip_module_data_ptr, Objid* ip_module_objid_ptr);
static Boolean			arp_connected_mac_find (Objid* mac_module_objid_ptr, Objid* mac_if_objid_ptr, OpT_Int64* phys_addr_ptr);
static Boolean			arp_is_local_virtual_address (IpT_Address ip_address, OpT_Int64* vmac_addr_ptr);
static void				arp_hsrp_info_get ();
static void				arp_ipv6_nd_process_create (IpT_Rte_Module_Data* ip_module_data_ptr);
static void				arp_packet_from_ip_handle (int intrpt_strm);
static void				arp_packet_from_mac_handle (int intrpt_strm);
static void				arp_ip_packet_from_mac_handle (Packet* pkptr, int subintf_index);
static int				arp_mac_pkt_subintf_index_get (Packet* pkptr, Ici* iciptr, Boolean* pkt_drop_ptr);
static void				arp_timer_expiry_handle (void);
static void				ip_arp_intf_lower_layer_type_set (IpT_Interface_Info* intf_ptr, OpT_Int64 lower_layer_addr);

/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
typedef struct
	{
	/* Internal state tracking for FSM */
	FSM_SYS_STATE
	/* State Variables */
	Objid	                  		my_id                                           ;	/* Variable for storing objid of the surrounding */
	                        		                                                	/* ARP processor, and the surr. node objid.      */
	Objid	                  		my_node_id                                      ;
	char	                   		proc_model_name [32]                            ;	/* Variables used in registering the process in OMS */
	                        		                                                	/* Process Registry.                                */
	Prohandle	              		own_prohandle                                   ;
	OmsT_Pr_Handle	         		own_process_record_handle                       ;
	Ici*	                   		mac_iciptr                                      ;	/* Variable that defines an ICI for conveying the */
	                        		                                                	/* destination specific information to the mac    */
	                        		                                                	/* module.                                        */
	IpT_Interface_Info *	   		local_intf_ptr                                  ;	/* State variable to store the data structure */
	                        		                                                	/* for an IP interface.                       */
	ArpT_Vlan_Table_Entry*	 		vlan_to_subintf_index_table                     ;	/* Table used to find out the subinterface  */
	                        		                                                	/* information from given VLAN information. */
	int*	                   		subintf_index_to_vlan_table                     ;	/* Table that contains the information on which */
	                        		                                                	/* subinterface belongs to which VLAN.          */
	int	                    		supported_vlan_count                            ;	/* The total number of VLANs supported by the    */
	                        		                                                	/* subinterfaces of the IP physical interface to */
	                        		                                                	/* which this ARP serves.                        */
	Boolean	                		arp_sim_eff                                     ;	/* Variable to store information on whether ARP */
	                        		                                                	/* simulation efficiency mode is used.          */
	int	                    		cache_max_size                                  ;
	double	                 		arp_gran                                        ;
	double	                 		wait_time                                       ;
	double	                 		max_age_timeout                                 ;
	int	                    		arpreq_max_retry                                ;
	int	                    		max_queue_size                                  ;
	List*	                  		arp_cache_lptr                                  ;
	OpT_Int64	              		hardware_addr                                   ;	/* The MAC address of the MAC layer served by this ARP process. */
	                        		                                                	/* Note that this state variable may by overwritten by a link   */
	                        		                                                	/* aggregation protocol process with the MAC address that is    */
	                        		                                                	/* used for all the MACs in the aggregation group if the IP     */
	                        		                                                	/* interface compose by this ARP and its MAC is bundled with    */
	                        		                                                	/* other interfaces under a aggregate interface.                */
	int	                    		instrm_from_ip_rte                              ;	/* Define variables to store information on the    */
	                        		                                                	/* stream indexes on which to transmit and receive */
	                        		                                                	/* packets from the network.                       */
	int	                    		outstrm_to_ip_rte                               ;
	int	                    		instrm_from_mac                                 ;
	int	                    		outstrm_to_mac                                  ;
	char	                   		pid_string [512]                                ;	/* State variables for use while tracing/debugging. */
	Objid	                  		my_pro_id                                       ;
	HsrpT_Info*	            		hsrp_info_ptr                                   ;
	Prohandle	              		ipv6_nd_prohandle                               ;	/* Process handle of the ipv6_nd process. */
	IpT_Interface_Info *	   		alt_intf_ptr                                    ;	/* A dummy interface that contains all ALT VLAN addresses as        */
	                        		                                                	/* sub-interfaces. Valid only on a dual MSFC running in dual router */
	                        		                                                	/* mode.                                                            */
	} ip_arp_v4_2_state;

#define my_id                   		op_sv_ptr->my_id
#define my_node_id              		op_sv_ptr->my_node_id
#define proc_model_name         		op_sv_ptr->proc_model_name
#define own_prohandle           		op_sv_ptr->own_prohandle
#define own_process_record_handle		op_sv_ptr->own_process_record_handle
#define mac_iciptr              		op_sv_ptr->mac_iciptr
#define local_intf_ptr          		op_sv_ptr->local_intf_ptr
#define vlan_to_subintf_index_table		op_sv_ptr->vlan_to_subintf_index_table
#define subintf_index_to_vlan_table		op_sv_ptr->subintf_index_to_vlan_table
#define supported_vlan_count    		op_sv_ptr->supported_vlan_count
#define arp_sim_eff             		op_sv_ptr->arp_sim_eff
#define cache_max_size          		op_sv_ptr->cache_max_size
#define arp_gran                		op_sv_ptr->arp_gran
#define wait_time               		op_sv_ptr->wait_time
#define max_age_timeout         		op_sv_ptr->max_age_timeout
#define arpreq_max_retry        		op_sv_ptr->arpreq_max_retry
#define max_queue_size          		op_sv_ptr->max_queue_size
#define arp_cache_lptr          		op_sv_ptr->arp_cache_lptr
#define hardware_addr           		op_sv_ptr->hardware_addr
#define instrm_from_ip_rte      		op_sv_ptr->instrm_from_ip_rte
#define outstrm_to_ip_rte       		op_sv_ptr->outstrm_to_ip_rte
#define instrm_from_mac         		op_sv_ptr->instrm_from_mac
#define outstrm_to_mac          		op_sv_ptr->outstrm_to_mac
#define pid_string              		op_sv_ptr->pid_string
#define my_pro_id               		op_sv_ptr->my_pro_id
#define hsrp_info_ptr           		op_sv_ptr->hsrp_info_ptr
#define ipv6_nd_prohandle       		op_sv_ptr->ipv6_nd_prohandle
#define alt_intf_ptr            		op_sv_ptr->alt_intf_ptr

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	ip_arp_v4_2_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((ip_arp_v4_2_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

static void
arp_init (void)
	{
	IpT_Rte_Module_Data*	ip_module_data_ptr;
	Objid					ip_module_objid;
	Boolean					unconnected_node = OPC_FALSE;
	int						instrm, outstrm;
	int						i, ip_iface_table_size;
	IpT_Interface_Info*		ip_iface_elem_ptr;
	Boolean					ip_addrs_found = OPC_FALSE;
	Objid					stream_objid;
	int						stream_status;
	Objid					mac_if_objid = OPC_OBJID_INVALID;
	Objid					mac_module_objid;
	OpT_Int64				phys_addr;
	IpT_Group_Intf_Info*	group_info_ptr;
	int						ith_member, num_member_intfs;
	IpT_Member_Intf_Info*	member_intf_ptr;

	/* 	If the ARP sim efficiency mode is enabled, ARP uses	*/
	/* 	nato tables, created by IP layer, to perform 		*/
	/*	the lookup between IP addresses and lower layer MAC	*/
	/*	addresses. In this state, the lookup structure is 	*/
	/*	created by entering the lower layer addresses for	*/ 
	/*	the local node into the nato table. 				*/

	FIN (arp_init (void));

	/* Find a connected IP module.	*/
	arp_connected_ip_find (&ip_module_data_ptr, &ip_module_objid);

	/* Find connected MAC module.	*/
	unconnected_node = arp_connected_mac_find (&mac_module_objid, &mac_if_objid, &phys_addr);

	/* Do further processing only if the node is connected.	*/
	if (unconnected_node != OPC_TRUE)
		{
		/* 	Determine the output stream number from the IP 		*/
		/*	module to the ARP module. 							*/
		oms_tan_neighbor_streams_find (my_id, ip_module_objid, &instrm_from_ip_rte, &outstrm_to_ip_rte);
		oms_tan_neighbor_streams_find (ip_module_objid, my_id, &instrm, &outstrm);

		/* 	Look for the local IP net and node numbers 			*/
		/*	corresponding to the above port number. 			*/
		ip_iface_table_size = inet_rte_num_interfaces_get (ip_module_data_ptr);
		
		/* 	If the value of the "ip addr index" on the stream	*/
		/* 	from IP is "Not Used", this ARP is not used at		*/
		/*	all, and it should not try to include entries in 	*/
		/*	the global ARP table. 								*/
		stream_objid = op_topo_assoc (my_id, OPC_TOPO_ASSOC_IN, OPC_OBJTYPE_STRM, 0);
		if (op_ima_obj_attr_exists (stream_objid, "ip addr index") == OPC_TRUE)
			{
			/*	This is the packet stream from IP.				*/
			op_ima_obj_attr_get (stream_objid, "ip addr index", &stream_status);
			}
		else
			{
			/*	It was the packet stream from MAC. Increment	*/
			/*	the index and re-search for "ip addr index".	*/
			stream_objid = op_topo_assoc (my_id, OPC_TOPO_ASSOC_IN, OPC_OBJTYPE_STRM, 1);
			op_ima_obj_attr_get (stream_objid, "ip addr index", &stream_status);
			}

		if (stream_status != ADDR_INDEX_INVALID)
			{
			for (i = 0; i < ip_iface_table_size; i++)
				{
				ip_iface_elem_ptr = inet_rte_intf_tbl_access (ip_module_data_ptr, i);
			
				/* If the current interface is a group, check	*/
				/* its member interfaces.						*/
				if (ip_rte_intf_is_group (ip_iface_elem_ptr))
					{
					/* Get a handle to structure that stores	*/
					/* group related parameters.				*/
					group_info_ptr = ip_iface_elem_ptr->phys_intf_info_ptr->group_info_ptr;

					/* Get the number of member interfaces.		*/
					num_member_intfs = group_info_ptr->num_members;
					
					/* Loop through each member and check if its*/
					/* outstrm matches the outstrm we are		*/
					/* looking for.								*/
					for (ith_member = 0; ith_member < num_member_intfs; ith_member++)
						{
						/* Get a handle to the ith member		*/
						member_intf_ptr = &(group_info_ptr->member_intf_array[ith_member]);

						/* Compare the outstrm.					*/
						if (member_intf_ptr->outstrm == outstrm)
							{
							/* We found the IP interface to		*/
							/* which we are connected. 			*/
							ip_addrs_found = OPC_TRUE;

							/* For the use of link aggregation	*/
							/* protocols, store the MAC address	*/
							/* information in the member record.*/
							member_intf_ptr->mac_address = phys_addr;
							
							/* Break out of the loop.			*/
							break;
							}
						}

					/* If we found the interface that we are	*/
					/* looking for, break out of the loop.		*/
					if (ip_addrs_found)
						{
						/* 	Save a reference to the interface this	*/
						/*	ARP belongs to. 						*/
						local_intf_ptr = ip_iface_elem_ptr;
						
						/* Create the mapping table between VLANs	*/
						/* and subinterfaces.						*/
						arp_vlan_tables_create (ip_iface_elem_ptr->phys_intf_info_ptr);

						break;
						}
					}
				
				else if (ip_iface_elem_ptr->phys_intf_info_ptr->port_num == outstrm)
					{
					/* We found the IP interface to which we	*/
					/* are connected. 							*/
					ip_addrs_found = OPC_TRUE;
					
					/* 	Save a reference to the interface this	*/
					/*	ARP belongs to. 						*/
					local_intf_ptr = ip_iface_elem_ptr;
					
					/* Create the mapping table between VLANs	*/
					/* and subinterfaces.						*/
					arp_vlan_tables_create (ip_iface_elem_ptr->phys_intf_info_ptr);
					
					break;
					}

				/* Subinterfaces of a physical interface also 	*/
				/* will have the same port number. No need to	*/
				/* repeat the check for subinterfaces.			*/
				i += ip_rte_num_subinterfaces_get (ip_iface_elem_ptr);
				}

			if (ip_addrs_found == OPC_TRUE)
				{
				/*	Obtain the output stream index from ARP to mac module.		*/
				/*	Determine if the ARP module is directly connected to the	*/
				/*	MAC or via an interface module.								*/
				if (mac_if_objid != OPC_OBJID_INVALID)
					{
					/*	ARP is connected to an interface module. Obtain stream	*/
					/*	indices connected to and from this module.				*/
					oms_tan_neighbor_streams_find (my_id, mac_if_objid, &instrm_from_mac, &outstrm_to_mac);
					}
				else
					{
					/*	ARP is directly connected to the MAC module. Obtain		*/
					/*	the stream indices connected to and from the MAC.		*/
					oms_tan_neighbor_streams_find (my_id, mac_module_objid, &instrm_from_mac, &outstrm_to_mac);
					}

				/* Spawn the ipv6_nd process if necessary.						*/
				arp_ipv6_nd_process_create (ip_module_data_ptr);
				}
			
			/* If this is a dual-MSFC device running in dual router mode, the	*/
			/* ARP module must assume the responsibility of the ALT IP addrs	*/
			/* of the VLAN interfaces as well. The alt addresses are modeled as	*/
			/* distinct VLAN interfaces on a dummy interface called RSM.		*/
			if (ip_node_is_dual_msfc_in_drm (ip_module_data_ptr) && (subintf_index_to_vlan_table != OPC_NIL))
				ip_rte_is_local_intf_name ("RSM-ALT", ip_module_data_ptr, OPC_NIL, &alt_intf_ptr);
			
			/* 	It is possible that no interface will be found because the		*/ 
			/*	interface table does not necessarily include interfaces that 	*/
			/* 	have not been connected at the network level.This is o.k.		*/
			/* 	because we don't expect this "mac-arp" pair to ever be used		*/
			/* 	during the simulation.											*/			
			if ((arp_sim_eff) && (ip_addrs_found == OPC_TRUE))
				{
				/*  For aggregate (group) interfaces, the registeration will be	*/
				/*  performed by the link aggregation protocol.					*/
				if (ip_rte_intf_is_group (local_intf_ptr) == OPC_FALSE)
					{
					/* Register both addresses into the global table			*/
					ip_rtab_intf_lower_layer_address_register (local_intf_ptr, phys_addr, ARPC_ADDR_TYPE_MAC);

					if (OPC_NIL != alt_intf_ptr)
						ip_rtab_intf_lower_layer_address_register (alt_intf_ptr, phys_addr, ARPC_ADDR_TYPE_MAC);
					}
				}
			else if (ip_addrs_found == OPC_TRUE)
				{
				/* Set the lower layer address and type in the IP interface information.	*/
				ip_arp_intf_lower_layer_type_set (local_intf_ptr, phys_addr);

				if (OPC_NIL != alt_intf_ptr)
					ip_arp_intf_lower_layer_type_set (alt_intf_ptr, phys_addr);
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				}

			/* Store the address of underlying MAC module. This address is		*/
			/* always set regardless of whether the interface is used, or ARP	*/
			/* simulation efficiency is enabled. Also note that this address	*/
			/* may by overwritten by a link	aggregation protocol process with	*/
			/* the MAC address that is used for all the MACs in the aggregation	*/
			/* group if the IP interface composed by this ARP and its MAC is	*/
			/* bundled with	other interfaces under an aggregate interface.		*/
			hardware_addr = phys_addr;
			}
		}

	FOUT;
	}

static void
arp_connected_ip_find (IpT_Rte_Module_Data** ip_module_data_pptr, Objid* ip_module_objid_ptr)
	{
	List						proc_record_handle_list;
	int							record_handle_list_size;
	OmsT_Pr_Handle				process_record_handle;
	Objid						ip_module_objid;
	IpT_Rte_Module_Data* 		ip_module_data_ptr;
	
	/** Finds connected IP module and gets its object ID  	**/
	/** and pointer to IP module data as published in the	**/
	/** process registry.									**/
	FIN (arp_connected_ip_find (ip_module_data_ptr, ip_module_objid));
	
	/* 	Obtain the IP interface information for the local 	*/
	/*	ip process from the model-wide registry. 			*/
	op_prg_list_init (&proc_record_handle_list);

	oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list, 
		"node objid",	OMSC_PR_OBJID,		my_node_id,
		"protocol", 	OMSC_PR_STRING,		"ip", 
		OPC_NIL);

	record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
	
	if (record_handle_list_size != 1)
		{
		/* 	An error should be created if there are more 	*/
		/*	than one ip process in the local node, or		*/
		/*	if no match is found. 							*/
		op_sim_end ("Error: either zero or several ip processes found in the local node", "", "", "");
		}
	else
		{
		/*	Obtain a handle on the process record.			*/
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);

		/* Obtain a pointer to the ip module data	. 		*/
		oms_pr_attr_get (process_record_handle,	"module data", OMSC_PR_POINTER, &ip_module_data_ptr);	

		/* Obtain the module objid for the IP module. 		*/
		oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &ip_module_objid);
		
		*ip_module_objid_ptr = ip_module_objid;
		*ip_module_data_pptr = ip_module_data_ptr;
		}

	FOUT;
	}


static Boolean
arp_connected_mac_find (Objid* mac_module_objid_ptr, Objid* mac_if_objid_ptr, OpT_Int64* phys_addr_ptr)
	{
	List						proc_record_handle_list;
	int							record_handle_list_size;
	OmsT_Pr_Handle				process_record_handle;
	OpT_Int64					phys_layer_addr = OPC_INT64_MIN;
	Objid						mac_module_objid = OPC_OBJID_INVALID;
	Objid						mac_if_objid = OPC_OBJID_INVALID;
	Boolean						unconnected_node = OPC_FALSE;

	/** Find a MAC module connected to this ARP process.	**/
	/** This can be one of									**/
	/** 1. a regular MAC module								**/
	/** 2. MAC interface module								**/
	/** 3. switch module (in a case of RSM device)			**/
	/** If ARP interfaces to a MAC interface module, also	**/
	/** find a MAC module conencted to the interface process**/
	/** After that obtain									**/
	/** 1. module object ID of MAC process, and				**/
	/** 2. physical address of MAC or switch module.		**/
	FIN (arp_connected_mac_find ());
	
	/* 	Obtain information about the neighboring, 			*/
	/*	underlying mac layer process. 						*/
	op_prg_list_init (&proc_record_handle_list); 

	/* First search for MAC module. Such a module has	*/
	/* already published MAC as its protocol.			*/
	oms_pr_process_discover (my_id, &proc_record_handle_list,
		"node objid",	OMSC_PR_OBJID,		my_node_id,
		"protocol",		OMSC_PR_STRING,		"mac",
		OPC_NIL);

	record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
	
	if (record_handle_list_size > 1)
		{
		/* 	An error should be created if there is more 	*/
		/*	than one mac layer process connected to this	*/
		/*	arp process. 									*/
		op_sim_end ("Error: several mac layer processes connected to a single arp process.", "", "", "");	
		}
	else if (record_handle_list_size == 1)
		{
		process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);

		/* Obtain the lower layer mac address. 				*/
		oms_pr_attr_get (process_record_handle, "address", OMSC_PR_INT64, &phys_layer_addr);

		/* Obtain the module objid for the mac module. 		*/
		oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &mac_module_objid);
		}
	else
		{
		/* 	There are no mac modules attached.  Attempt to 	*/
		/*	find "mac_if" modules. "mac_if" modules are 	*/
		/*	modules that act as an interface between the mac*/	
		/* 	and other modules.								*/
		oms_pr_process_discover (my_id, &proc_record_handle_list,
			"node objid",	OMSC_PR_OBJID,		my_node_id, 
			"mac_if",		OMSC_PR_STRING,		"TRUE",
			OPC_NIL);
			
		record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
		if (record_handle_list_size > 1)
			{
			/* 	An error should be created if there are more*/
			/*	than one mac layer process connected to this*/
			/*	arp process. 								*/
			op_sim_end ("Error: several mac layer processes connected to a single arp process.", "", "", "");	
			}
		else if (record_handle_list_size == 1)
			{
			process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);

			/* Obtain the lower layer module objid. */
			oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &mac_if_objid);
		
			oms_pr_process_discover (mac_if_objid, &proc_record_handle_list, 
				"node objid",	OMSC_PR_OBJID,		my_node_id, 
				"protocol",		OMSC_PR_STRING,		"mac",
				OPC_NIL);
		
			record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
			if (record_handle_list_size >= 1)
				{
				/* Multiple MAC modules are allowed below the "mac_if"	*/
				/* module.												*/
				/* However only one MAC module address is read by ARP.	*/	
				process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);

				/* Obtain the lower layer mac address. 		*/
				oms_pr_attr_get (process_record_handle, "address", OMSC_PR_INT64, &phys_layer_addr);
				
				/* Obtain the module objid for the mac module. */
				oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &mac_module_objid);
				}
			else
				{
				/* 	There are no mac modules attached.  	*/
				/*	Issue error. An error should be created	*/
				/* 	if there are no mac layer processes 	*/
				/*	connected to this arp process. 			*/
				unconnected_node = OPC_TRUE;
				}
			}
		else
			{
			/* There is neither MAC, nor MAC IF process below. */
			/* There can still be a switch model (in a case of 	*/
			/* an RSM switch.									*/
		
			oms_pr_process_discover (my_id, &proc_record_handle_list,
				"node objid",	OMSC_PR_OBJID,		my_node_id,
				"protocol",		OMSC_PR_STRING,		"bridge",
				"location",		OMSC_PR_STRING,		"mac_if",
				OPC_NIL);

			record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
		
			if (record_handle_list_size > 1)
				{
				/* 	An error should be created if there are more 	*/
				/*	than one mac layer process connected to this	*/
				/*	arp process. 									*/
				op_sim_end ("Error: several bridge processes connected to a single arp process.", "", "", "");	
				}
			else if (record_handle_list_size == 1)
				{
				process_record_handle = (OmsT_Pr_Handle) op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);

				/* Obtain the lower layer mac address. 		*/
				oms_pr_attr_get (process_record_handle, "address", OMSC_PR_INT64, &phys_layer_addr);
								
				/* Obtain the module objid for the mac module. */
				oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &mac_module_objid);
				}
			else
				{
				/* 	There are no mac modules attached.  	*/
				/*	Issue error. An error should be created	*/
				/* 	if there are no mac layer processes 	*/
				/*	connected to this arp process. 			*/
				unconnected_node = OPC_TRUE;
				}
			}

		/* Clean up the no longer needed registry information  */
		/* - in this case, because we've used a list allocated */
		/* on the local stack, we do not need to worry about   */
		/* freeing the memory. Just empty the list. 		   */
		while (op_prg_list_size (&proc_record_handle_list))
			op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);
		}
	
	/* 	Store the address into an interger 		*/
	/*	variable. 								*/
	*phys_addr_ptr = phys_layer_addr;

	*mac_module_objid_ptr 	= mac_module_objid;
	*mac_if_objid_ptr	 	= mac_if_objid;
	
	FRET (unconnected_node);
	}

static Compcode 
arp_cache_entry_find (IpT_Address dest_ip_addr, int* index_ptr)
	{
	int					table_size;
	int					i;
	IpT_Arp_Entry*		entry_ptr;

	/**	Find the entry in the ARP cache for a given			**/
	/**	destination IP address. Returns	SUCCESS and the 	**/
	/**	index of the found entry if an address mapping 		**/
	/**	corresponding to the destination IP address is 		**/
	/**	found. Otherwise, this function returns a FAILURE. 	**/
	FIN (arp_cache_entry_find (dest_ip_addr, index_ptr))

	/*	Obtain the size of the ARP table.					*/
	table_size = op_prg_list_size (arp_cache_lptr);

	/*	Loop thrpugh the ARP table entries to find an entry	*/
	/*	for the destination IP address.						*/
	for (i = 0; i < table_size; i++)
		{
		/*	Get an handle of the entry.						*/
		entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, i);

		/*	Match the to-be-resolved destination IP address	*/
		/*	with the entry's IP address.					*/
		if (ip_address_equal (dest_ip_addr, entry_ptr->ip_addr) == OPC_TRUE)
			{
			/*	IP addresses match. Return the index of the	*/
			/*	entry in the ARP table.						*/ 
			*index_ptr = i;
			
			/*	Return a success code to indicate that a	*/
			/*	matching entry was found.					*/
			FRET (OPC_COMPCODE_SUCCESS)
			}
		}

	/*	All the entries in the table have been searched;	*/
	/*	however no matching entry could be found. Return a	*/
	/*	failure to indicate this.							*/
	FRET (OPC_COMPCODE_FAILURE)
	}

static int
arp_cache_entry_create (void)
	{
	int					cache_size;
	IpT_Arp_Entry*		temp_entry_ptr;
	int					tbl_index;
	int					resolved_entry_find;
	int					pending_entry_find;

	/**	Creates a new entry in the arp table. If the 		**/
	/**	size of the ARP	cache has reached the maximum size,	**/
	/**	then the new entry is created by deleting the 		**/
	/**	existing entry in the following order:				**/
	/**	1. Resolved entry with minimum age.					**/
	/** 2. Pending entry with maximum number of attempts.	**/
	/** Returns the index of the newly created entry.		**/
	FIN (arp_cache_entry_create ())

	/* Obtain the size of the ARP Cache.					*/
	cache_size = op_prg_list_size (arp_cache_lptr);

	/* 	Compare the ARP cache size with the maximum			*/
	/*	allowable ARP Cache size.							*/
	if (cache_size < cache_max_size)
		{
		/* Allocates memory for the new entry				*/
		temp_entry_ptr = arp_cache_entry_alloc ();

		/* Initializes all the field in the ARP entry		*/
		arp_cache_entry_init (temp_entry_ptr);

		/* Insert the entry into the ARP Cache.				*/
		op_prg_list_insert (arp_cache_lptr, temp_entry_ptr, OPC_LISTPOS_TAIL);

		/*	Obtain the size of the table and subtract 1 	*/
		/*	as index always starts from 0.					*/
		tbl_index = op_prg_list_size (arp_cache_lptr) - 1;
		}
	else
		/* 	Otherwise, determine the entry to be deleted	*/ 
		/*	based on the criteria listed above.				*/ 
		{
		/*	Find out the index of the resolved entry with	*/
		/*	minimum age.									*/
		resolved_entry_find = arp_cache_oldest_resolved_entry (&tbl_index);
		
		if (resolved_entry_find == OPC_COMPCODE_FAILURE)
			{
			/* 	If resolved entry with minimum age is not	*/
			/*	found then find out the pending entry 		*/
			/*	with maximum number of retries for sending 	*/
			/*	an ARP request.								*/
			pending_entry_find = arp_cache_oldest_pending_entry (&tbl_index);
			
			if (pending_entry_find == OPC_COMPCODE_FAILURE)
				{
				ip_arp_error ("Unable to find the pending or resolved entry to be deleted.");
				}
			}

		/* 	Call the procedure to delete the entry 		*/
		/*	found based on the above mentioned 			*/
		/*	deletion criteria.							*/
		arp_cache_entry_delete (tbl_index);
			
		/*	Obtain the size of the ARP cache.			*/
		cache_size = op_prg_list_size (arp_cache_lptr);

		/* Allocates memory for the new entry			*/
		temp_entry_ptr = arp_cache_entry_alloc ();

		/* Initialize the fields in the ARP entry.		*/
		arp_cache_entry_init (temp_entry_ptr);
		
		/* Insert the entry into the ARP Cache.			*/
		op_prg_list_insert (arp_cache_lptr, temp_entry_ptr, OPC_LISTPOS_TAIL);

		/*	Obtain the size of the table and subtract 1 */
		/*	as index always starts from 0.				*/
		tbl_index = op_prg_list_size (arp_cache_lptr) - 1;
		}

	/*	Return the index of the entry to be used.		*/
	FRET (tbl_index)
	}

static IpT_Arp_Entry*
arp_cache_entry_alloc (void)
	{
	static Boolean      arp_entry_poolmem_defined = OPC_FALSE;
	static Pmohandle    arp_entry_pmh;
	IpT_Arp_Entry*		table_entry_ptr;

	/** It allocates the memory for an ARP entry			**/
	FIN (arp_cache_entry_alloc())

	/* "Pooled" memory is used to allocate ARP entry		*/
	/*	allocation blocks since they are frequently created	*/
	/*	and destroyed. If the pooled memory object has  	*/
	/*	not yet been defined, do so now, prior to allocation*/
	if (arp_entry_poolmem_defined == OPC_FALSE)
		{
		arp_entry_pmh = op_prg_pmo_define ("ARP entry allocation block", sizeof (IpT_Arp_Entry), 10);

		/* Prevent redundant definition.  					*/
		arp_entry_poolmem_defined = OPC_TRUE;
		}
	table_entry_ptr = (IpT_Arp_Entry *) op_prg_pmo_alloc (arp_entry_pmh);

	FRET (table_entry_ptr)
	}

static void
arp_cache_entry_init (IpT_Arp_Entry* temp_entry_ptr)
	{
	/** Initializes the fields of an ARP entry and			**/ 
	/**	returns an intialized arp entry.					**/
	FIN (arp_cache_entry_init (temp_entry_ptr))

	/* 	Intialize the status of the entry to 				*/
	/*	free.												*/	
	temp_entry_ptr->state = ArpC_Entry_Free;

	/* 	Intialize phys_addr to indicate that it is unset.	*/	
	temp_entry_ptr->phys_addr = ARPC_PHYS_ADDR_UNSET;

	/* 	Initialize ip address to show that it is unset.		*/
	temp_entry_ptr->ip_addr = IPC_ADDR_INVALID;

	/*	Initialize age and num_attempts to 0.				*/
	temp_entry_ptr->age = 0;
	temp_entry_ptr->num_attempts = 0;

	/*	Create a list to contain packets to be queued		*/
	/*	address mapping is being resolved.					*/
	temp_entry_ptr->queue = op_prg_list_create ();

	FOUT
	}

static Compcode
arp_cache_oldest_resolved_entry (int* oldest_entry_index)
	{
	int				i;
	int				entry_age;
	IpT_Arp_Entry*	tbl_entry_ptr;
	
	/**	This procedure determines the oldest resloved 		**/
	/**	entry in the ARP cache and returns its index 		**/
	/**	and SUCCESS if the entry is found.					**/
	FIN (arp_cache_oldest_resolved_entry (oldest_entry_index));

	/*	Initialize a variable to indicate that the oldest	*/
	/*	entry is unknown, and set the entry age to maximum	*/
	/*  age.												*/	
    *oldest_entry_index = -1;
	entry_age = max_age_timeout;

	/* 	Loop through all the entries of the table to 		*/
	/*	find out the index of the resolved entry with		*/
	/*	minimum age.										*/
	for (i = 0; i < cache_max_size; i++)
		{
		/*	Obtain the handle for the ARP entry.			*/
		tbl_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, i);

		/* Determine the resolved entry with minimum age.	*/
		if (tbl_entry_ptr->state == ArpC_Entry_Resolved)
			{
			if (tbl_entry_ptr->age <= entry_age)
				{
				entry_age = tbl_entry_ptr->age;
				*oldest_entry_index = i;
				}
			}
		}

	/*	Return FAILURE if an oldest resolved entry has 		*/
	/*	not been found.										*/
	if (*oldest_entry_index != -1)
		{
		FRET (OPC_COMPCODE_SUCCESS)
		}
	else
		{
		FRET (OPC_COMPCODE_FAILURE)
		}
	}

static Compcode
arp_cache_oldest_pending_entry (int* pending_entry_index)
	{
	int				i;
	int				entry_num_attempts = 0;
	IpT_Arp_Entry*	tbl_entry_ptr;
	
	/**	This procedure determines the pending entry with	**/
	/**	maximum number of retries for sending an ARP 		**/
	/**	request in the ARP cache and returns its index 	**/
	/**	and SUCCESS if the entry is found.					**/
	FIN (arp_cache_oldest_pending_entry (pending_entry_index))
	
    *pending_entry_index = -1;

	/* 	Loop through all the entries of the table to 		*/
	/*	find out the index of the pending entry with		*/
	/*	maximum number of request retires.					*/
	for (i = 0; i < cache_max_size; i++)
		{
		/*	Obtain the handle for the ARP entry.			*/
		tbl_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, i);

		/* 	Determine the pending entry with maximum number	*/
		/* 	of request retires.								*/	
		if (tbl_entry_ptr->state == ArpC_Entry_Pending)
			{
			if (tbl_entry_ptr->num_attempts > entry_num_attempts)
				{
				entry_num_attempts = tbl_entry_ptr->num_attempts;
				*pending_entry_index = i;
				}
			}
		}

	/*	return FAILURE if pending entry is not found.		*/
	if (*pending_entry_index != -1)
		{
		FRET (OPC_COMPCODE_SUCCESS)
		}
	else
		{
		FRET (OPC_COMPCODE_FAILURE)
		}
	}

static void
arp_cache_entry_delete (int tbl_index)
	{
	IpT_Arp_Entry*			table_entry_ptr;
	IpT_Arp_Queue_Entity*	queue_entity_ptr;

	/**	Deletes the entry from the table and 				**/
	/**	deallocates the memory.								**/
	FIN (arp_cache_entry_delete (tbl_index))

	/* Obtain the handle of the ARP entry to be deleted 	*/
	table_entry_ptr = (IpT_Arp_Entry *) op_prg_list_remove (arp_cache_lptr, tbl_index);
		
	/* Determine if there are any packets in the queue.		*/
	while (op_prg_list_size (table_entry_ptr->queue))
		{
		/* Remove the current entity from the list.		   	*/
		queue_entity_ptr = (IpT_Arp_Queue_Entity *) op_prg_list_remove (table_entry_ptr->queue, OPC_LISTPOS_HEAD);

		/* Destroy the queued packet.						*/
		op_pk_destroy (queue_entity_ptr->queued_pkptr);
		
		/* Free the memory occupied by the list entity.		*/
		op_prg_mem_free (queue_entity_ptr);
		}

	/* Deallocate the memory associated with the queue.		*/
	op_prg_mem_free (table_entry_ptr->queue);

	/* Destroy the IP address.								*/
	ip_address_destroy (table_entry_ptr->ip_addr);

	/* Deallocate the memory associated with this entry.   	*/
	arp_cache_entry_dealloc (table_entry_ptr);

	FOUT
	}

static void
arp_cache_entry_update (int index, int state, 
	IpT_Address ip_address, OpT_Int64 phys_addr, int age, 
	int num_attempts, Packet* pkptr, int subintf_index)
	{
	IpT_Arp_Queue_Entity*	queue_entity_ptr;
	IpT_Arp_Entry*			entry_ptr;
	int						queue_size;
	
	/** Update the fields of a given entry in the			**/
	/**	ARP cache.											**/
	FIN (arp_cache_entry_update (index, state, ip_address, phys_addr, age, num_attempts, pkptr, subintf_index))

	/*	Get a handle of the entry from the ARP cache so 	*/
	/*	that the entry can be updated.						*/
	entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, index);

	/* 	Update the status of the entry if it is				*/ 
	/*	not set to ignore.									*/
	if (state != ARPC_STATE_UPDATE_IGNORE)
		{
		entry_ptr->state = (ArpT_Entry_Status)state;
		}

	/* 	Update the ip_address of the entry 					*/ 
	/*	if it is not set to ignore.							*/
	if (ip_address_equal (ip_address, ARPC_IP_ADDR_UPDATE_IGNORE) != OPC_TRUE)
		{
		entry_ptr->ip_addr = ip_address_copy (ip_address);
		}

	/* 	Update the physical address of the entry 			*/ 
	/*	if it is not set to ignore.							*/
	if (phys_addr != ARPC_PHYS_ADDR_UPDATE_IGNORE)
		{
		entry_ptr->phys_addr = phys_addr;
		}

	/* 	Update the age of the entry if it is				*/ 
	/*	not set to ignore.									*/
	if (age != ARPC_AGE_UPDATE_IGNORE)
		{
		entry_ptr->age = age;
		}

	/* 	Update the number of attempts of the 				*/ 
	/*	entry if it is not set to ignore.					*/
	if (num_attempts != ARPC_ATTEMPTS_UPDATE_IGNORE)
		{
		++entry_ptr->num_attempts;
		}

	/* 	Update the queue associated with the 				*/ 
	/*	entry if it is not set to ignore.					*/
	if (pkptr != ARPC_QUEUE_UPDATE_IGNORE)
		{
		/*	Obtain the size of the queue.					*/
		queue_size= op_prg_list_size (entry_ptr->queue);

		/* 	Queue the packet if the queue size has not 		*/
		/*	reached its maximum limit. 						*/
		if (queue_size < max_queue_size)
			{
			/* Queue the packet along with any related		*/
			/* information.									*/
			queue_entity_ptr = (IpT_Arp_Queue_Entity *) op_prg_mem_alloc (sizeof (IpT_Arp_Queue_Entity));
			queue_entity_ptr->queued_pkptr  = pkptr;
			queue_entity_ptr->subintf_index = subintf_index;
			op_prg_list_insert (entry_ptr->queue, queue_entity_ptr, OPC_LISTPOS_TAIL);
			}
		else
			{
			/*	Destroy the packet.							*/
			op_pk_destroy (pkptr);
			}
		}

	FOUT
	}

static void
arp_cache_entry_dealloc(IpT_Arp_Entry* entry_ptr)
	{
	
	/** Deallocates the memory for the ARP entry 			**/
	FIN (arp_cache_entry_dealloc(entry_ptr))

	op_prg_mem_free (entry_ptr);
	
	FOUT;
	}


static void
arp_request_bcast (IpT_Address dest_ip_addr, int subintf_index)
	{
	OpT_Int64				dest_phys_addr;	
	Packet*					pk_ptr;
	Boolean					is_arp_packet = OPC_TRUE;

	/**	Create an ARP request and set the following field  	**/
	/**	in the ARP request:									**/
	/**		1. Source IP address, 							**/
	/**		2. Source physical layer address				**/
	/**		3. Destination IP address 						**/
	/**	 	4. Operation code as ARPC_REQUEST 				**/
	/**	Set the broadcast address in the ici and send the 	**/
	/**	packet.												**/
	FIN (arp_request_bcast (dest_ip_addr, subintf_index))

	/* Create a packet of format "arp"						*/
	pk_ptr = op_pk_create_fmt ("arp_v2");

	/* 	Set the src IP and physical layer address 			*/	
	/*	fields in the ARP request packet.					*/
	op_pk_nfd_set (pk_ptr, "src hw addr", hardware_addr);
	op_pk_nfd_set (pk_ptr, "src protocol addr", local_intf_ptr->addr_range_ptr->address); 

	/*	Set the destination IP address and 					*/
	/*	operation code in the packet.						*/
	op_pk_nfd_set (pk_ptr,  "dest hw addr", ARPC_BROADCAST_ADDR);
	op_pk_nfd_set (pk_ptr, "dest protocol addr", dest_ip_addr); 

	/* 	Set the operation code field in the packet			*/
	/*	to ARPC_REPLY.										*/	
	op_pk_nfd_set (pk_ptr, "arp opcode", ARPC_REQUEST);	
	dest_phys_addr = ARPC_BROADCAST_ADDR;

	/* Call the function to send the packet.				*/
	arp_packet_send (is_arp_packet, pk_ptr, dest_phys_addr, subintf_index, outstrm_to_mac);

	FOUT
	}

static void
arp_packet_send (Boolean is_arp_packet, Packet* pkptr, OpT_Int64 dest_phys_addr, int subintf_index, int strm_index)
	{
	/**	Send the packet and set the destination address 	**/
	/**	and protocol type in the ICI 						**/
	FIN (arp_packet_send (is_arp_packet, pkptr, dest_phys_addr, subintf_index, strm_index));

	/*  Place the destination physical layer address and	*/
	/*  protocol type (IP) into the ICI.					*/
	op_ici_attr_set_int64 (mac_iciptr, "dest_addr",	  dest_phys_addr);
	
    /* As per ethereal trace, ARP packets have the protocol type field	*/
	/* set to NET_PROT_IP but ethernet packets have the protocol type	*/
	/* field set to NET_PRO_ARP.										*/
	
	/* The hardware type field is being hardcoded to value of 1 which	*/
	/* corresponds to ethernet. This may need to change for other MACs.	*/	
	
	if (is_arp_packet)
		{
		op_ici_attr_set_int32 (mac_iciptr, "protocol_type", NET_PROT_ARP);
		op_pk_nfd_set_int32 (pkptr, "protocol type", NET_PROT_IP);
		op_pk_nfd_set_int32 (pkptr, "hardware type", 1);		
		}
	else
		{
		op_ici_attr_set_int32 (mac_iciptr, "protocol_type", NET_PROT_IP);
		}

	/* If the IP packet is associated with any subinterface	*/
	/* then pass the VID of the VLAN, to which this			*/
	/* subinterface belongs, to the MAC within the ICI.		*/
	if (subintf_index != IPC_SUBINTF_PHYS_INTF && subintf_index != ARPC_UNDEF_SUBINTF_INDEX)
		op_ici_attr_set_int32 (mac_iciptr, "vlan_id",	subintf_index_to_vlan_table [subintf_index]);
	else
		op_ici_attr_set_int32 (mac_iciptr, "vlan_id",	OMSC_VLAN_NULL_VID);

	/* Send the packet coupled with the ICI.				*/
	op_ici_install (mac_iciptr);
	op_pk_send_forced (pkptr, strm_index);

	/* Deinstall the ICI.									*/
	op_ici_install (OPC_NIL);

	FOUT;
	}

static void
arp_response_ucast (Packet* pkptr, OpT_Int64 src_phys_address, IpT_Address src_ip_address, 
					IpT_Address dest_ip_address, int subintf_index, OpT_Int64 virtual_mac_addr)
	{
	Boolean			is_arp_packet = OPC_TRUE;

	/**	This function will create a response packet 		**/
	/**	by swapping the source and destination 				**/
	/**	hardware and protocol addresses in the ARP 			**/
	/**	request packet. Set the operation code as 			**/
	/** ARPC_RESPONSE. Set the physical address in 			**/
	/**	the ici and send the packet.						**/
	FIN (arp_response_ucast (pkptr, src_phys_address, src_ip_address, dest_ip_address, subintf_index))

	/* 	Set the operation code field in the packet			*/
	/*	to ARPC_REPLY.										*/	
	op_pk_nfd_set (pkptr, "arp opcode", ARPC_REPLY);										

	/* 	Set the src IP and physical layer address 			*/
	/*	fields in the packet.								*/
	/* If this ARP request was for a virtual address then	*/
	/* respond with corresponding Virtual MAC Address else	*/
	/* use regular hardware address							*/
	if (virtual_mac_addr == -1)
		{
		op_pk_nfd_set (pkptr, "src hw addr", hardware_addr);
		}
	else
		{
		op_pk_nfd_set (pkptr, "src hw addr", virtual_mac_addr);
		}
	
	op_pk_nfd_set (pkptr, "src protocol addr", dest_ip_address); 

	/* 	Set the destination IP and physical layer 			*/	
	/*	address fields in the packet.						*/
	op_pk_nfd_set (pkptr, "dest hw addr", src_phys_address);
	op_pk_nfd_set (pkptr, "dest protocol addr", src_ip_address); 

	/* 	Set the physical layer address and protocol 		*/
	/*	in the ICI and send the packet 						*/
	arp_packet_send (is_arp_packet, pkptr, src_phys_address, subintf_index, outstrm_to_mac);

	FOUT
	}

static void
arp_enq_pkt_send (int index)
	{
	int						queue_size;
	IpT_Arp_Entry*			entry_ptr;
	OpT_Int64				dest_phys_addr;
	IpT_Arp_Queue_Entity*	queue_entity_ptr;

	/**	This procedure sends the packets, if any,			**/
	/**	in the queue for a given entry in the ARP 			**/
	/**	cache.												**/
	FIN (arp_enq_pkt_send (index))

	/*	Obtain the handle for the given entry.				*/
	entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, index);

	/*	Obtain the size of the queue.						*/
	queue_size = op_prg_list_size (entry_ptr->queue);

	/*	Check if the queue associated with this 			*/
	/*	entry has packets.									*/
	if (queue_size > 0)
		{
		/*	Obtain the destination physical layer			*/
		/*	address from the ARP table corresponding		*/
		/*	to this entry.									*/
		dest_phys_addr = entry_ptr->phys_addr;

		/* 	Loop through the queue to send packets.			*/
		while (op_prg_list_size (entry_ptr->queue))
			{
			queue_entity_ptr = (IpT_Arp_Queue_Entity *) op_prg_list_remove (entry_ptr->queue, OPC_LISTPOS_HEAD);

			/* Call the function to send the queued packet.	*/
			arp_packet_send (OPC_FALSE, queue_entity_ptr->queued_pkptr, dest_phys_addr, queue_entity_ptr->subintf_index, outstrm_to_mac);
			
			/* Free the memory used by the queue entity.	*/
			op_prg_mem_free (queue_entity_ptr);
			}
		}

	FOUT
	}

static void
arp_cache_entry_print (IpT_Arp_Entry* tbl_ptr)
	{
	char				address_str [IPC_ADDR_STR_LEN];
	int					queue_size = 0;
	char				str0 [512];
	char				str1 [512];
	char				str2 [512];

	/**	This procedure is called to print out the 			**/
	/**	contents of an ARP cache entry.						**/
	FIN (arp_cache_entry_print (tbl_ptr))

	printf ("\t  State       IP Address     Phys Address   Age   Req Retry  Queue Size\n");
	printf ("\t---------  ---------------   ------------  -----  ---------  ----------\n");

	/* 	Get string representations of the address 			*/
	/*	and subnet mask.									*/
	ip_address_print (address_str, tbl_ptr->ip_addr);

	/*	Obtain the size of the packet 						*/
	/*	retransmission queue.								*/
	queue_size = op_prg_list_size (tbl_ptr->queue);

	arp_entry_status_index_to_string_convert (tbl_ptr->state, str1);
			
	/*	Obtain the string representation for the status 	*/
	/*	field of an arp entry.								*/
	if (tbl_ptr->phys_addr == ARPC_PHYS_ADDR_UNSET)
				{
				arp_entry_phys_addr_to_string_convert (tbl_ptr->phys_addr, str2);
				sprintf (str0, "%9s  %15s   %12s  %5d  %9d  %10d\n",
					str1, address_str, str2, tbl_ptr->age, tbl_ptr->num_attempts, queue_size);
				}
			else
				{ 
				sprintf (str0, "%9s  %15s	"   OPC_INT64_FMT  "	%5d  %9d  %10d\n",
					str1, address_str, tbl_ptr->phys_addr, tbl_ptr->age, tbl_ptr->num_attempts, queue_size); 
				}

	printf ("\t%s\n", str0);

	FOUT
	}

static void 
arp_cache_print (void)
	{
	char				address_str [IPC_ADDR_STR_LEN];
	int					i, tbl_size;
	int					queue_size = 0;
	char				str0 [512];
	char				str1 [512];
	char				str2 [512];
	IpT_Arp_Entry*		tbl_entry_ptr;

	/**	This procedure is called to print out the 			**/
	/**	contents of an ARP cache.							**/
	FIN (arp_cache_print ())

	/* 	Obtain the size of ARP cache.						*/	
	tbl_size = op_prg_list_size (arp_cache_lptr);

	if (tbl_size == 0)
		{
		op_prg_odb_print_minor ("ARP cache occupancy is zero.", OPC_NIL);
		}
	else
		{
		printf ("\t  State       IP Address     Phys Address   Age   Req Retry  Queue Size\n");
		printf ("\t---------  ---------------   ------------  -----  ---------  ----------\n");
	
		for (i = 0; i < tbl_size; i++)
			{
			/*	Obtain the handle for an ARP cache entry.	*/
			tbl_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, i);

			/* 	Get string representations of the address 	*/
			ip_address_print (address_str, tbl_entry_ptr->ip_addr);

			/*	Obtain the size of the packet 				*/
			/*	retransmission queue.						*/
			queue_size = op_prg_list_size (tbl_entry_ptr->queue);
		
			arp_entry_status_index_to_string_convert (tbl_entry_ptr->state, str1);
			
			if (tbl_entry_ptr->phys_addr == ARPC_PHYS_ADDR_UNSET)
				{
				arp_entry_phys_addr_to_string_convert (tbl_entry_ptr->phys_addr, str2);
				sprintf (str0, "%9s  %15s   %12s  %5d  %9d  %10d\n",
					str1, address_str, str2, tbl_entry_ptr->age, tbl_entry_ptr->num_attempts, queue_size); 
				}
			else
				{
				sprintf (str0, "%9s  %15s	"  OPC_INT64_FMT  "		%5d  %9d  %10d\n",
					str1, address_str, tbl_entry_ptr->phys_addr, tbl_entry_ptr->age, tbl_entry_ptr->num_attempts, queue_size); 
				}

			printf ("\t%s\n", str0);
			}
		}

	FOUT
	}

static void
arp_entry_status_index_to_string_convert (int class_index, char* class_string)
	{
	/** This procedure sets the class string value specified	**/
	/** by the class index.  If there is no match, then the     **/
	/** a string indicating an invalid value is set.            **/
	FIN (arp_entry_status_index_to_string_convert (class_index, class_string));

	/* Switch off of the class index value. 					*/
	switch (class_index)
		{
		case ArpC_Entry_Free:
			{
			strcpy (class_string, "Free");
			break;
			}

		case ArpC_Entry_Pending:
			{
			strcpy (class_string, "Pending");
			break;
			}
		
		case ArpC_Entry_Resolved:
			{
			strcpy (class_string, "Resolved");
			break;
			}

		case ArpC_Entry_Permanent:
			{
			strcpy (class_string, "Permanent");
			break;
			}
		
		default:
			{
			sprintf (class_string, "Invalid value (%d)", class_index);
			break;
			}
		}
	FOUT;
	}

static void
arp_entry_phys_addr_to_string_convert (int class_index, char* class_string)
	{
	/** This procedure sets the class string value specified	**/
	/** by the class index.  If there is no match, then the     **/
	/** a string indicating an invalid value is set.            **/
	FIN (arp_entry_phys_addr_to_string_convert (class_index, class_string));

	/* Switch off of the class index value. 					*/
	switch (class_index)
		{
		case ARPC_PHYS_ADDR_UNSET:
			{
			strcpy (class_string, "Undefined");
			break;
			}

		default:
			{
			break;
			}
		}

	FOUT;
	}

static void
arp_vlan_tables_create (IpT_Phys_Interface_Info* intf_info_ptr)
	{
	int			i, j;
	Boolean		sorted;
	
	/** This function creates and populates the tables that		**/
	/** will be used mapping between the VLAN Identifiers and	**/
	/** indices of the subinterfaces of the IP interface served	**/
	/** by this ARP. The table to map the indices to VIDs is a	**/
	/** simple VID (integer) array accessed with subinterface	**/
	/** indices. The table to map the VIDs to indices is sorted	**/
	/** with respect to VIDs to support binary search over the	**/
	/** table.													**/
	FIN (arp_vlan_tables_create (intf_info_ptr));
	
	/* Initialize the total count of supported VLANs by the		*/
	/* subinterfaces.											*/
	supported_vlan_count = 0;
	
	/* Quit if the physical interface doesn't have any			*/
	/* subinterface configuration.								*/
	if (intf_info_ptr->num_subinterfaces == 0)
		{
		subintf_index_to_vlan_table = OPC_NIL;
		vlan_to_subintf_index_table = OPC_NIL;
		FOUT;
		}
	
	/* Create the table array for subinterface address to VLAN	*/
	/* mapping.													*/
	subintf_index_to_vlan_table = (int *) op_prg_mem_alloc (intf_info_ptr->num_subinterfaces * sizeof (int));
	
	/* Go over the list of the subinterfaces and get the		*/
	/* information to fill the mapping table.					*/
	for (i = 0; i < intf_info_ptr->num_subinterfaces; i++)
		{
		subintf_index_to_vlan_table [i] = intf_info_ptr->subintf_pptr [i]->layer2_mappings.vlan_identifier;
		
		/* If valid, increment the number of subinterfaces with	*/
		/* valid VID association.								*/
		if (subintf_index_to_vlan_table [i] != OMSC_VLAN_NULL_VID)
			{
			supported_vlan_count++;
			}
		else
			{
			/* This subinterface was not assigned a VLAN ID.	*/
			/* Log a warning.									*/
			ipnl_subintf_without_vlan_id_log_write (ip_rte_intf_name_get 
				(ip_rte_ith_subintf_info_get (local_intf_ptr, i)));
			}
		}
	
	/* If the subinterfaces support VLANs, also create a table	*/
	/* to map VIDs to subinterface addresses.					*/
	if (supported_vlan_count > 0)
		{
		/* Create the table.									*/
		vlan_to_subintf_index_table = (ArpT_Vlan_Table_Entry *) op_prg_mem_alloc (supported_vlan_count * sizeof (ArpT_Vlan_Table_Entry));
		
		/* Populate the table.									*/
		for (i = 0, j = 0; i < intf_info_ptr->num_subinterfaces; i++)
			{
			if (subintf_index_to_vlan_table [i] != OMSC_VLAN_NULL_VID)
				{
				/* The current subinterface belongs to a VLAN.	*/
				vlan_to_subintf_index_table [j].vid           = subintf_index_to_vlan_table [i];
				vlan_to_subintf_index_table [j].subintf_index = i;
				j++;
				}
			}
		}
	else
		/* No VLANs are supported in spite of subinterface		*/
		/* configuration.										*/
		vlan_to_subintf_index_table = OPC_NIL;
	
	/* Sort the VID to subinterface index table according to	*/
	/* the VIDs to support binary search.						*/
	do
		{
		sorted = OPC_TRUE;
		for (i = 1; i < supported_vlan_count; i++)
			{
			if (vlan_to_subintf_index_table [i].vid < vlan_to_subintf_index_table [i - 1].vid)
				{
				/* Swap the entries to achieve order.			*/
				arp_vlan_table_entry_swap (&(vlan_to_subintf_index_table [i - 1]), &(vlan_to_subintf_index_table [i]));
				sorted = OPC_FALSE;
				}
			}
		} while (sorted == OPC_FALSE);
	
	FOUT;
	}

static void
arp_vlan_table_entry_swap (ArpT_Vlan_Table_Entry* entry1_ptr, ArpT_Vlan_Table_Entry* entry2_ptr)
	{
	ArpT_Vlan_Table_Entry	temp_entry;
	
	/** This function swaps the given two entries of the VID-	**/
	/** to-subinterface index mapping table.					**/
	FIN (arp_vlan_table_entry_swap (entry1_ptr, entry2_ptr));
	
	/* Swap the contents of two given entries using a			*/
	/* temporarily created entry.								*/
	op_prg_mem_copy (entry1_ptr,  &temp_entry, sizeof (ArpT_Vlan_Table_Entry));
	op_prg_mem_copy (entry2_ptr,  entry1_ptr,  sizeof (ArpT_Vlan_Table_Entry));
	op_prg_mem_copy (&temp_entry, entry2_ptr,  sizeof (ArpT_Vlan_Table_Entry));
	
	FOUT;
	}

static int
arp_subintf_index_from_vid_obtain (int pkt_vid)
	{
	int		low, median, high;
	
	/** This function performs binary search over the mapping	**/
	/** table to find the corresponding subinterface index for	**/
	/** the given VID. The found index value is returned. If	**/
	/** not found, then a special value indicating an undefined	**/
	/** subinterface index is returned.							**/
	FIN (arp_subintf_addr_from_vid_obtain (pkt_vid));
	
	/* Perform binary search over the table to find the entry	*/
	/* for given VID.											*/
	low = 0;
	high = supported_vlan_count - 1;
	while (low <= high)
		{
		/* Compare with the median of the remaining table.		*/
		median = (low + high) / 2;
		if (vlan_to_subintf_index_table [median].vid == pkt_vid)
			{
			/* We found the entry.								*/
			FRET (vlan_to_subintf_index_table [median].subintf_index);
			}
		else if (vlan_to_subintf_index_table [median].vid < pkt_vid)
			/* Focus on the remaining upper half.				*/
			low = median + 1;
		else
			/* Focus on the remaining lower half.				*/
			high = median - 1;
		}
	
	/* If we come to this point then there is no entry found in	*/
	/* the table for the given VID.								*/
	FRET (ARPC_UNDEF_SUBINTF_INDEX);
	}

static Boolean
arp_is_local_address_on_interface (IpT_Interface_Info* intf_info_ptr, IpT_Address ip_address)
	{
	int						i, num_subinterfaces;
	IpT_Interface_Info*		ith_subintf_info_ptr;
	int						num_addresses, j;

	/** This function checks if the specified address belongs to	**/
	/** to the physical interface or any of its subinterfaces of	**/
	/** the IP interface served by this ARP.						**/
	FIN (arp_is_local_address_on_interface ());

	/* Get the number of subinterfaces.								*/
	num_subinterfaces = ip_rte_num_subinterfaces_get (intf_info_ptr);

	/* Loop through the subinterfaces and look for one with a		*/
	/* matching ip address.											*/
	for (i = IPC_SUBINTF_PHYS_INTF; i < num_subinterfaces; i++)
		{
		ith_subintf_info_ptr = ip_rte_ith_subintf_info_get (intf_info_ptr, i);
		
		/* Check the primary and secondary addresses */
		num_addresses = ip_rte_intf_num_secondary_addresses_get (ith_subintf_info_ptr);
		
		/* Note that the secondary addres index of -1 */
		/* corresponds to the primary address.		  */
		for (j = -1; j < num_addresses; j++)
			{
			/* Match the jth secondary address 		*/
			/* If the addresses match, return true.	*/
			if (ip_address_equal (ip_address, ip_rte_intf_secondary_addr_get (ith_subintf_info_ptr, j)))
				{
				FRET (OPC_TRUE);
				}
			}
		}

	/* We looped through all the subinterfaces without finding a	*/
	/* match. return false.											*/
	FRET (OPC_FALSE);
	}
	
	
static Boolean			
arp_is_local_address (IpT_Address ip_address)
	{
	Boolean is_local_address;	
	/** This function checks if the specified address belongs to	**/
	/** to the physical interface or any of its subinterfaces of	**/
	/** the IP interface served by this ARP.						**/
	FIN (arp_is_local_address (ip_address));

	/* First check the interface on which this ARP resides.	Make sure that	*/
	/* the interface exists. If the address is "Auto-assigned" and the sim	*/
	/* is run in "Manually Addressed" mode, the interface will be NIL.		*/
	if (OPC_NIL == local_intf_ptr)
		{
		FRET (OPC_FALSE);
		}
	else
		{
		is_local_address = arp_is_local_address_on_interface (local_intf_ptr, ip_address);

		/* If this is a dual MSFC with an ALT interface, check the addresses	*/
		/* on that one too. Neighbor may be ARPing for an ALT address.			*/
		if ((!is_local_address) && (OPC_NIL != alt_intf_ptr))
			is_local_address = arp_is_local_address_on_interface (alt_intf_ptr, ip_address);
		}

	FRET (is_local_address);
	}

static void
ip_arp_error (const char *msg)
	{
	FIN (ip_arp_error (msg));

	op_sim_end ("Error in IP ARP process model (ip_arp_v4):",
		msg, OPC_NIL, OPC_NIL);

	FOUT;
	}

static void
ip_arp_warn (const char *msg)
	{
	FIN (ip_arp_warn (msg));

	op_sim_message ("Warning from IP ARP process model (ip_arp_v4):", msg);

	FOUT;
	}

static Boolean			
arp_is_local_virtual_address (IpT_Address ip_address, OpT_Int64* virtual_mac_addr_ptr)
	{
	HsrpT_Virtual_Addr_Info*			virtual_addr_info_ptr = OPC_NIL;
	int 								index = 0;
	InetT_Address						inet_ip_address;
	
	/** This function checks if the specified address belongs to	**/
	/** to the active virtual addresses configured for any HSRP		**/
	/** group on this interface										**/
	FIN (arp_is_local_virtual_address (ip_address));

	/* The following code is used to obtain the handle to list 			*/
	/* of virtual address info on this interface. This handle is		*/
	/* obtained just once for first packet and then reused for all		*/
	/* other packets. Once the handle is available check is done if		*/
	/* destinations mac address is there in the virtual address list	*/
	/* and if it is active. If active then this function returns TRUE	*/
	/* else FALSE.														*/
	
	/* Check if we already have the list of virtual addresses			*/
	if (hsrp_info_ptr == OPC_NIL)
		arp_hsrp_info_get ();
	
	/* Check for the validity of list									*/
	if ((hsrp_info_ptr == OPC_NIL) || (hsrp_info_ptr->num_groups <= 0))	
		FRET (OPC_FALSE);
	
	/* Loop through all the virtual IP addresses and see if there		*/
	/* is any match with active address									*/
	for (index = 0; index < hsrp_info_ptr->num_groups; index++)
		{
		/* Initialize Virtual address									*/
		virtual_addr_info_ptr = OPC_NIL;
		
		/* Get the next virtual address info ptr						*/
		virtual_addr_info_ptr = (HsrpT_Virtual_Addr_Info*) hsrp_info_ptr->virtual_addrs_array_ptr [index];
		
		/* Create an InetT_Address of the passed in IP Address			*/
		inet_ip_address =  inet_address_from_ipv4_address_create (ip_address);
		
		/* Match the IP Address with the Virtual IP address				*/
		if ((virtual_addr_info_ptr != OPC_NIL) &&
			(inet_address_equal(virtual_addr_info_ptr->virtual_ip_address,inet_ip_address)) &&
			(virtual_addr_info_ptr->addr_active	== OPC_TRUE))
			{
			*virtual_mac_addr_ptr = virtual_addr_info_ptr->virtual_mac_address;
			FRET (OPC_TRUE);
			}
		}
	
	FRET (OPC_FALSE);
	}

static void
arp_hsrp_info_get ()
	{
	List								proc_record_handle_list;
	int									record_handle_list_size;
	OmsT_Pr_Handle						process_record_handle;
	
	/* This function discovers HSRP and get HSRP information		*/
	FIN (arp_hsrp_info_get (<args>));
	
	/* In cases of user misconfiguration (no address on interface),	*/
	/* the local interface may be NIL. Handle this case.			*/
	if (OPC_NIL == local_intf_ptr)
		FOUT;

	/* Discover the HSRP process for this interface					*/
	op_prg_list_init (&proc_record_handle_list);
	oms_pr_process_discover (OPC_OBJID_INVALID, &proc_record_handle_list, 
								"protocol", 	OMSC_PR_STRING, 	"hsrp",
								"node id", 		OMSC_PR_OBJID, 		my_node_id,
								"iface name",	OMSC_PR_STRING,		ip_rte_intf_name_get (local_intf_ptr),
								OPC_NIL);
	
	/* Get the number of HSRP processes found						*/										
	record_handle_list_size = op_prg_list_size (&proc_record_handle_list);
	
	/* Do not process further if no HSRP is found					*/	
	if (record_handle_list_size == 0)
		FOUT;
		
	/* Get first process's record handle							*/
	process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (&proc_record_handle_list, OPC_LISTPOS_HEAD);
		
	/* Obtain the virtual addr list.			 					*/
	oms_pr_attr_get (process_record_handle, "HSRP Virtual Addr Info", OMSC_PR_POINTER, &hsrp_info_ptr);

	/* Deallocate the list pointer.								*/
	while (op_prg_list_size (&proc_record_handle_list) > 0)
		op_prg_list_remove (&proc_record_handle_list, OPC_LISTPOS_HEAD);
	
	FOUT;
	}

static void
arp_ipv6_nd_process_create (IpT_Rte_Module_Data* ip_module_data_ptr)
	{
	Ipv6T_Nd_Init_Info			ipv6_nd_init_info;
	int							subintf_index, num_subinterfaces;
	IpT_Interface_Info*			ith_subintf_info_ptr;

	/** If IPv6 is enabled on at least one subinterface, spawn the	**/
	/** the ipv6_nd child process.									**/

	FIN (arp_ipv6_nd_process_create (ip_module_data_ptr));

	/* Because of the way the IP interface table is set up, if IPv6	*/
	/* is enabled on at least one subinterface, it will be enabled	*/
	/* on the physical interface also.								*/
	if (ip_rte_intf_ipv6_active (local_intf_ptr))
		{
		/* Create the ipv6_nd process.								*/
		ipv6_nd_prohandle = op_pro_create ("ipv6_nd", OPC_NIL);

		/* Store the process handle in each subinterface.			*/
		num_subinterfaces = ip_rte_num_subinterfaces_get (local_intf_ptr);
		for (subintf_index = IPC_SUBINTF_PHYS_INTF; subintf_index < num_subinterfaces; subintf_index++)
			{
			/* Get a handle to the ith subinterface.				*/
			ith_subintf_info_ptr = ip_rte_ith_subintf_info_get (local_intf_ptr, subintf_index);

			/* Some parent interfaces (e.g for VLAN interfaces) may */
			/* not be IPv6 enabled. Check for this case.			*/
			if (OPC_NIL != 	ith_subintf_info_ptr->ipv6_info_ptr->nd_info_ptr)
				ith_subintf_info_ptr->ipv6_info_ptr->nd_info_ptr->nd_prohandle = ipv6_nd_prohandle;
			}

		/* Fill in the init info structure.							*/
		ipv6_nd_init_info.ip_module_data_ptr	= ip_module_data_ptr;
		ipv6_nd_init_info.phys_intf_info_ptr 	= local_intf_ptr;
		ipv6_nd_init_info.strm_to_ip			= outstrm_to_ip_rte;
		ipv6_nd_init_info.strm_to_mac			= outstrm_to_mac;
		ipv6_nd_init_info.mac_ici_ptr			= mac_iciptr;
		ipv6_nd_init_info.subintf_index_to_vlan_id_table = subintf_index_to_vlan_table;

		/* Invoke the ipv6_nd child process.						*/
		op_pro_invoke (ipv6_nd_prohandle, &ipv6_nd_init_info);
		}

	FOUT;
	}

static void
arp_packet_from_ip_handle (int intrpt_strm)
	{
	Packet*					pkptr;
	Ici*					iciptr;
	OpT_Int64				vmac_addr = -1;
	Boolean					is_arp_packet;
	InetT_Address*			inet_next_addr_ptr;
	IpT_Address				next_addr;
	int						subintf_index;
	IpT_Interface_Info*		ip_iface_elem_ptr;
	Ipv6T_Nd_Invoke_Info	ipv6_nd_invoke_info;
	OpT_Int64				phys_addr;
	IpT_Arp_Entry*			arp_entry_ptr;
	IpT_Arp_Entry*			debug_entry_ptr;
	int						cache_index;
	ArpT_Entry_Status		entry_status;

  //char		msg_string1 [256];
  //char		msg_string [256];
  char		addr_str [INETC_ADDR_STR_LEN];


	/**	Packet has arrived from the higher layer.		**/
	/**	Address mapping corresponding to next hop's		**/
	/**	IP address is obtained either from the global	**/
	/**	table or from the ARP cache depending upon the	**/
	/**	ARP sim efficiency mode's value and packet is 	**/
	/**	sent to the data link layer.					**/

	FIN (arp_packet_from_ip_handle (intrpt_strm));

	/* Obtain the packet and the accompanying ICI.	*/
	pkptr = op_pk_get (intrpt_strm);
	if (pkptr == OPC_NIL)
		ip_arp_error ("Unable to get packet from input stream.");
	iciptr = op_intrpt_ici ();  
	if (iciptr == OPC_NIL)
		ip_arp_error ("Unable to get ICI accompanying received packet.");

	/* Obtain the next node number.						*/
	if (op_ici_attr_get_ptr (iciptr, "next_addr", (void**) &inet_next_addr_ptr) == OPC_COMPCODE_FAILURE)
		{
		ip_arp_error ("Unable to get IP address of next hop from ICI.");
		}

	/*	Print diagnostic/trace information.				*/

/*
#ifndef OPD_NO_DEBUG
	if (ARPC_LTRACE_DATA_ACTIVE)
		{
*/
				/*	Generate message strings.					*/
		inet_address_print( addr_str, *inet_next_addr_ptr );
		
    /*
		sprintf( msg_string, "Packet ID: " SIMC_PK_ID_FMT " has arrived from higher layer", op_pk_id (pkptr) );
		sprintf( msg_string1,"and is destined for IP address %s.", addr_str);
    */

		printf( "Packet is destined for IP address %s", addr_str );
    op_ici_print( iciptr );

		/*	Print trace information.					*/
		//op_prg_odb_print_major (pid_string, msg_string, msg_string1, OPC_NIL);

    /*
		}
#endif
*/

	/* If the next hop address is an IPv6 address,	*/
	/* invoke the ipv6_nd process to handle the		*/
	/* packet.										*/
	if (InetC_Addr_Family_v6 == inet_address_family_get (inet_next_addr_ptr))
		{
		/* Fill in the invocation information.		*/
		ipv6_nd_invoke_info.invoke_reason 		= Ipv6C_Nd_Invoke_Reason_IP_Packet;
		ipv6_nd_invoke_info.packet_ptr			= pkptr;
		ipv6_nd_invoke_info.intrpt_ici_ptr		= iciptr;
		ipv6_nd_invoke_info.next_hop_addr_ptr	= inet_next_addr_ptr;

		/* Invoke the child to handle the packet	*/
		op_pro_invoke (ipv6_nd_prohandle, &ipv6_nd_invoke_info);

		/* There is nothing more to be done.		*/
		FOUT;
		}

	/*  Convert the next address to IpT_Address		*/
	next_addr = inet_ipv4_address_get (*inet_next_addr_ptr);

	/* Get the HSRP ICI fields and set them for next ICI*/
	/* Get the MAC address							*/
	op_ici_attr_get_int64 (iciptr, "src_mac_addr", &vmac_addr);

	/* If the Virtual MAC address is set then 		*/
	/* Also get HSRP info from the process registery*/
	/* and set it in the ICI						*/
	if (vmac_addr != -1)
		{
		/* Get the HSRP info						*/
		if (hsrp_info_ptr == OPC_NIL)
			arp_hsrp_info_get ();
		}
		
	/* Set the known information in ICI					*/
	/* If HSRP is not enabled, src_mac_addr will be -1	*/
	/* and hsrp_info_ptr will be OPC_NIL.				*/
	op_ici_attr_set_int64 (mac_iciptr, "src_mac_addr", vmac_addr);
	op_ici_attr_set_ptr (mac_iciptr, "hsrp_info", hsrp_info_ptr);

	/* Since this is a higher layer packet, it is not	*/
	/* an ARP packet.									*/
	is_arp_packet = OPC_FALSE;

	/* If the IP interface we are serving has 			*/
	/* subinterfaces configured, then obtain the index	*/
	/* of the subinterface via which the packet has 	*/
	/* arrived. This information is conveyed within the	*/
	/* ICI under "minor_port" field.					*/
	if (SUBINTERFACES_CONFIGURED)
		{
		if (op_ici_attr_get_int32 (iciptr, "minor_port", &subintf_index) == OPC_COMPCODE_FAILURE)
			ip_arp_error ("Unable to get minor port from ICI.");
		}
	else
		subintf_index = IPC_SUBINTF_PHYS_INTF;

	/* Get a handle to the specifed subinterface.		*/
	ip_iface_elem_ptr = ip_rte_ith_subintf_info_get (local_intf_ptr, subintf_index);

	/* If the next hop address is a broadcast or a		*/
	/* multicast address, broadcast the packet at the	*/
	/* MAC layer.										*/
  /*
	if ((ip_address_equal (next_addr, IpI_Broadcast_Addr)) ||
		(ip_address_is_multicast (next_addr)) ||
		(ip_rte_next_hop_address_is_broadcast_for_interface (next_addr, ip_iface_elem_ptr)))
		{
    */
    puts("ARP: Packet Sent!");
		arp_packet_send (is_arp_packet, pkptr, ARPC_BROADCAST_ADDR, subintf_index, outstrm_to_mac);

		/* Destroy the IP ICI if necessary.				*/
		ip_rte_arp_req_ici_destroy (iciptr);

		/* Nothing more to be done.						*/
		FOUT;
    /*
		}
    */

	/* The packet is a unicast packet.					*/

	/*	Determine if ARP sim efficiency mode is enabled.*/
	/*	If yes, Global IP table is used for obtaining 	*/
	/*	the physical address corresponding to the next	*/
	/*	hop's IP address.								*/
	if (arp_sim_eff)
		{
		/* 	Determine the corresponding physical address*/
		/*	corresponding to the IP address. 			*/
		if (OPC_COMPCODE_SUCCESS == arp_rtab_phys_addr_get (*inet_next_addr_ptr, &phys_addr))
			{
			/* 	The address translation was successful.	*/
			/* Send the packet coupled with the ICI. 	*/
      puts("ARP: Packet Sent");
			arp_packet_send (is_arp_packet, pkptr, phys_addr, subintf_index, outstrm_to_mac);
			}
		else
			{
			// If the address translation failed,
			// destroy the packet.						*
      puts("ARP: Packet Destroyed :(");
			op_pk_destroy (pkptr);
			}
		}
	else
		{
		/* ARP simulation efficiency is not enabled.	*/

		/* 	ARP sim efficiency mode is disabled. ARP	*/
		/*	cache is used for obtaining the physical 	*/
		/*	address corresponding to the next hop's IP 	*/
		/*	address.									*/

		/*	Print diagnostic/trace information.			*/
		if (ARPC_LTRACE_DATA_ACTIVE)
			{
			/*	Print trace information.				*/
			op_prg_odb_print_minor ("Searching ARP cache for a matching entry.", OPC_NIL);
			}
	
		/* 	Search through the ARP cache for the 		*/
		/*	matching entry corresponding to the			*/
		/*	next hop's IP address. 						*/
		if (OPC_COMPCODE_SUCCESS == arp_cache_entry_find (next_addr, &cache_index))
			{
			/* Obtain the handle for the entry.			*/
			arp_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, cache_index);
	
			/* Obtain the status of the entry.			*/
			entry_status = arp_entry_ptr->state;
	
			if ((entry_status == ArpC_Entry_Resolved) || (entry_status == ArpC_Entry_Permanent))
				{
				/*	Set the age of the resolved			*/
				/*	entry to maximum time-out.			*/
				if (entry_status != ArpC_Entry_Permanent)
					{
					arp_cache_entry_update (cache_index, ARPC_STATE_UPDATE_IGNORE, 
						ARPC_IP_ADDR_UPDATE_IGNORE, ARPC_PHYS_ADDR_UPDATE_IGNORE, max_age_timeout, 
						ARPC_ATTEMPTS_UPDATE_IGNORE, ARPC_QUEUE_UPDATE_IGNORE, ARPC_SUBINTF_INDEX_IGNORE);
					}
				if (ARPC_LTRACE_DATA_ACTIVE)
					{
					/*	Print trace information.		*/
					op_prg_odb_print_minor ( "Matching entry is found." ,
											 "Setting the age of the entry to max timeout.",
											 "Sending the pkt.", OPC_NIL);

					arp_cache_entry_print (arp_entry_ptr);
					}
					
				/* 	Obtain the physical address			*/	
				/*	from the arp entry.					*/
				phys_addr = arp_entry_ptr->phys_addr;
	
				/* 	set the physical layer address in the ICI	*/
				/*	and send the packet.						*/
				arp_packet_send (is_arp_packet, pkptr, phys_addr, subintf_index, outstrm_to_mac);
				}
			else
				{
				/* This is a pending entry. Therefore,	*/
				/* queue the packet. 					*/
				arp_cache_entry_update (cache_index, ARPC_STATE_UPDATE_IGNORE, 
						ARPC_IP_ADDR_UPDATE_IGNORE, ARPC_PHYS_ADDR_UPDATE_IGNORE,
						ARPC_AGE_UPDATE_IGNORE, ARPC_ATTEMPTS_UPDATE_IGNORE, pkptr, subintf_index);
	
				if (ARPC_LTRACE_DATA_ACTIVE)
					{
					/*	Print trace information.			*/
					op_prg_odb_print_minor ("Pending entry is found. Queueing the pkt.", OPC_NIL);
					arp_cache_entry_print (arp_entry_ptr);
					}
				}
			}
		else
			{
			/*	Address mapping corresponding to the next 	*/
			/*	hop's IP address is not found in the ARP 	*/
			/*	cache. Creates a new entry in the ARP cache.*/
			cache_index = arp_cache_entry_create ();

			/*	Call a function to update the newly created	*/
			/*	entry in the ARP cache.						*/
			arp_cache_entry_update (cache_index, ArpC_Entry_Pending, next_addr, 
					ARPC_PHYS_ADDR_UPDATE_IGNORE, wait_time, ARPC_ATTEMPTS_UPDATE, pkptr, subintf_index);

			if (ARPC_LTRACE_DATA_ACTIVE)
				{
				debug_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, cache_index);
				
				/*	Print trace information.			*/
				op_prg_odb_print_minor ("Matching entry is not found.",
									"Creating a new entry in the ARP cache.",
									"Broadcast an ARP request.", OPC_NIL);

				arp_cache_entry_print (debug_entry_ptr);
				}
	
			/* 	Broadcast an ARP request						*/
			arp_request_bcast (next_addr, subintf_index);
			}
		}

	/* Destroy the IP ICI if necessary.							*/
	ip_rte_arp_req_ici_destroy (iciptr);

  puts("ARP: Out of Packet");

	/* Return.		*/
	FOUT;
	}

static void
arp_packet_from_mac_handle (int intrpt_strm)
	{
	Packet*					pkptr;
	int						subintf_index;
	Boolean					pkt_drop;
	IpT_Arp_Entry*			arp_entry_ptr;
	Compcode				entry_index_found;
	int						cache_index;
	ArpT_Entry_Status		entry_status;
	OpT_Int64				virtual_mac_addr = -1;
	IpT_Address				src_protocol_addr;
	IpT_Address				dest_protocol_addr;
	OpT_Int64				src_hw_addr;
	OpT_Int64				dest_hw_addr;
	int						op_code;
	char					pk_format [128];

	/*	Packet has arrived from the lower layer. It is	*/
	/*	forwarded to the higher layer if it is an IP 	*/
	/*	datagram. If it is an ARP packet and ARP		*/
	/*  efficiency mode is disabled, the following		*/
	/*	operations are performed:						*/
	/*	1. 	Entry corresponding to the src IP address 	*/
	/*		in the ARP cache is updated if it exists.	*/
	/*	2.	If the ARP packet is destined for this node,*/
	/*		a new entry is created in the ARP cache for	*/
	/*		sender's IP address if it does not exist.	*/
	/*		Otherwise, enqueued packets, if any, are 	*/
	/*		sent.										*/
	/*	3.	If it is an ARP request, ARP reply is 		*/
	/*		created by interchanging the target and 	*/
	/*		sender address fields, supplying the 		*/
	/*		requested hardware address and changing the	*/
	/*		operation from REQUEST to REPLY.			*/
	FIN (arp_packet_from_mac_handle (intrpt_strm));

	/* Obtain the packet. 								*/
	pkptr = op_pk_get (intrpt_strm);
	if (pkptr == OPC_NIL)
		ip_arp_error ("Unable to get packet from lower layer input stream.");

	/* The packet is an LACP PDU, forward it to the		*/
	/* IP layer directly.								*/
	op_pk_format (pkptr, pk_format);
	if (strcmp (pk_format, "lac_pdu") == 0)
		{
		/* Send the packet to the IP layer and return.	*/
		op_pk_send (pkptr, outstrm_to_ip_rte);

		/* Return.	*/
		FOUT;
		}

	/* Get the index of the subinterface on which the	*/
	/* packet was received based on the VLAN ID			*/
	/* specified in the accompanying ICI.				*/
	subintf_index = arp_mac_pkt_subintf_index_get (pkptr, op_intrpt_ici (), &pkt_drop);

	/* If the packet was dropped, there is nothing		*/
	/* else that we need to do.							*/
	if (pkt_drop)
		{
		FOUT;
		}

	/*	Determine if ARP sim efficiency mode is 		*/
	/*	enabled. If enabled, packet is forwarded to the	*/
	/*	higher layer. This is because there is no 		*/
	/*	ARP traffic when this mode is used.				*/
	if (arp_sim_eff)
		{
		/* If this is as IPv6 ICMP packet forward it	*/
		/* the ipv6_nd child process.					*/
		arp_ip_packet_from_mac_handle (pkptr, subintf_index);
		}
	else
		{
		/* ARP efficiency is disabled. Send the packet	*/
		/* to the higher layer if it is not an ARP		*/
		/* packet.										*/
		if (strcmp (pk_format, "arp_v2") != 0)
			{
			/* This is not an ARP packet. Hence it must	*/
			/* be an IP packet.	Send it to IP.			*/
			arp_ip_packet_from_mac_handle (pkptr, subintf_index);
			}
		else
			{
			/*	Obtain the operation code from the 		*/
			/*	arp packet.								*/
			op_pk_nfd_get (pkptr, "arp opcode", &op_code);

			/*	Obtain the source IP and physical layer	*/
			/*	address from the packet.				*/
			op_pk_nfd_get (pkptr, "src hw addr", 		&src_hw_addr);
			op_pk_nfd_get (pkptr, "src protocol addr",	&src_protocol_addr);

			/* 	Obtain the destination IP address from	*/
			/*	the ARP packet.							*/
			op_pk_nfd_get (pkptr, "dest hw addr", 		&dest_hw_addr);
			op_pk_nfd_get (pkptr, "dest protocol addr", &dest_protocol_addr);

			/* 	Check ARP cache if matching entry is 	*/
			/*	found for the source IP address 		*/
			entry_index_found = arp_cache_entry_find (src_protocol_addr, &cache_index);

			/*	Check if matching entry is found.		*/
			if (entry_index_found == OPC_COMPCODE_SUCCESS)
				{
				/* Obtain the handle of the entry.		*/
				arp_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, cache_index);

				/* Obtain the status of the entry.			*/
				entry_status = arp_entry_ptr->state;

				/* 	Update the physical layer address and 	*/
				/*	age of the entry.						*/
				if (entry_status != ArpC_Entry_Permanent)
					{
					arp_cache_entry_update (cache_index, ARPC_STATE_UPDATE_IGNORE, 
						ARPC_IP_ADDR_UPDATE_IGNORE, src_hw_addr, max_age_timeout, 
						ARPC_ATTEMPTS_UPDATE_IGNORE, ARPC_QUEUE_UPDATE_IGNORE, ARPC_SUBINTF_INDEX_IGNORE);
					}
				}

			/* Initialize the virtual_mac_address			*/
			virtual_mac_addr = -1;

			/* 	Determine if destination IP address 		*/
			/*	matches this node's IP address.				*/
			if ((arp_is_local_address (dest_protocol_addr) == OPC_TRUE) ||
				(arp_is_local_virtual_address  (dest_protocol_addr, &virtual_mac_addr) == OPC_TRUE))
				{
				/* 	If the ARP entry corresponding to the 	*/
				/*	source IP address already exists in the	*/	
				/*	table then send the enqueued packets.	*/
				if (entry_index_found == OPC_COMPCODE_SUCCESS)
					{
					/* 	Determine whether the entry 		*/
					/*	corresponding to the source IP 		*/
					/*	address is resolved or pending.		*/
					if (entry_status == ArpC_Entry_Pending)
						{
						/* 	Set the status of the entry as 	*/
						/*	resolved and send the enqueued 	*/
						/*	packets if any.					*/
						arp_cache_entry_update (cache_index, ArpC_Entry_Resolved, ARPC_IP_ADDR_UPDATE_IGNORE,
							ARPC_PHYS_ADDR_UPDATE_IGNORE, ARPC_AGE_UPDATE_IGNORE, ARPC_ATTEMPTS_UPDATE_IGNORE,
							ARPC_QUEUE_UPDATE_IGNORE, ARPC_SUBINTF_INDEX_IGNORE);
						arp_enq_pkt_send (cache_index);
						}
					}
				else
					{
					/*	Create a new entry in ARP cache.	*/
					cache_index = arp_cache_entry_create ();
					
					/* 	Update the newly created entry in 	*/
					/*	the ARP cache corresponding to the 	*/
					/*	source address.						*/
					arp_cache_entry_update (cache_index, ArpC_Entry_Resolved, src_protocol_addr, src_hw_addr, max_age_timeout, 
						ARPC_ATTEMPTS_UPDATE_IGNORE, ARPC_QUEUE_UPDATE_IGNORE, ARPC_SUBINTF_INDEX_IGNORE);
					}

				/* Check if this is an ARP request or response.	*/
				if (op_code == ARPC_REQUEST)
					{
					/*	This is an ARP Request packet. Send a	*/
					/*	unicast reply.							*/
					arp_response_ucast (pkptr, src_hw_addr, src_protocol_addr, dest_protocol_addr, subintf_index, virtual_mac_addr);

					/*	Generate trace statements.				*/
#ifndef OPD_NO_DEBUG
					if (ARPC_LTRACE_DATA_ACTIVE)
						{
						char			addr_str [IPC_ADDR_STR_LEN];
						char			msg_string1 [256];
						IpT_Arp_Entry *	debug_entry_ptr;

						ip_address_print (addr_str, src_protocol_addr);
						
						/*	Generate a message string.			*/
						sprintf (msg_string1, "ARP request has been received from IP address %s.", addr_str);
												
						/*	Print trace information.			*/
						op_prg_odb_print_minor (msg_string1, 
							"Destination IP address from the ARP request matches",
							"this node's IP address.",
							"Sending an ARP reply.", OPC_NIL);

						debug_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, cache_index);
						arp_cache_entry_print (debug_entry_ptr);
						}
#endif
					}
				else
					{
					/* 	ARP reply has arrived. Cache entry is 	*/
					/*	already updated and the enqueued packet	*/
					/*	have also been sent. Discard the packet	*/
					op_pk_destroy (pkptr);
					
					/*	Generate trace/debugging message.		*/
#ifndef OPD_NO_DEBUG
					if (ARPC_LTRACE_DATA_ACTIVE)
						{
						char		addr_str [IPC_ADDR_STR_LEN];
						char		msg_string1 [256];

						/*	Generate a message string.			*/
						ip_address_print (addr_str, src_protocol_addr);
						sprintf (msg_string1, "ARP reply has been received from IP address %s.", addr_str);

						/*	Print trace information.			*/
						op_prg_odb_print_minor (msg_string1, "Sending enqueued packets.", OPC_NIL);
		
						arp_cache_entry_print (arp_entry_ptr);
						}
#endif
					/*	De-allocate memory associated with the	*/
					/*	source protocol address.				*/
					ip_address_destroy (src_protocol_addr);
					}
				}
			else
				{
				/* 	The incoming packet is not destined for 	*/
				/*	me. Destroy the packet.						*/ 
				op_pk_destroy (pkptr);

#ifndef OPD_NO_DEBUG
				if (ARPC_LTRACE_DATA_ACTIVE)
					{
					char				addr_str [IPC_ADDR_STR_LEN], my_addr_str [IPC_ADDR_STR_LEN];
					char				msg_string1 [256], msg_string2 [256];
					/*	Generate a message string.			*/
					ip_address_print (addr_str, src_protocol_addr);
					ip_address_print (my_addr_str, local_intf_ptr->addr_range_ptr->address);

					sprintf (msg_string1, "ARP request has been received from IP address (%s)", addr_str);
					sprintf (msg_string2, "match this node's IP address (%s).", my_addr_str);

					/*	Print trace information.			*/
					op_prg_odb_print_minor (msg_string1,
						"Destination IP address from the ARP request does not",
						msg_string2, OPC_NIL);
					}
#endif
				}
			}
		}

	FOUT;
	}

static void
arp_ip_packet_from_mac_handle (Packet* pkptr, int subintf_index)
	{
	Ici*					ip_iciptr;
	Ipv6T_Nd_Invoke_Info	ipv6_nd_invoke_info;
	const IpT_Dgram_Fields*	ip_dgram_fd_ptr;
	
	/** An IP packet has been received from the MAC layer	**/
	/** If it is an IPv6 ICMP Packet, forward it to the		**/
	/** ipv6_nd child process. Otherwise forward it to the	**/
	/** IP layer directly.									**/

	FIN (arp_ip_packet_from_mac_handle (pkptr, subintf_index));

	/* Make sure that the packet has been received at		*/
	/* a valid active interface. If this interface is		*/
	/* a shutdown interface then "local_intf_ptr" will		*/
	/* be invalid. In this case the packet should simply	*/
	/* be destroyed 										*/
	if (local_intf_ptr == OPC_NIL)
		{
		/* Destroy the packet and fout						*/	
		op_pk_destroy (pkptr);
		FOUT;
		}

	/* Access the IP header of the packet.					*/
	ip_dgram_fd_ptr = ip_dgram_fields_access_read_only (pkptr);
	
	/* Check if IPv6 is enabled on this interface. First,	*/
	/* make sure that the packet is an IP datagram, since	*/
	/* we may also receive unformatted packets if there		*/
	/* station nodes in the network.						*/
	if (ip_dgram_fd_ptr != OPC_NIL)
		{
		if (ip_rte_intf_ipv6_active (local_intf_ptr))
			{
			/* IPv6 ICMP (ICMPv6) packets must be forwarded	*/
			/* to the IPv6 neighbor discovery process.		*/
			if (IpC_Protocol_Icmpv6 == ip_dgram_fd_ptr->protocol)
				{
				/* Fill in the invocation information.		*/
				ipv6_nd_invoke_info.invoke_reason	= Ipv6C_Nd_Invoke_Reason_MAC_Packet;
				ipv6_nd_invoke_info.packet_ptr		= pkptr;
				ipv6_nd_invoke_info.subintf_index	= subintf_index;

				/* Invoke the child.						*/
				op_pro_invoke (ipv6_nd_prohandle, &ipv6_nd_invoke_info);

				/* Nothing more to be done. Return.			*/
				FOUT;
				}
			}
		else
			{		
			/* If this interface is IPv6 not active, and if	*/
			/* the packet is IPv6 sink the packet here, on	*/
			/* grounds that an IPv6 packet cannot be		*/
			/* received by an inactive IPv6 interface. 		*/
			if (InetC_Addr_Family_v6 == inet_address_family_get (&(ip_dgram_fd_ptr->dest_addr)))
				{
				/* 6PE: Allow packets riding on LSPs.		*/
				if (!op_pk_nfd_is_set (pkptr, "MPLS Shim Header"))
					{
					op_pk_destroy (pkptr);
					FOUT; 
					}
				}
			}
		}

	/* Forward the packet to the IP module.					*/
	/* If there is any subinterface information to report,	*/
	/* send this within the ICI associated with the			*/
	/* interrupt as "minor port".							*/
	if (subintf_index != ARPC_UNDEF_SUBINTF_INDEX)
		{
		/* Create and install the ICI. The ICI will be		*/
		/* destroyed by the IP.								*/
		ip_iciptr = op_ici_create ("ip_arp_ind_v4");
		op_ici_attr_set_int32 (ip_iciptr, "minor_port", subintf_index);
		op_ici_install (ip_iciptr);
		}

	/* Send the packet to IP.								*/
	op_pk_send (pkptr, outstrm_to_ip_rte);

	/* Deinstall the ICI in case installed.					*/
	op_ici_install (OPC_NIL);

	/* Print a trace message.								*/
#ifndef OPD_NO_DEBUG
	if (ARPC_LTRACE_DATA_ACTIVE)
		{
		char		msg_string1 [256];
		char		arp_packet_format [64];

		/*	Generate a message string.						*/
		op_pk_format (pkptr, arp_packet_format);
		sprintf (msg_string1, "Packet of format (%s) has arrived.", arp_packet_format);

		/*	Print trace information.						*/
		op_prg_odb_print_minor (msg_string1, "Sending it to the higher layer.", OPC_NIL);
		}
#endif

	/* Return.		*/
	FOUT;
	}


static int
arp_mac_pkt_subintf_index_get (Packet* pkptr, Ici* iciptr, Boolean* pkt_drop_ptr)
	{
	int					subintf_index;
	Boolean				untagged_packet = OPC_FALSE;
	int					pkt_vid;

	/* Check whether the arriving MAC packet has a VLAN	*/
	/* classification conveyed within the ICI			*/
	/* associated with the stream interrupt. If this is	*/
	/* the case, then we need to determine the			*/
	/* subinterface of this arrival by using this VLAN	*/
	/* information and report it to the IP as "minor	*/
	/* port" when we forward the packet. Start with		*/

	FIN (arp_mac_pkt_subintf_index_get (mac_ici_ptr, pkt_drop_ptr));

	/* Initialize the subinterface index to an invalid	*/
	/* value.											*/
	subintf_index = ARPC_UNDEF_SUBINTF_INDEX;

	/* Initialize the pkt_drop flag to false.			*/
	*pkt_drop_ptr = OPC_FALSE;

	/* First check whether there is any VLANs			*/
	/* associated with the subinterfaces served by this	*/
	/* ARP.												*/
	if (supported_vlan_count > 0) 
		{
		/* Make sure that we have an ICI and that it	*/
		/* has a field named vlan_id.					*/
		if ((iciptr != OPC_NIL) &&
			(op_ici_attr_exists (iciptr, "vlan_id") == OPC_TRUE))
			{
			/* The ICI exists, and has VLAN information	*/
			/* Retrieve the VLAN information.		*/
			op_ici_attr_get_int32 (iciptr, "vlan_id", &pkt_vid);
		
			/* If the packet is untagged, assume that	*/
			/* it belongs to VLAN 1.					*/
			if (OMSC_VLAN_NULL_VID == pkt_vid)
				{
				pkt_vid = 1;

				/* Set the flag indicating that the		*/
				/* packet was untagged.					*/
				untagged_packet = OPC_TRUE;
				}

			/* Figure out the subinterface of arrival	*/
			/* using this VLAN information.				*/
			subintf_index = arp_subintf_index_from_vid_obtain (pkt_vid);

			/* If a matching subinterface was not found,*/
			/* the packet must be dropped. If the packet*/
			/* was untagged, don't drop it. Let IP take	*/
			/* care of it.								*/
			if ((subintf_index == ARPC_UNDEF_SUBINTF_INDEX) &&
				(! untagged_packet))
				{
				/* Set the flag to indicate that the*/
				/* packet should be dropped	and		*/
				/* destroy the packet.				*/
				*pkt_drop_ptr = OPC_TRUE;

				/* Write a log message.				*/
				ipnl_unmappable_vlan_pkt_drop_log_write 
					(my_node_id, ip_rte_intf_name_get (local_intf_ptr), pkt_vid, pkptr);
				op_pk_destroy (pkptr);
				}
			}
		}

	/* Return the subinterface index.					*/
	FRET (subintf_index);
	}

static void
arp_timer_expiry_handle (void)
	{
	int						i, arp_tbl_size;
	IpT_Arp_Entry *			arp_entry_ptr;
	ArpT_Entry_Status		entry_status;
	IpT_Arp_Queue_Entity*	queue_entity_ptr;
	IpT_Address				dest_protocol_addr;

	/*	An ARP timer has expired. Iterate through 	*/
	/*	each entry in the ARP cache and decrement	*/
	/*	the age of the entry by "arp_gran".			*/
	/*	If the age becomes zero or negative,		*/
	/*	remove the entry from the ARP cache. If		*/
	/*	the age expires on a entry that is pending	*/	
	/*	resolution, an ARP request is re-broadcast	*/
	/*	if the request has not already been for a	*/
	/*	ceratin maximum number of times. If the		*/
	/*	request been rebroadcast for the maximum	*/
	/*	allowable count, then the entry is deleted 	*/
	/*	from the ARP cache.							*/

	FIN (arp_timer_expiry_handle (void));

	/* Obtain the size of the ARP table				*/
	arp_tbl_size = op_prg_list_size (arp_cache_lptr);

	/* 	Loop through all the entries in the ARP 	*/
	/*	cache and delete aged entries.				*/
	for (i = 0; i < arp_tbl_size; i++)
		{
		/* Obtain the handle of the ARP entry.		*/
		arp_entry_ptr = (IpT_Arp_Entry *) op_prg_list_access (arp_cache_lptr, i);

		/*	Obtain the status of this entry.		*/
		entry_status = arp_entry_ptr->state;

		/*	Perform aging operation depending the	*/
		/*	status of the entry.					*/
		switch (entry_status)
			{
			case ArpC_Entry_Permanent:
				{
				/*	Since this entry is permanent,	*/
				/*	it cannot be "aged". Check the	*/
				/*	next available entry, if any.	*/
				/*	Currently, an ARP entry cannot	*/
				/*	be set to "permanent".			*/
				break;
				}

			case ArpC_Entry_Resolved:
				{
				/* 	Decrement the age of the entry	*/
				/*	by "arp_gran".					*/
				arp_entry_ptr->age = arp_entry_ptr->age - arp_gran;
				
				/* 	Delete the entry if the age of	*/
				/*	the entry is less than or equal	*/
				/*	to zero. This condition means	*/
				/*	that the the entry is too old.	*/
				if (arp_entry_ptr->age <= 0)
					{
					arp_cache_entry_delete (i);
					arp_tbl_size --;
					i--;
					}

				break;
				}

			case ArpC_Entry_Pending:
				{
				/* 	Decrement the age of the entry.	*/
				arp_entry_ptr->age = arp_entry_ptr->age - arp_gran;

				/*	Check the "age" of the entry.	*/
				if (arp_entry_ptr->age <= 0)
					{
					/* 	This indicates that the age	*/
					/*	of the entry has expired.	*/
					/* 	Examine num_attempts field	*/
					/*	of this entry. This field	*/
					/*	tracks the number of times	*/
					/*	an ARP request has been		*/
					/*	broadcast.					*/
					if (arp_entry_ptr->num_attempts < arpreq_max_retry)
						{
						/*	Obtain the destination 	*/
						/*	IP address.				*/
						dest_protocol_addr = arp_entry_ptr->ip_addr;

						/* 	Broadcast the ARP request. Use the	*/
						/*  subinterface index of the first		*/
						/*  entry in the queue.					*/
						queue_entity_ptr = (IpT_Arp_Queue_Entity *) op_prg_list_access (arp_entry_ptr->queue, OPC_LISTPOS_HEAD);
						arp_request_bcast (dest_protocol_addr, queue_entity_ptr->subintf_index);

						/* Update the age and num_attempts		*/
						/* fields of the entry.					*/	
						arp_cache_entry_update (i, ARPC_STATE_UPDATE_IGNORE, ARPC_IP_ADDR_UPDATE_IGNORE, ARPC_PHYS_ADDR_UPDATE_IGNORE, 
							wait_time, ARPC_ATTEMPTS_UPDATE, ARPC_QUEUE_UPDATE_IGNORE, ARPC_SUBINTF_INDEX_IGNORE);
						}
					else 
						{
						/* 	Delete the entry from the table and */
						/*	give an error message that this 	*/
						/*	address can not be reached 			*/
						arp_cache_entry_delete (i);
						arp_tbl_size --;
						i--;
							
						/*	Print a warning message to indicate this.	*/
#ifndef OPD_NO_DEBUG
						if (ARPC_LTRACE_DATA_ACTIVE)
							{
							char	addr_str [IPC_ADDR_STR_LEN];
							char	msg_string [256];

							ip_address_print (addr_str, arp_entry_ptr->ip_addr);
							sprintf (msg_string, "IP address (%s) can not be reached.", addr_str);
							ip_arp_warn (msg_string);
							}
#endif
						}
					}
				break;
				}
			default:
				{
				break;
				}
			}
		}

	if (ARPC_LTRACE_TIMER_ACTIVE)
		{
		op_prg_odb_print_minor ("Status of ARP cache after aging out the entries\n", OPC_NIL);
		arp_cache_print ();
		}
					
	/*	Schedule the self interrupt 						*/
	op_intrpt_schedule_self ((op_sim_time () + arp_gran), 0);

	FOUT;
	}


static void
ip_arp_intf_lower_layer_type_set (IpT_Interface_Info* intf_ptr, OpT_Int64 lower_layer_address)
	{
	/** Set the lower layer address and type in the IP Interface information.	**/
	FIN (ip_arp_intf_lower_layer_type_set (intf_ptr, lower_layer_address));

	/* Store the lower layer address information for this interface		*/
	if ((intf_ptr != OPC_NIL) && (intf_ptr->phys_intf_info_ptr != OPC_NIL))
		intf_ptr->phys_intf_info_ptr->lower_layer_addr = lower_layer_address;
	
	/* The type is also being stored in the interface object.	*/
	intf_ptr->phys_intf_info_ptr->lower_layer_type = (OpT_Int8) IpC_Intf_Lower_Layer_LAN;

	FOUT;
	}

/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

#if defined (__cplusplus)
extern "C" {
#endif
	void ip_arp_v4_2 (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_ip_arp_v4_2_init (int * init_block_ptr);
	void _op_ip_arp_v4_2_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_ip_arp_v4_2_terminate (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Address _op_ip_arp_v4_2_alloc (VosT_Obtype, int);
	void _op_ip_arp_v4_2_svar (void *, const char *, void **);


#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
ip_arp_v4_2 (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (ip_arp_v4_2 ());

		{
		/* Temporary Variables */
		int					intrpt_type = OPC_INT_UNDEF;
		int					intrpt_strm = OPC_INT_UNDEF;
		/* End of Temporary Variables */


		FSM_ENTER ("ip_arp_v4_2")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (INIT) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "INIT", "ip_arp_v4_2 [INIT enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [INIT enter execs]", state0_enter_exec)
				{
				/* Obtain the object ID of the surrounding ARP processor. 	*/
				my_id = op_id_self ();
				
				/* Also obtain the object ID of the surrounding node.		*/
				my_node_id = op_topo_parent (my_id);
				
				/* Obtain the prohandle for this process.					*/
				own_prohandle = op_pro_self ();
				
				/*	Obtain the name of the process. It is the process model	*/
				/*	attribute on the surrounding module.					*/
				op_ima_obj_attr_get (my_id, "process model", proc_model_name);
				
				/**	Register the process in the model-wide registry.				**/
				own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register 
					(my_node_id, my_id, own_prohandle, proc_model_name);
				
				/*	Register the protocol attribute in the registry. No other	*/
				/*	process should use the string "arp" as the value for its	*/
				/*	"protocol" attribute!										*/
				oms_pr_attr_set (own_process_record_handle, 
					"protocol", 	OMSC_PR_STRING, 	"arp",
					"location", 	OMSC_PR_STRING, 	"mac_if", 
					OPC_NIL);
				
				/* 	Schedule a self interrupt to allow the lower layer		*/
				/*	modules (MACs) and the higher IP module to get 			*/
				/*	their addresses assigned. 				*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				/* Create an ICI to communicate with data link layer. 		*/
				mac_iciptr = op_ici_create ("ip_mac_req");
				if (mac_iciptr == OPC_NIL)
					ip_arp_error ("Unable to create ICI to communicate with data link layer.");
				
				/*	Initialize the state variable used to keep track of the	*/
				/*	ARP module object ID and to generate trace/debugging 	*/
				/*	string information. Obtain process ID of this process. 	*/
				my_pro_id = op_pro_id (op_pro_self ());
				
				/* 	Set the process ID string, to be later used for trace	*/
				/*	and debugging information.								*/
				sprintf (pid_string, "ARP PID (%d)", my_pro_id);
				
				/* Initialize the HSRP Virtual Address Info pointer			*/
				hsrp_info_ptr	= OPC_NIL;
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"ip_arp_v4_2")


			/** state (INIT) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "INIT", "ip_arp_v4_2 [INIT exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [INIT exit execs]", state0_exit_exec)
				{
				/* Block specific variables.								*/
				Objid			arp_parameter_comp_objid, arp_parameter_objid;
				
				/*	Determine if ARP simulation efficiency mode is used.	*/
				/* 	If yes, Global Cache table is constructed using process	*/
				/*	registry and ARP traffic is not modeled. Otherwise,		*/
				/*	ARP traffic is modeled and separate cache is constructed*/
				/* 	for each network interface. Obtain the value of the 	*/
				/*  simulation attribute only if specified.					*/
				
				/*  The function below will return FALSE if it detects 		*/
				/*  a SITL gateway in the network.							*/
				arp_sim_eff = ip_arp_sim_eff_sim_attr_get (OPC_FALSE);
				
				
				if (! arp_sim_eff)
					{
					/*	Create the ARP cache.								*/					
					arp_cache_lptr = op_prg_list_create ();
				
				    /* Obtain the objid of compound attibute which stores all the "ARP Parametera"  */
				    op_ima_obj_attr_get (my_id, "ARP Parameters", &arp_parameter_comp_objid);
				    arp_parameter_objid = op_topo_child (arp_parameter_comp_objid, OPC_OBJTYPE_GENERIC, 0);
				
					/*	Obtain the maximum size of the ARP cache.			*/
					op_ima_obj_attr_get (arp_parameter_objid, "Cache Size", &cache_max_size);
				
					/*	Obtain the timeout interval the sender waits for 	*/
					/*	an ARP response.									*/
					op_ima_obj_attr_get (arp_parameter_objid, "Response Wait Time", &wait_time);
				
					/*	Obtain the maximum number of times a sender retries	*/
					/*	a request.											*/
					op_ima_obj_attr_get (arp_parameter_objid, "Request Retry Limit", &arpreq_max_retry);
				
					/*	Obtain maximum age timeout for a cache entry.		*/
					op_ima_obj_attr_get (arp_parameter_objid, "Age Timeout", &max_age_timeout);
				
					/*	Obtain the maximum size of the packet 				*/
					/*	retransmission queue associated with each 			*/
					/*	cache entry.										*/
					op_ima_obj_attr_get (arp_parameter_objid, "Maximum Queue Size", &max_queue_size);
				
					/*	Obtain time interval between iterations for 		*/
					/*	deleting the aged entries from the ARP cache.		*/
					op_ima_obj_attr_get (arp_parameter_objid, "Timer Granularity", &arp_gran);
					}
				
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (INIT) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 3, state3_enter_exec, ;, INIT, "SELF_NOTIF", "", "INIT", "wait", "tr_35", "ip_arp_v4_2 [INIT -> wait : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (WAIT) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "WAIT", state1_enter_exec, "ip_arp_v4_2 [WAIT enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [WAIT enter execs]", state1_enter_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"ip_arp_v4_2")


			/** state (WAIT) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "WAIT", "ip_arp_v4_2 [WAIT exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [WAIT exit execs]", state1_exit_exec)
				{
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (WAIT) transition processing **/
			FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [WAIT trans conditions]", state1_trans_conds)
			FSM_INIT_COND (IP_ARRIVAL)
			FSM_TEST_COND (DLL_ARRIVAL)
			FSM_TEST_COND (TIMER_EXP)
			FSM_TEST_COND (NODE_FAILREC)
			FSM_TEST_COND (UNKNOWN_PACKET)
			FSM_TEST_LOGIC ("WAIT")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 1, state1_enter_exec, IP_PACKET_HANDLE;, "IP_ARRIVAL", "IP_PACKET_HANDLE", "WAIT", "WAIT", "tr_9", "ip_arp_v4_2 [WAIT -> WAIT : IP_ARRIVAL / IP_PACKET_HANDLE]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, MAC_PACKET_HANDLE;, "DLL_ARRIVAL", "MAC_PACKET_HANDLE", "WAIT", "WAIT", "tr_10", "ip_arp_v4_2 [WAIT -> WAIT : DLL_ARRIVAL / MAC_PACKET_HANDLE]")
				FSM_CASE_TRANSIT (2, 1, state1_enter_exec, ARP_TIMER_HANDLE;, "TIMER_EXP", "ARP_TIMER_HANDLE", "WAIT", "WAIT", "tr_11", "ip_arp_v4_2 [WAIT -> WAIT : TIMER_EXP / ARP_TIMER_HANDLE]")
				FSM_CASE_TRANSIT (3, 1, state1_enter_exec, IPv6_ND_INVOKE;, "NODE_FAILREC", "IPv6_ND_INVOKE", "WAIT", "WAIT", "tr_6", "ip_arp_v4_2 [WAIT -> WAIT : NODE_FAILREC / IPv6_ND_INVOKE]")
				FSM_CASE_TRANSIT (4, 1, state1_enter_exec, DROP_PACKET;, "UNKNOWN_PACKET", "DROP_PACKET", "WAIT", "WAIT", "tr_12", "ip_arp_v4_2 [WAIT -> WAIT : UNKNOWN_PACKET / DROP_PACKET]")
				}
				/*---------------------------------------------------------*/



			/** state (arp_table) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "arp_table", state2_enter_exec, "ip_arp_v4_2 [arp_table enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [arp_table enter execs]", state2_enter_exec)
				{
				/* Schedule another self interrupt for this process to allow
				the lower modules and IP to register their addresses into the model-wide
				registry. */
				op_intrpt_schedule_self (op_sim_time (), 0); 
				
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"ip_arp_v4_2")


			/** state (arp_table) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "arp_table", "ip_arp_v4_2 [arp_table exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [arp_table exit execs]", state2_exit_exec)
				{
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				
				/* Initialize the ARP package.		*/
				arp_init ();
				}
				FSM_PROFILE_SECTION_OUT (state2_exit_exec)


			/** state (arp_table) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 1, state1_enter_exec, ;, arp_table, "SELF_NOTIF", "", "arp_table", "WAIT", "tr_18", "ip_arp_v4_2 [arp_table -> WAIT : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (wait) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "wait", state3_enter_exec, "ip_arp_v4_2 [wait enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait enter execs]", state3_enter_exec)
				{
				/* It takes the completion of two self interrupts (from BEGSIM) for IP to	*/
				/* complete building its IP interface table. There is nothing to be done	*/
				/* at this stage. Schedule a self interrupt and move on.					*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"ip_arp_v4_2")


			/** state (wait) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "wait", "ip_arp_v4_2 [wait exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait exit execs]", state3_exit_exec)
				{
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (wait) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 4, state4_enter_exec, ;, wait, "SELF_NOTIF", "", "wait", "wait_0", "tr_57", "ip_arp_v4_2 [wait -> wait_0 : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (wait_0) enter executives **/
			FSM_STATE_ENTER_UNFORCED (4, "wait_0", state4_enter_exec, "ip_arp_v4_2 [wait_0 enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait_0 enter execs]", state4_enter_exec)
				{
				/* It takes the completion of two self interrupts (from BEGSIM) for IP to	*/
				/* complete building its IP interface table. There is nothing to be done	*/
				/* at this stage. Schedule a self interrupt and move on.					*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (9,"ip_arp_v4_2")


			/** state (wait_0) exit executives **/
			FSM_STATE_EXIT_UNFORCED (4, "wait_0", "ip_arp_v4_2 [wait_0 exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait_0 exit execs]", state4_exit_exec)
				{
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (wait_0) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 5, state5_enter_exec, ;, wait_0, "SELF_NOTIF", "", "wait_0", "wait_1", "tr_58", "ip_arp_v4_2 [wait_0 -> wait_1 : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (wait_1) enter executives **/
			FSM_STATE_ENTER_UNFORCED (5, "wait_1", state5_enter_exec, "ip_arp_v4_2 [wait_1 enter execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait_1 enter execs]", state5_enter_exec)
				{
				/* It takes the completion of two self interrupts (from BEGSIM) for IP to	*/
				/* complete building its IP interface table. There is nothing to be done	*/
				/* at this stage. Schedule a self interrupt and move on.					*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (11,"ip_arp_v4_2")


			/** state (wait_1) exit executives **/
			FSM_STATE_EXIT_UNFORCED (5, "wait_1", "ip_arp_v4_2 [wait_1 exit execs]")
				FSM_PROFILE_SECTION_IN ("ip_arp_v4_2 [wait_1 exit execs]", state5_exit_exec)
				{
				/* Obtain interrupt parameters.	*/
				intrpt_type = op_intrpt_type ();
				if (intrpt_type == OPC_INTRPT_STRM)
					{
					intrpt_strm = op_intrpt_strm ();
					}
				}
				FSM_PROFILE_SECTION_OUT (state5_exit_exec)


			/** state (wait_1) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 2, state2_enter_exec, ;, wait_1, "SELF_NOTIF", "", "wait_1", "arp_table", "tr_59", "ip_arp_v4_2 [wait_1 -> arp_table : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"ip_arp_v4_2")
		}
	}




void
_op_ip_arp_v4_2_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
#if defined (OPD_ALLOW_ODB)
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__+1;
#endif

	FIN_MT (_op_ip_arp_v4_2_diag ())

	if (1)
		{

		/* Diagnostic Block */

		BINIT
		{
		char				str0 [512], str1 [512];
		char				my_addr_str [IPC_ADDR_STR_LEN];
		
		/*	Print out the address of the interface on which	*/
		/*	this ARP module is attached.					*/
		printf ("\n\n    Information on ARP module for: \n");
		printf ("  =================================\n");
		
		/*	Print the name of the surrounding node.			*/
		op_ima_obj_attr_get (op_topo_parent (my_id), "name", str0);
		op_ima_obj_attr_get (op_topo_parent (op_topo_parent (my_id)), "name", str1);
		printf ("\n                 Node Name:   %s\n", str0);
		printf ("               Subnet Name:   %s\n", str1);
		
		/*	Print IP interface information. First check		*/
		/*  whether the interface is used.					*/
		if (local_intf_ptr == OPC_NIL)
			printf ("      Interface IP Address:   N/A (not connected)\n");
		else
			{
			ip_address_print (my_addr_str, local_intf_ptr->addr_range_ptr->address);
			printf ("      Interface IP Address:   %s\n", my_addr_str);
			}
		
		/* Print the physical layer address.				*/
		printf ("    Physical Layer Address:   " OPC_INT64_FMT "\n\n", hardware_addr);
		
		/*	Print the ARP cache entries.					*/
		if (! arp_sim_eff)
			arp_cache_print ();
		}

		/* End of Diagnostic Block */

		}

	FOUT
#endif /* OPD_ALLOW_ODB */
	}




void
_op_ip_arp_v4_2_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{

	FIN_MT (_op_ip_arp_v4_2_terminate ())


	/* No Termination Block */

	Vos_Poolmem_Dealloc (op_sv_ptr);

	FOUT
	}


/* Undefine shortcuts to state variables to avoid */
/* syntax error in direct access to fields of */
/* local variable prs_ptr in _op_ip_arp_v4_2_svar function. */
#undef my_id
#undef my_node_id
#undef proc_model_name
#undef own_prohandle
#undef own_process_record_handle
#undef mac_iciptr
#undef local_intf_ptr
#undef vlan_to_subintf_index_table
#undef subintf_index_to_vlan_table
#undef supported_vlan_count
#undef arp_sim_eff
#undef cache_max_size
#undef arp_gran
#undef wait_time
#undef max_age_timeout
#undef arpreq_max_retry
#undef max_queue_size
#undef arp_cache_lptr
#undef hardware_addr
#undef instrm_from_ip_rte
#undef outstrm_to_ip_rte
#undef instrm_from_mac
#undef outstrm_to_mac
#undef pid_string
#undef my_pro_id
#undef hsrp_info_ptr
#undef ipv6_nd_prohandle
#undef alt_intf_ptr

#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_ip_arp_v4_2_init (int * init_block_ptr)
	{
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_ip_arp_v4_2_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (ip_arp_v4_2)",
		sizeof (ip_arp_v4_2_state));
	*init_block_ptr = 0;

	FRET (obtype)
	}

VosT_Address
_op_ip_arp_v4_2_alloc (VosT_Obtype obtype, int init_block)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	ip_arp_v4_2_state * ptr;
	FIN_MT (_op_ip_arp_v4_2_alloc (obtype))

	ptr = (ip_arp_v4_2_state *)Vos_Alloc_Object (obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "ip_arp_v4_2 [INIT enter execs]";
#endif
		}
	FRET ((VosT_Address)ptr)
	}



void
_op_ip_arp_v4_2_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	ip_arp_v4_2_state		*prs_ptr;

	FIN_MT (_op_ip_arp_v4_2_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (ip_arp_v4_2_state *)gen_ptr;

	if (strcmp ("my_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_id);
		FOUT
		}
	if (strcmp ("my_node_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_node_id);
		FOUT
		}
	if (strcmp ("proc_model_name" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->proc_model_name);
		FOUT
		}
	if (strcmp ("own_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_prohandle);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("mac_iciptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->mac_iciptr);
		FOUT
		}
	if (strcmp ("local_intf_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_intf_ptr);
		FOUT
		}
	if (strcmp ("vlan_to_subintf_index_table" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->vlan_to_subintf_index_table);
		FOUT
		}
	if (strcmp ("subintf_index_to_vlan_table" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->subintf_index_to_vlan_table);
		FOUT
		}
	if (strcmp ("supported_vlan_count" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->supported_vlan_count);
		FOUT
		}
	if (strcmp ("arp_sim_eff" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->arp_sim_eff);
		FOUT
		}
	if (strcmp ("cache_max_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cache_max_size);
		FOUT
		}
	if (strcmp ("arp_gran" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->arp_gran);
		FOUT
		}
	if (strcmp ("wait_time" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->wait_time);
		FOUT
		}
	if (strcmp ("max_age_timeout" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->max_age_timeout);
		FOUT
		}
	if (strcmp ("arpreq_max_retry" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->arpreq_max_retry);
		FOUT
		}
	if (strcmp ("max_queue_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->max_queue_size);
		FOUT
		}
	if (strcmp ("arp_cache_lptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->arp_cache_lptr);
		FOUT
		}
	if (strcmp ("hardware_addr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->hardware_addr);
		FOUT
		}
	if (strcmp ("instrm_from_ip_rte" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->instrm_from_ip_rte);
		FOUT
		}
	if (strcmp ("outstrm_to_ip_rte" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outstrm_to_ip_rte);
		FOUT
		}
	if (strcmp ("instrm_from_mac" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->instrm_from_mac);
		FOUT
		}
	if (strcmp ("outstrm_to_mac" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outstrm_to_mac);
		FOUT
		}
	if (strcmp ("pid_string" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->pid_string);
		FOUT
		}
	if (strcmp ("my_pro_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_pro_id);
		FOUT
		}
	if (strcmp ("hsrp_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->hsrp_info_ptr);
		FOUT
		}
	if (strcmp ("ipv6_nd_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ipv6_nd_prohandle);
		FOUT
		}
	if (strcmp ("alt_intf_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->alt_intf_ptr);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

