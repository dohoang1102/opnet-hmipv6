/* mobile_ip_support.ex.c */
/* mobile ip related functions. */

/****************************************/
/* 	     Copyright (c) 1987-2008    	*/
/*		by OPNET Technologies, Inc.		*/
/*		(A Delaware Corporation)		*/
/*	7255 Woodmont Av., Suite 250  		*/
/*     Bethesda, MD 20814, U.S.A.       */
/*			All Rights Reserved.		*/
/****************************************/

#include	"opnet.h"
#include	"mobile_ip_support.h"
#include	"ip_rte_support.h"
#include	"oms_tan.h"
#include	"ip_higher_layer_proto_reg_sup.h"
#include	<math.h>

#define		MipC_Tunnel_Circle_Radius_Outer	5
#define		MipC_Tunnel_Circle_Radius_Inner	2
#define		MipC_Tunnel_Outer_Color		OPC_ANIM_COLOR_RGB221
#define		MipC_Tunnel_Inner_Color		OPC_ANIM_COLOR_RGB123
#define		MipC_Anime_Legend_Position_X	30
#define		MipC_Anime_Legend_Position_Y	30
#define		MipC_Anime_Legend_Position_W	150
#define		MipC_Anime_Legend_Position_H	80

/* Global for animation. */
Anvid	MipI_Anvid = OPC_ANIM_ID_NIL;
Boolean	MipI_Custom_Anime = OPC_FALSE;
Objid	MipI_Subnet_Objid;
List*	mn_tunnel_lptr = OPC_NIL;
int		MipI_Position_Update_Interval = 10;
List*	global_agent_lptr = OPC_NIL;
List*	global_mn_mr_lptr = OPC_NIL;

/* Structure to store agent information in the global list. */
typedef struct
{
	Objid			node_objid;
	InetT_Address	intf_address;
	MipC_Node_Type	agent_type;
	List*			bind_lptr;
	List*			visitor_lptr;
}
MipT_Agent_Reg;

/* Structure to store MN or MR information in the global list. */
typedef struct
{
	Objid			node_objid;
	InetT_Address		intf_address;
	MipC_Mn_Mr_Status	status;
	InetT_Address		ha_address;
	InetT_Address		fa_address;
}
MipT_Mn_Mr_Status;

const char *agent_type [] = {"HA", "FA", "HA_FA", "MR", "MN"};
const char *mn_mr_status [] = {"Lost", "Home", "Foreign", "Pending"};

/* Structure to represent tunnel object. */
typedef	struct 
{
	int		src_center_x;
	int		src_center_y;
	int		src_point_1_x;
	int		src_point_1_y;
	int		src_point_2_x;
	int		src_point_2_y;
	int		src_point_1_x_1;
	int		src_point_1_y_1;
	int		src_point_2_x_1;
	int		src_point_2_y_1;
	int		dest_center_x;
	int		dest_center_y;
	int		dest_point_1_x;
	int		dest_point_1_y;
	int		dest_point_2_x;
	int		dest_point_2_y;
	int		dest_point_1_x_1;
	int		dest_point_1_y_1;
	int		dest_point_2_x_1;
	int		dest_point_2_y_1;
	int		radius;
	int		color;
	Andid	drawing_did[6];
}
MipT_Tunnel_Pipe;
	
typedef	struct
{
	Objid	mn_objid;
	Objid	ha_objid;
	Objid	fa_objid;
	Boolean	double_tunnel;
	MipT_Tunnel_Pipe*	outer_pipe;
	MipT_Tunnel_Pipe*	inner_pipe_ha_fa;
	MipT_Tunnel_Pipe*	inner_pipe_fa_mr;
}
MipT_Tunnel;


/* Local helper functions. */
void	mip_sup_draw_circles (Objid, Objid, int, int, List**);
void	mip_sup_circle_list_erase (List*);
void	mip_sup_draw_pipe (Objid, Objid, int, int, MipT_Tunnel_Pipe **);
void	mip_sup_pipe_erase (MipT_Tunnel_Pipe *);
void	mip_sup_animation_legend (void);
void	mip_sup_draw_pipe_by_position (int, int, int, int, int, int, MipT_Tunnel_Pipe *);

/* Callbacks	*/
EXTERN_C_BEGIN
int		agent_reg_compare_proc (const void*, const void*);
int		mn_mr_compare_proc (const void*, const void*);
void	mip_sup_mn_position_update (void *, int);
EXTERN_C_END

Boolean
mip_sup_is_mobility_enabled (IpT_Rte_Module_Data module_data)
	{
	Objid	my_node_objid, tmp_comp_objid;
	char	ha_ip_addr [64];

	/** PURPOSE: Find if the mobile ip configs exists and non-empty.**/
	/** REQUIRES: none.	**/
	/** EFFECTS: Returns true if non zero row on the attribute is found.**/
	FIN (mip_sup_is_mobility_enabled (IpT_Rte_Module_Data module_data));

	my_node_objid = module_data.node_id;
	
		
	/* Now check if the MIPv4 attributes exist in this node.		*/
	if (op_ima_obj_attr_exists (my_node_objid, "Mobile IPv4 Parameters"))
		{
		/* Read the MIPv4 compound attribute.						*/
		op_ima_obj_attr_get_objid (my_node_objid, "Mobile IPv4 Parameters", &tmp_comp_objid);
	
		/* There are two different cases: Host and Router.			*/
		if (ip_rte_node_is_gateway (&module_data))
			{
			/* See if there is non-zero row. */
			tmp_comp_objid = op_topo_child (tmp_comp_objid, OPC_OBJTYPE_GENERIC, 0);
			op_ima_obj_attr_get (tmp_comp_objid, "Interface Information", &tmp_comp_objid);

			if (op_topo_child_count (tmp_comp_objid, OPC_OBJTYPE_GENERIC))
				{
				FRET (OPC_TRUE);
				}
			}
		else
			{
			/* See if there is non-zero row. */
			tmp_comp_objid = op_topo_child (tmp_comp_objid, OPC_OBJTYPE_GENERIC, 0);
			op_ima_obj_attr_get (tmp_comp_objid, "Home Agent IP Address", &ha_ip_addr);

			/* Check if the Home Agent addres has been set.			*/
			if (strcmp (ha_ip_addr, "Unassigned"))
				{
				/* HA address set, MIPv4 is active.					*/
				FRET (OPC_TRUE);
				}
			}
		}

	FRET (OPC_FALSE);
	}

Packet*
mip_sup_irdp_pkt_encapsulate (Packet* irdp_pkptr, InetT_Address src_address, 
						  InetT_Address dest_address, int pk_type)
	{
	Packet*				ip_pkptr;
	IpT_Dgram_Fields*	ip_dgram_fd_ptr;

	/** PURPOSE: Create an IP packet containing the ICMP packet.**/
	/** REQUIRES: ICMP packet + source & dest address + optional pk_type.	**/
	/** EFFECTS: New IP packet is created with all the fields set.**/
	FIN (mip_sup_irdp_pkt_encapsulate (irdp_pkptr, src_address, dest_address, pk_type));

	/* Create an IP datagram.	*/
	ip_pkptr = op_pk_create_fmt ("ip_dgram_v4");

	/* Set the ICMP packet in the data field of the IP datagram	*/
	op_pk_nfd_set (ip_pkptr, "data", irdp_pkptr);

	/* Set the bulk size of the IP packet to model the space	*/
	/* occupied by the encapsulated data. This is equal to the	*/
	/* the data packet plus the size of the ICMP header.		*/
	op_pk_bulk_size_set (ip_pkptr, MipC_Agent_Ad_Pk_Size * 8);

	/* Since no request should be made to the IP process,	*/
	/* explicitly de-install any outstanding ICIs.			*/
	op_ici_install (OPC_NIL);

	/* Create fields data structure that contains orig_len,	*/
	/* ident, frag_len, ttl, src_addr, dest_addr, frag,		*/
	/* connection class, src and dest internal addresses.	*/
	ip_dgram_fd_ptr = ip_dgram_fdstruct_create ();

	/* Set the destination address for this IP datagram.	*/
	ip_dgram_fd_ptr->dest_addr = dest_address;
	ip_dgram_fd_ptr->connection_class = 0;
	
	/* Set the source address */
	ip_dgram_fd_ptr->src_addr = src_address;

	/* Set the correct protocol in the IP datagram.	*/
	ip_dgram_fd_ptr->protocol = IpC_Protocol_Icmp;

	/* This is IRDP type ICMP packet. */
	ip_dgram_fd_ptr->icmp_type = pk_type;

	/* Set the packet size-related fields of the IP datagram.	*/
	ip_dgram_fd_ptr->orig_len = MipC_Agent_Ad_Pk_Size;
	ip_dgram_fd_ptr->frag_len = ip_dgram_fd_ptr->orig_len;
	ip_dgram_fd_ptr->original_size = 160 + ip_dgram_fd_ptr->orig_len * 8;

	/* Indicate that the packet is not yet fragmented.	*/
	ip_dgram_fd_ptr->frag = 0;

	/* Also set the compression method and original size fields	*/
	ip_dgram_fd_ptr->compression_method = IpC_No_Compression;

	/* The record route options has not been set.	*/
	ip_dgram_fd_ptr->options_field_set = OPC_FALSE;

	/*	Set the fields structure inside the ip datagram	*/
	op_pk_nfd_set (ip_pkptr, "fields", ip_dgram_fd_ptr, 
			ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields));

	FRET (ip_pkptr);
	}


void		
mip_sup_agent_register (Objid node_objid, InetT_Address intf_address, MipC_Node_Type agent_node_type, 
	List* bind_lptr, List* visitor_lptr)
	{
	static	Boolean	init = OPC_FALSE;
	MipT_Agent_Reg*	reg_ptr;
	
	/* Helper function to register all the agents. */
	FIN (mip_sup_agent_register (node_objid, intf_address, agent_node_type, binding_lptr, visitor_lptr));
	
	/* Only if we are in debug mode. */
	if (!op_sim_debug ())
		FOUT;
	
	if (!init)
		{
		global_agent_lptr = op_prg_list_create ();
		init = OPC_TRUE;
		}
	
	/* Create a structure to hold the passed information. */
	reg_ptr = (MipT_Agent_Reg*) op_prg_mem_alloc (sizeof (MipT_Agent_Reg));
	reg_ptr->node_objid = node_objid;
	reg_ptr->intf_address = intf_address;
	reg_ptr->agent_type = agent_node_type;
	reg_ptr->bind_lptr = bind_lptr;
	reg_ptr->visitor_lptr = visitor_lptr;
	
	/* Insert the struct in the sorted list. */
	op_prg_list_insert_sorted (global_agent_lptr, reg_ptr, agent_reg_compare_proc);
	
	FOUT;
	}

int
agent_reg_compare_proc (const void* generic_reg_1, const void* generic_reg_2)
	{
	MipT_Agent_Reg* reg_1 = OPC_NIL; 
	MipT_Agent_Reg* reg_2 = OPC_NIL;
	
	FIN (agent_reg_compare_proc (reg_1, reg_2));
	
	reg_1 = (MipT_Agent_Reg*) generic_reg_1;
	reg_2 = (MipT_Agent_Reg*) generic_reg_2;
	
	if (reg_1->node_objid < reg_2->node_objid)
		{
		FRET (1);
		}
	else if (reg_1->node_objid > reg_2->node_objid)
		{
		FRET (-1);
		}
	else
		{
		/* By now it can be said that the objid values are same.	*/
		/* Then no need to compare them (== case) again just return	*/
		/* 0.														*/ 
		FRET (0);
		}
	}	


void		
mip_sup_mn_mr_status_update (Objid node_objid, InetT_Address intf_address, MipC_Mn_Mr_Status status, 
	InetT_Address ha_address, InetT_Address fa_address)
	{
	int		low, high;
	static	Boolean	init = OPC_FALSE;
	MipT_Mn_Mr_Status*	mn_mr_status_ptr = OPC_NIL;
	MipT_Mn_Mr_Status	tmp_mn_mr_status;
	Boolean	found = OPC_FALSE;
	
	/* Helper function to record the current status of mn and mr. */
	FIN (mip_sup_mn_mr_status_update (node_objid, intf_address, status, ha_address, fa_address));
	
	/* Only if we are in debug mode. */
	if (!op_sim_debug ())
		FOUT;
	
	if (!init)
		{
		global_mn_mr_lptr = op_prg_list_create ();
		init = OPC_TRUE;
		}
	
	/* See if we have a entry already. */
	tmp_mn_mr_status.node_objid = node_objid;
	if ((mn_mr_status_ptr = (MipT_Mn_Mr_Status*) op_prg_list_elem_find (global_mn_mr_lptr, mn_mr_compare_proc, 
		&tmp_mn_mr_status, &low, &high)))
		{
		if (inet_address_equal (mn_mr_status_ptr->intf_address, intf_address))
			{
			found = OPC_TRUE;
			}
		else
			{
			for (;low <= high; low++)
				{
				/* If we have multple proc on the same node... */
				mn_mr_status_ptr = (MipT_Mn_Mr_Status*) op_prg_list_access (global_mn_mr_lptr, low);
			
				if (inet_address_equal (mn_mr_status_ptr->intf_address, intf_address))
					{
					found = OPC_TRUE;
					break;
					}
				}
			}
		}
	
	if (found)
		{
		/* Update the existing entry. */
		mn_mr_status_ptr->status = status;
		mn_mr_status_ptr->fa_address = fa_address;
		}
	else
		{
		/* Create a structure to hold the passed information. */
		mn_mr_status_ptr = (MipT_Mn_Mr_Status*) op_prg_mem_alloc (sizeof (MipT_Mn_Mr_Status));
		mn_mr_status_ptr->node_objid = node_objid;
		mn_mr_status_ptr->intf_address = intf_address;
		mn_mr_status_ptr->status = status;
		mn_mr_status_ptr->ha_address = ha_address;
		mn_mr_status_ptr->fa_address = fa_address;
	
		/* Insert the struct in the sorted list. */
		op_prg_list_insert_sorted (global_mn_mr_lptr, mn_mr_status_ptr, mn_mr_compare_proc);
		}
	
	FOUT;
	}

int
mn_mr_compare_proc (const void* generic_node_1, const void* generic_node_2)
	{
	MipT_Mn_Mr_Status* node_1 = OPC_NIL; 
	MipT_Mn_Mr_Status* node_2 = OPC_NIL; 
	
	FIN (mn_mr_compare_proc (node_1, node_2));
	
	node_1 = (MipT_Mn_Mr_Status*) generic_node_1;
	node_2 = (MipT_Mn_Mr_Status*) generic_node_2;
	
	if (node_1->node_objid < node_2->node_objid) 
		{
		FRET (1);
		}
	else if (node_1->node_objid > node_2->node_objid)
		{
		FRET (-1);
		}
	else
		{
		/* By now it can be said that the objid values are same.	*/
		/* Then no need to compare them (== case) again just return	*/
		/* 0.														*/ 
		FRET (0);
		}
	}	
	
int	
mip_sup_network_summary_print (const char* PRG_ARG_UNUSED (dummy1), void* PRG_ARG_UNUSED (dummy2))
	{
	int		list_idx, list_cnt, bind_list_idx, bind_list_cnt, visitor_list_idx, visitor_list_cnt;
	char	node_name [OMSC_HNAME_MAX_LEN], ip_address [32], care_of_address [32]; 
	char	fa_address [32], home_address [32];
	MipT_Agent_Reg*	reg_ptr;
	MipT_Mn_Mr_Status*	mn_mr_status_ptr;
	MipT_List_Entry*	list_entry_ptr;
	
	/* Function to print the status mobile IP related information. */
	FIN (mip_sup_network_summary_print (void));

	/* Only if list is available. */
	if (global_agent_lptr)
		{
		/* Iterate through all the agents registered. */
		printf ("\n\n##### Mobile Agent Status Table #####\n");
		list_cnt = op_prg_list_size (global_agent_lptr);
		for (list_idx=0; list_idx < list_cnt; list_idx++)
			{
			/* Print the hierarchical name of nodes involved. */
			printf ("\nNode_ID\tIP_address\tType\tHierarchical Name\n");
			printf ("=====================================================\n");

			/* Access the entry. */
			reg_ptr = (MipT_Agent_Reg*) op_prg_list_access (global_agent_lptr, list_idx);
			
			/* Get the hierarchical name of the node. */
			oms_tan_hname_get (reg_ptr->node_objid, node_name);
			inet_address_print (ip_address, reg_ptr->intf_address);
			
			printf ("%d\t%s\t%s\t%s\n", reg_ptr->node_objid, ip_address, 
				agent_type [reg_ptr->agent_type], node_name);
			
			if ((bind_list_cnt = op_prg_list_size (reg_ptr->bind_lptr)))
				{
				printf ("Binding Table Contents:\n");
				printf ("\tHome_address\tCare_of_address\tLifetime_expiration\n");
				printf ("\t===================================================\n");
				
				for (bind_list_idx=0; bind_list_idx < bind_list_cnt; bind_list_idx++)
					{
					list_entry_ptr = (MipT_List_Entry*) op_prg_list_access (reg_ptr->bind_lptr, bind_list_idx);
					
					/* Get the addresses in the string format. */
					inet_address_print (home_address, list_entry_ptr->home_address);
					inet_address_print (care_of_address, list_entry_ptr->care_of_address);
					
					printf ("\t%s\t%s\t%f\n", home_address, care_of_address, list_entry_ptr->lifetime);
					}
				}
			
			if ((visitor_list_cnt = op_prg_list_size (reg_ptr->visitor_lptr)))
				{
				printf ("Visitor Table Contents:\n");
				printf ("\tHome_address\tLifetime_expiration\n");
				printf ("\t====================================\n");
				
				for (visitor_list_idx=0; visitor_list_idx < visitor_list_cnt; visitor_list_idx++)
					{
					list_entry_ptr = (MipT_List_Entry*) op_prg_list_access (reg_ptr->visitor_lptr, visitor_list_idx);
					
					/* Get the addresses in the string format. */
					inet_address_print (home_address, list_entry_ptr->home_address);
					
					printf ("\t%s\t%f\n", home_address, list_entry_ptr->lifetime);
					}
				}
			}
		}
		
	if (global_mn_mr_lptr)
		{
		/* Iterate through all the mobile entities. */
		/* Print the hierarchical name of nodes involved. */
		printf ("\n\n##### Mobile Node or Router Status Table #####\n");
		printf ("\nNode_ID\tIP_address\tHierarchical Name\tStatus\tHA_address\tfa_address\n");
		printf ("===================================================================================\n");

		list_cnt = op_prg_list_size (global_mn_mr_lptr);
		for (list_idx=0; list_idx < list_cnt; list_idx++)
			{
			/* Access the entry. */
			mn_mr_status_ptr = (MipT_Mn_Mr_Status*) op_prg_list_access (global_mn_mr_lptr, list_idx);
			
			/* Get the hierarchical name of the node. */
			oms_tan_hname_get (mn_mr_status_ptr->node_objid, node_name);
			inet_address_print (ip_address, mn_mr_status_ptr->intf_address);
			inet_address_print (home_address, mn_mr_status_ptr->ha_address);
			inet_address_print (fa_address, mn_mr_status_ptr->fa_address);

			printf ("%d\t%s\t%s\t%s\t%s\t%s\n", mn_mr_status_ptr->node_objid, ip_address, 
				node_name, mn_mr_status [mn_mr_status_ptr->status],	home_address, fa_address);
			}
		}

	FRET (0);
	}

Compcode	
mip_sup_packet_check (IpT_Rte_Module_Data* module_data_ptr, Packet* pk_ptr, 
						 IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	IpT_Interface_Info*		intf_info_ptr;
	MipT_Invocation_Info	mip_invoke_struct;

	/** PURPOSE: Check the mobility support in the node and invoke to see if tunneling is needed.**/
	/** REQUIRES: module data for the node + packet and the internal routing info.	**/
	/** EFFECTS: if tunneling is not needed returns false, true otherwise.**/
	FIN (mip_sup_packet_check (module_data_ptr, pk_ptr, intf_ici_fdstruct_ptr));

	/* We do not want to handle that is going to higher layer anyway. */
	if (intf_ici_fdstruct_ptr->higher_layer)
		FRET (OPC_COMPCODE_FAILURE);
		
	/* Find the interface ptr corresponding to the output interface for the packet. */
	if ((intf_info_ptr = ip_rte_intf_tbl_access 
		(module_data_ptr, intf_ici_fdstruct_ptr->output_intf_index))) 
		{
		/* We have a valid interface which should handle this packet.  Give it to mip manager. */
		mip_invoke_struct.invocation_type = MipC_Invoke_Type_IP_Datagram;
		mip_invoke_struct.pk_ptr = pk_ptr;
		mip_invoke_struct.interface_ptr = intf_info_ptr;
		mip_invoke_struct.rte_info_ici_ptr = intf_ici_fdstruct_ptr;

		/* Invoke the manager proc. */
		op_pro_invoke (module_data_ptr->mip_info_ptr->mgr_phndl, &mip_invoke_struct);

		/* See if the packet was tunneled O.K. */
		if (mip_invoke_struct.pk_ptr == OPC_NIL)
			{
			/* Success. */
			FRET (OPC_COMPCODE_SUCCESS);
			}
		}

	FRET (OPC_COMPCODE_FAILURE);
	}
			
Compcode	
mip_sup_IRDP_packet_forward (IpT_Rte_Module_Data* module_data_ptr, Packet* pk_ptr, 
							 IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr, int irdp_type)
	{
	MipT_Invocation_Info	mip_invoke_struct;

	/** PURPOSE: Check the mobility support in the node and invoke manager to handle IRDP packet.**/
	/** REQUIRES: module data for the node + packet.	**/
	/** EFFECTS: if problems, returns false, true otherwise.**/
	FIN (mip_sup_IRDP_packet_forward (module_data_ptr, pk_ptr, intf_ici_fdstruct_ptr, irdp_type));

	/* Create an invocation info and let manager handle the rest. */
	mip_invoke_struct.invocation_type = MipC_Invoke_Type_IRDP;
	mip_invoke_struct.pk_ptr = pk_ptr;
	mip_invoke_struct.interface_ptr = OPC_NIL;
	mip_invoke_struct.rte_info_ici_ptr = intf_ici_fdstruct_ptr; 
	mip_invoke_struct.irdp_type = (IcmpC_Type) irdp_type;
	
	/* Invoke the manager proc. */
	FRET (op_pro_invoke (module_data_ptr->mip_info_ptr->mgr_phndl, &mip_invoke_struct));
	}

Packet*		
mip_sup_ip_in_ip_encapsulate (Packet* orig_ip_pk_ptr, InetT_Address dest_address)
	{
	Packet*		ip_pkptr;
	IpT_Dgram_Fields	*new_ip_dgram_fd_ptr, *old_ip_dgram_fd_ptr;

	/** PURPOSE: Encapsulate the packet going to dest_addr.**/
	/** REQUIRES: original packet and the new destination.	**/
	/** EFFECTS: new packet encapsulating old.**/
	FIN (mip_sup_ip_in_ip_encapsulate (pk_ptr, dest_addr));
	
	/* Access the old field information. */
	op_pk_nfd_access (orig_ip_pk_ptr, "fields", &old_ip_dgram_fd_ptr);

	/* Create an IP datagram.	*/
	ip_pkptr = op_pk_create_fmt ("ip_dgram_v4");

	/* Set the bulk size of the IP packet to model the space	*/
	/* occupied by the encapsulated IP packet. This is equal to the	*/
	/* the data packet plus the size of the ICMP header.		*/
	op_pk_bulk_size_set (ip_pkptr, op_pk_total_size_get (orig_ip_pk_ptr));

	/* Since no request should be made to the IP process,	*/
	/* explicitly de-install any outstanding ICIs.			*/
	op_ici_install (OPC_NIL);

	/* Copy the old info field to create new one for the outer packet. */
	new_ip_dgram_fd_ptr = ip_dgram_fdstruct_copy (old_ip_dgram_fd_ptr);

	/* Set the destination address for this IP datagram.	*/
	new_ip_dgram_fd_ptr->dest_addr = dest_address;
	
	/* Set the protocol value so that it is recognized correctly	*/
	/* in socket_info_extract, print procs etc.						*/
	new_ip_dgram_fd_ptr->protocol = IpC_Protocol_Ip_Mip;
	
	/* Set the packet size-related fields of the IP datagram.	*/
	new_ip_dgram_fd_ptr->orig_len = op_pk_total_size_get (orig_ip_pk_ptr) / 8;;
	new_ip_dgram_fd_ptr->frag_len = new_ip_dgram_fd_ptr->orig_len;
	new_ip_dgram_fd_ptr->original_size = 160 + new_ip_dgram_fd_ptr->orig_len * 8;

	/* Indicate that the packet is not yet fragmented.	*/
	new_ip_dgram_fd_ptr->frag = 0;

	/* Set the encapsulation count for sim efficiency. */
	new_ip_dgram_fd_ptr->encap_count++;

	new_ip_dgram_fd_ptr->dest_internal_addr = IPC_FAST_ADDR_INVALID;
	new_ip_dgram_fd_ptr->src_internal_addr  = IPC_FAST_ADDR_INVALID;

	/*	Set the fields structure inside the ip datagram	*/
	op_pk_nfd_set (ip_pkptr, "fields", new_ip_dgram_fd_ptr, 
			ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields));

	/* Set the original IP packet in the data field of the new IP datagram	*/
	op_pk_nfd_set (ip_pkptr, "data", orig_ip_pk_ptr);

	FRET (ip_pkptr);
	}

Compcode		
mip_sup_ip_in_ip_decapsulate (Packet* orig_ip_pk_ptr, Packet** encap_pk)
	{
	IpT_Dgram_Fields	*ip_dgram_fd_ptr;

	/** PURPOSE: Decapsulate if it is a tunneling packet.**/
	/** REQUIRES: original packet.	**/
	/** EFFECTS: encapsulated packet if successful old one if not.**/
	FIN (mip_sup_ip_in_ip_decapsulate (orig_ip_pk_ptr, encap_pk));

	/* Access the field structure of the packet. */
	op_pk_nfd_access (orig_ip_pk_ptr, "fields", &ip_dgram_fd_ptr);

	/* Check if the encap counter is non-zero. */
	if (ip_dgram_fd_ptr->encap_count)
		{
		/* Access the encapsulated packet. */
		op_pk_nfd_get (orig_ip_pk_ptr, "data", encap_pk);

		FRET (OPC_COMPCODE_SUCCESS);
		}
	else
		{
		/* Non tunnel packet. */ 
		FRET (OPC_COMPCODE_FAILURE);
		}
	}

Compcode
mip_sup_tunneled_pkt_check (IpT_Rte_Module_Data* module_data_ptr, Packet* pk_ptr,
							IpT_Rte_Ind_Ici_Fields* intf_ici_fdstruct_ptr)
	{
	MipT_Invocation_Info	mip_invoke_struct;

	/** PURPOSE: Check if the packet needs to be decapsulated.**/
	/** REQUIRES: module data, packet and the fields struct ptr.	**/
	/** EFFECTS: If true, hands over the packet to FA to handle.**/
	FIN (mip_sup_tunneled_pkt_check (module_data_ptr, pk_ptr, intf_ici_fdstruct_ptr));
	
	/* Create an invocation info and let manager handle the rest. */
	mip_invoke_struct.invocation_type = MipC_Invoke_Type_Tunnel_Check;
	mip_invoke_struct.pk_ptr = pk_ptr;
	mip_invoke_struct.interface_ptr = OPC_NIL;
	mip_invoke_struct.rte_info_ici_ptr = intf_ici_fdstruct_ptr; 
	
	/* Invoke the manager proc. */
	op_pro_invoke (module_data_ptr->mip_info_ptr->mgr_phndl, &mip_invoke_struct);

	if (mip_invoke_struct.pk_ptr)
		{
		/* Let the IP handle it. */
		FRET (OPC_COMPCODE_FAILURE);
		}
	else
		{
		/* A FA process is now handling the packet. */
		FRET (OPC_COMPCODE_SUCCESS);
		}
	}	

int	
mip_sup_tbl_idx_from_int_info_get (IpT_Rte_Module_Data* module_data, IpT_Interface_Info* intf_info_ptr)
	{
	int		intf_list_size, intf_index;

	/** PURPOSE: Find the interface table index from the interface info ptr.**/
	/** REQUIRES: module data, interface info found using name information.	**/
	/** EFFECTS: index if found. PA if error.**/
	FIN (mip_sup_tbl_idx_from_int_info_get (module_data, intf_info_ptr));

	/* To guesstimate the number of interface entry in the array... */
	intf_list_size = op_prg_list_size (module_data->interface_table_ptr);

	for (intf_index=0; intf_index < intf_list_size; intf_index++)
		{
		if (ip_rte_intf_tbl_access (module_data, intf_index) == intf_info_ptr)
			{
			FRET (intf_index);
			}
		}

	op_sim_end ("Cannot find the interface index from the table!","","","");
	FRET (0);
	}

Compcode
mip_sup_incoming_interface_check (IpT_Rte_Module_Data* module_data_ptr, int	instrm, IpT_Interface_Info** intf_info_pptr)
	{
	int					num_interfaces, i;
	IpT_Interface_Info*		ith_intf_ptr;
	/** PURPOSE: Find the interface information of the MR agent proc if exists.**/
	/** REQUIRES: Instream where the packet arrived.	**/
	/** EFFECTS: Interface information pointer filled.**/
	FIN (mip_sup_incoming_interface_check (module_data, instrm, intf_info_ptr));

	/* Find out the number of interfaces.					*/
	num_interfaces = ip_rte_num_interfaces_get (module_data_ptr);

	/* loop through each of the interfaces and check whether*/
	/* the strm information matches up.						*/
	for (i = 0; i < num_interfaces; i++)
		{
		ith_intf_ptr = ip_rte_intf_tbl_access (module_data_ptr, i);

		/* Compare the instrm numbers. */
		if (ith_intf_ptr->phys_intf_info_ptr)
			{
			if (ith_intf_ptr->phys_intf_info_ptr->in_port_num == instrm)		
				{
				*intf_info_pptr = ith_intf_ptr;
		
				FRET (OPC_COMPCODE_SUCCESS);
				}
			}
		}
	
	FRET (OPC_COMPCODE_FAILURE);
	}

void
mip_sup_packet_send_to_ip (IpT_Rte_Module_Data* module_data_ptr, Packet* pk_ptr)
	{
	/** PURPOSE: Deliver the IP packet to IP dispatch.**/
	/** REQUIRES: Module wide IP info and the packet to send.	**/
	/** EFFECTS: packet is op_pk_delivered.**/
	FIN (mip_sup_packet_send_to_ip (module_data_ptr, pk_ptr));
	
	/* deliver the packet to the parent IP process. */
	op_pk_deliver (pk_ptr, module_data_ptr->module_id, module_data_ptr->instrm_from_ip_encap);

	FOUT;
	}

double
mip_sup_activation_time_calculate (void)
	{
	static	Boolean	init = OPC_FALSE;
	static  int		active_time = 0;

	/** PURPOSE: Come up with a initial time value when the MIP process gets actvated.**/
	/** REQUIRES: Simulation attribute "Mobile IP Activation Time".	**/
	/** EFFECTS: A randome number will be chosen and returned.**/
	FIN (mip_sup_activation_time_calculate ());

	/*  Get the simulation attribute value for the first time. */
	if (!init)
		{
		if (op_ima_sim_attr_exists ("Mobile IP Activation Time"))
			{
			op_ima_sim_attr_get (OPC_IMA_INTEGER, "Mobile IP Activation Time", &active_time);

			init = OPC_TRUE;
			}
		else
			{
			op_sim_end ("Cannot access the simulation attribute: Mobile IP Activation Time", "","","");
			}
		}

	/* Calculate the random value around the time specified by the attribute for activation. */
	FRET ((double) active_time + op_dist_uniform (10.0));
	}
	
Compcode
mip_sup_visitor_search_by_addr (List* visitor_list_lptr, InetT_Address dest_addr, Prohandle* agent_phndl)
	{
	int		node_list_size, node_list_index, local_list_size, local_list_index;
	MipT_FA_Visitor_List_Entry		*tmp_list_entry;
	MipT_List_Entry					*tmp_visitor_entry;
	
	/** PURPOSE: Search the node level visitor list with the dest_addr of incoming packet.**/
	/** REQUIRES: dest address of the incoming packet.	**/
	/** EFFECTS: process handle of the mip proc if found. **/
	FIN (mip_sup_visitor_search_by_addr (visitor_list_lptr, dest_addr, agent_phndl));
	
	/* Search the node level visitor lists. */
	node_list_size = op_prg_list_size (visitor_list_lptr);
	for (node_list_index=0; node_list_index < node_list_size; node_list_index++)
		{
		tmp_list_entry = (MipT_FA_Visitor_List_Entry*) op_prg_list_access (visitor_list_lptr, node_list_index);
		
		/* Search the visitor lists in each of the FA. */
		local_list_size = op_prg_list_size (tmp_list_entry->local_visitor_lptr);
		for (local_list_index=0; local_list_index < local_list_size; local_list_index++)
			{
			tmp_visitor_entry = (MipT_List_Entry*) op_prg_list_access (
				tmp_list_entry->local_visitor_lptr, local_list_index);
			
			if (inet_address_equal (tmp_visitor_entry->home_address, dest_addr))
				{
				*agent_phndl = tmp_list_entry->agent_phndl;
				FRET (OPC_COMPCODE_SUCCESS);
				}
			}

		/* We now check for the rejected ones as well. */
		local_list_size = op_prg_list_size (tmp_list_entry->local_rejection_cache_lptr);
		for (local_list_index=0; local_list_index < local_list_size; local_list_index++)
			{
			tmp_visitor_entry = (MipT_List_Entry*) op_prg_list_access (
				tmp_list_entry->local_rejection_cache_lptr, local_list_index);
			
			if (inet_address_equal (tmp_visitor_entry->home_address, dest_addr))
				{
				*agent_phndl = tmp_list_entry->agent_phndl;
				FRET (OPC_COMPCODE_SUCCESS);
				}
			}
		}
	
	FRET (OPC_COMPCODE_FAILURE);
	}


void
mip_sup_pk_cleanup (MipT_Invocation_Info* invoc_info_ptr)
	{
	/** PURPOSE: Clean up the packet and associated ICI when MIP procs are done. **/
	/** REQUIRES: Invocation struct pointer.	**/
	/** EFFECTS: Packet gets destroyed and the pointer reset, ICI destroyed. **/
	FIN (mip_sup_pk_cleanup (invoc_info_ptr));

	/* Destroy the packet and reset the pointer. */
	op_pk_destroy (invoc_info_ptr->pk_ptr);
	invoc_info_ptr->pk_ptr = OPC_NIL;

	/* Clean up ICI as well. */
	ip_rte_ind_ici_fdstruct_destroy (invoc_info_ptr->rte_info_ici_ptr);

	FOUT;
	}


void
mip_sup_log_warning (const char* warning)
	{
	static	Boolean		init = OPC_FALSE;
	static	Log_Handle	mip_log_hndl;

	/** PURPOSE: Initialize sim log handle and log warnings.	**/
	/** REQUIRES: Warning message.	**/
	/** EFFECTS: None.			**/
	FIN (mip_sup_log_warning (warning));

	if (!init)
		{
		/* Initialize the sim log handle for later use. */
		mip_log_hndl = op_prg_log_handle_create
			(OpC_Log_Category_Protocol, "Mobile IP", "Routing", MipC_Log_Limit);

		init = OPC_TRUE;
		}

	/* Log the warning. */
	op_prg_log_entry_write (mip_log_hndl, warning);

	FOUT;
	}

void
mip_sup_prepare_animation (void)
	{
	static	Boolean	init = OPC_FALSE;
	char			net_name [128], subnet_name [128];
	Log_Handle		mip_log_hndl;
	Objid			subnet_id;
	Objid			node_id;
	
	/* Helper function for the animation. */
	FIN (mip_sup_prepare_animation (void));
	
	if (!init)
		{
		init = OPC_TRUE;
	
		/* Open the anim viewer. */
		MipI_Anvid = op_anim_lprobe_anvid ("MIP");
		
		if (OPC_ANIM_ID_NIL == MipI_Anvid)
			{
			/* Problem with custom animation. */
			mip_log_hndl = op_prg_log_handle_create
				(OpC_Log_Category_Configuration, "Mobile IP", "Animation", MipC_Log_Limit);
			op_prg_log_entry_write (mip_log_hndl,"Animation is active but the Mobile IP custom animation is not activated.\n"
				"Try creating a custom animation probe model with label \"MIP\".");

			FOUT;
			}
		else
			{
			/* Set the global flag. */
			MipI_Custom_Anime = OPC_TRUE;
			}
		
		/* Correction: Get net_name from sim attribute rather than sim info	*/
		/* Find the network model name. */
		/* op_sim_info_get (OPC_STRING, OPC_SIM_INFO_OUTPUT_FILE_NAME, net_name); */
		op_ima_sim_attr_get (OPC_IMA_STRING, "net_name", net_name);
		
		/* Get the node on which the calling process runs */
		node_id = op_topo_parent (op_id_self ());
		
		/* Get the subnet to which this node belongs */
		subnet_id = op_topo_parent (node_id);
		
		/* Get the name of this subnet */
		op_ima_obj_attr_get_str (subnet_id, "name", 128, subnet_name);
		
		/* Make sure that the node is not already in the topmost	*/
		/* subnet. If no then get teh top subnet name.				*/
		/* If yes then the name of subnet will be "top" 			*/
		if (strcmp (subnet_name, "top") != 0)
			{
			/* Find the name of the top most subnet, underneath top.*/
			MipI_Subnet_Objid = op_topo_child (0, OPC_OBJMTYPE_SITE, 0);
			op_ima_obj_attr_get_str (MipI_Subnet_Objid, "name", 128, subnet_name);
			}
		
		/* Draw the animation										*/
		op_anim_ime_nmod_draw (MipI_Anvid, OPC_ANIM_MODTYPE_NETWORK, net_name, subnet_name,
			OPC_ANIM_MOD_OPTION_NONE, OPC_ANIM_DEFPROPS);
		
		/* Draw the legends for the custom animation. */
		mip_sup_animation_legend ();
		
		/* We will redraw network and tunnels every such seconds. */
		op_ima_sim_attr_get_int32 ("Mobile IP Tunnel Animation Update Interval", &MipI_Position_Update_Interval);
		op_intrpt_schedule_call (op_sim_time () + (double) MipI_Position_Update_Interval, 0, mip_sup_mn_position_update, OPC_NIL);
		}
			
	FOUT;
	}

void
mip_sup_draw_tunnel (Objid mn_node_objid, InetT_Address ha_address, InetT_Address fa_address, Boolean double_tunnel)
	{
	int		list_cnt, list_idx, outer_tunnel_match, both_tunnel_match;
	Boolean	found;
	MipT_Tunnel		*tmp_tunnel_obj, *my_tunnel_obj;
	Objid	ha_objid, fa_objid;
	
	/* Helper function for animation. */
	FIN (mip_sup_draw_tunnel (mn_objid, ha_address, fa_address, double_tunnel));
	
	/* See if we need to be invoked to begin with. */
	if (!MipI_Custom_Anime)
		{
		FOUT;
		}
		
	/* Initialize global lists first. */
	if (!mn_tunnel_lptr)
		{
		mn_tunnel_lptr = op_prg_list_create ();
		}
		
	/* Find the HA, FA objid from the IP address. */
	ha_objid = inet_support_node_id_from_ip_address_get (ha_address);
	fa_objid = inet_support_node_id_from_ip_address_get (fa_address);
		
	/* See if we have cached info on this MN. */
	list_cnt = op_prg_list_size (mn_tunnel_lptr);
	for (found=OPC_FALSE,list_idx=0; list_idx < list_cnt; list_idx++)
		{
		tmp_tunnel_obj = (MipT_Tunnel*) op_prg_list_access (mn_tunnel_lptr, list_idx);
		if (tmp_tunnel_obj->mn_objid == mn_node_objid)
			{
			tmp_tunnel_obj = (MipT_Tunnel*) op_prg_list_remove (mn_tunnel_lptr, list_idx);
			found = OPC_TRUE;
			break;
			}
		}
	
	if (found)
		{
		/* We found the match.  We only need to update the existing tunnel. */
		my_tunnel_obj = tmp_tunnel_obj;
		outer_tunnel_match = 0; both_tunnel_match = 0;
		
		/* If I have tunnel drawn already, find if I am the only one on the HA-FA pair. */
		if (my_tunnel_obj->outer_pipe != OPC_NIL)
			{
			/* Am I only one with tunnel between these two nodes? */
			list_cnt = op_prg_list_size (mn_tunnel_lptr);
			for (list_idx=0; list_idx < list_cnt; list_idx++)
				{
				tmp_tunnel_obj = (MipT_Tunnel*) op_prg_list_access (mn_tunnel_lptr, list_idx);
				if ((tmp_tunnel_obj->mn_objid != mn_node_objid) && (tmp_tunnel_obj->ha_objid == ha_objid) &&
					(tmp_tunnel_obj->fa_objid == my_tunnel_obj->fa_objid))
					{
					if (my_tunnel_obj->double_tunnel)
						{
						/* I had double tunnel.  What about this one? */
						if (tmp_tunnel_obj->double_tunnel)
							{
							/* This one also has double tunnel. */
							both_tunnel_match++;
							}
						else
							{
							/* We only have the outer tunnel in common. */
							outer_tunnel_match++;
							}
						}
					else
						{
						/* I only had outer tunnel to care. */
						outer_tunnel_match++;
						}
					}
				}
			}
		
		if (my_tunnel_obj->double_tunnel)
			{
			if (both_tunnel_match)
				{
				/* We only need to erase the MN to FA tunnel in this case. */
				mip_sup_pipe_erase (my_tunnel_obj->inner_pipe_fa_mr);
				}
			else
				{
				if (outer_tunnel_match)
					{
					/* We need to remove the whole inner tunnel thing. */
					mip_sup_pipe_erase (my_tunnel_obj->inner_pipe_ha_fa);
					mip_sup_pipe_erase (my_tunnel_obj->inner_pipe_fa_mr);
					}
				else
					{
					/* Nobody else is sharing this tunnel with me. Erase whole thing. */
					mip_sup_pipe_erase (my_tunnel_obj->outer_pipe);
					mip_sup_pipe_erase (my_tunnel_obj->inner_pipe_ha_fa);
					mip_sup_pipe_erase (my_tunnel_obj->inner_pipe_fa_mr);
					}
				}
			}
		else
			{
			/* I had a single tunnel. */
			if (outer_tunnel_match == 0)
				{
				/* I am the only one using this tunnel. */
				/* Erase the outer tunnel drawing. */
				mip_sup_pipe_erase (my_tunnel_obj->outer_pipe);
				}
			}
		
		/* Assign the new FA. */
		my_tunnel_obj->fa_objid = fa_objid;
		}
	else
		{
		if (ha_objid == fa_objid)
			{
			FOUT;
			}
		else
			{
			/* We need to create a new entry for this mobile entity. */
			my_tunnel_obj = (MipT_Tunnel*) op_prg_mem_alloc (sizeof (MipT_Tunnel));
			my_tunnel_obj->mn_objid = mn_node_objid;
			my_tunnel_obj->ha_objid = ha_objid;
			my_tunnel_obj->fa_objid = fa_objid;
			my_tunnel_obj->double_tunnel = double_tunnel;
			}
		}
			
	if (ha_objid == fa_objid)
		FOUT;
	
	/* Am I only one with tunnel between these two nodes? */
	outer_tunnel_match = 0; both_tunnel_match = 0;
	list_cnt = op_prg_list_size (mn_tunnel_lptr);
	for (list_idx=0; list_idx < list_cnt; list_idx++)
		{
		tmp_tunnel_obj = (MipT_Tunnel*) op_prg_list_access (mn_tunnel_lptr, list_idx);
		if ((tmp_tunnel_obj->mn_objid != mn_node_objid) && (tmp_tunnel_obj->ha_objid == ha_objid) &&
			(tmp_tunnel_obj->fa_objid == fa_objid))
			{
			if (my_tunnel_obj->double_tunnel)
				{
				/* I had double tunnel.  What about this one? */
				if (tmp_tunnel_obj->double_tunnel)
					{
					/* This one also has double tunnel. */
					both_tunnel_match++;
					
					/* Copy the list pointers. */
					my_tunnel_obj->outer_pipe = tmp_tunnel_obj->outer_pipe;
					my_tunnel_obj->inner_pipe_ha_fa = tmp_tunnel_obj->inner_pipe_ha_fa;	
					
					break;
					}
				else
					{
					/* We only have the outer tunnel in common. */
					outer_tunnel_match++;
											
					/* Copy the list pointers. */
					my_tunnel_obj->outer_pipe = tmp_tunnel_obj->outer_pipe;
					}
				}
			else
				{
				/* I only had outer tunnel to care. */
				outer_tunnel_match++;
					
				/* Copy the list pointers. */
				my_tunnel_obj->outer_pipe = tmp_tunnel_obj->outer_pipe;
				
				break;
				}
			}
		}
		
	if (double_tunnel)
		{
		if (both_tunnel_match)
			{
			/* Draw only the FA to MR. */
			mip_sup_draw_pipe (mn_node_objid, fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
				&my_tunnel_obj->inner_pipe_fa_mr);
			}
		else
			{
			if (outer_tunnel_match)
				{
				/* Draw a couple of pipes. */
				mip_sup_draw_pipe (ha_objid, fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
					&my_tunnel_obj->inner_pipe_ha_fa);
				mip_sup_draw_pipe (mn_node_objid, fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
					&my_tunnel_obj->inner_pipe_fa_mr);
				}
			else
				{
				/* Nothing so far.  Draw all three. */
				mip_sup_draw_pipe (ha_objid, fa_objid, MipC_Tunnel_Outer_Color, MipC_Tunnel_Circle_Radius_Outer, 
					&my_tunnel_obj->outer_pipe);
				mip_sup_draw_pipe (ha_objid, fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
					&my_tunnel_obj->inner_pipe_ha_fa);
				mip_sup_draw_pipe (mn_node_objid, fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
					&my_tunnel_obj->inner_pipe_fa_mr);
				}
			}
		}
	else
		{
		if (!outer_tunnel_match)
			{
			/* We have to draw the only outer tunnel. */
			mip_sup_draw_pipe (ha_objid, fa_objid, MipC_Tunnel_Outer_Color, MipC_Tunnel_Circle_Radius_Outer, 
				&my_tunnel_obj->outer_pipe);
			}
		}
		
	/* Insert the new structure into the cache. */
	op_prg_list_insert (mn_tunnel_lptr, my_tunnel_obj, OPC_LISTPOS_TAIL);
	
	FOUT;
	}
	

void
mip_sup_draw_pipe (Objid src_objid, Objid dest_objid, int color, int radius, MipT_Tunnel_Pipe **pipe_pptr)
	{
	double	lat, lon, alt, x, y, z, src_nx, src_ny, dest_nx, dest_ny;
	int		src_vx, src_vy, dest_vx, dest_vy;
	Boolean	src_subnet = OPC_FALSE, dest_subnet = OPC_FALSE;
	MipT_Tunnel_Pipe *pipe_ptr;
	char	src_name [128], dest_name [128];
	
	/* Helper function for custom animation. */
	FIN (mip_sup_draw_pipe (src_objid, dest_objid, color, radius, pipe_pptr));
	
	/* We do not need to draw anything if the src and dest are the same. */
	if (src_objid == dest_objid)
		FOUT;
	
	/* We will move up the ladder to find the subnet being animated now. */
	while (op_topo_parent (src_objid) != MipI_Subnet_Objid)
		{
		src_subnet = OPC_TRUE;
		src_objid = op_topo_parent (src_objid);
		
		/* we want to handle the subnets only in the subnet being animated. */
		if (src_objid == 0)
			FOUT;
		}
		
	while (op_topo_parent (dest_objid) != MipI_Subnet_Objid)
		{
		dest_subnet = OPC_TRUE;
		dest_objid = op_topo_parent (dest_objid);
		
		/* we want to handle the subnets only in the subnet being animated. */
		if (dest_objid == 0)
			FOUT;
		}
	
	/* Create a new structure for the pipe. */
	*pipe_pptr = pipe_ptr = (MipT_Tunnel_Pipe*) op_prg_mem_alloc (sizeof (MipT_Tunnel_Pipe));
	
	/* Force the location update. */
	op_ima_obj_pos_get (src_objid, &lat, &lon, &alt, &x, &y, &z);
	op_ima_obj_pos_get (dest_objid, &lat, &lon, &alt, &x, &y, &z);
	
	/* relative location. */
	op_ima_obj_attr_get (src_objid, "x position", &src_nx);
	op_ima_obj_attr_get (src_objid, "y position", &src_ny);

	op_ima_obj_attr_get (dest_objid, "x position", &dest_nx);
	op_ima_obj_attr_get (dest_objid, "y position", &dest_ny);
	
	/* Update the node and subnet location in case they moved. */
	op_ima_obj_attr_get (src_objid, "name", &src_name);
	if (src_subnet)
		{
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, src_name, OPC_ANIM_OBJ_ATTR_XPOS, src_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, src_name, OPC_ANIM_OBJ_ATTR_YPOS, src_ny, OPC_EOL);
		}
	else
		{
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, src_name, OPC_ANIM_OBJ_ATTR_XPOS, src_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, src_name, OPC_ANIM_OBJ_ATTR_YPOS, src_ny, OPC_EOL);
		}
	
	op_ima_obj_attr_get (dest_objid, "name", &dest_name);
	if (dest_subnet)
		{
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, dest_name, OPC_ANIM_OBJ_ATTR_XPOS, dest_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, dest_name, OPC_ANIM_OBJ_ATTR_YPOS, dest_ny, OPC_EOL);
		}
	else
		{
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, dest_name, OPC_ANIM_OBJ_ATTR_XPOS, dest_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, dest_name, OPC_ANIM_OBJ_ATTR_YPOS, dest_ny, OPC_EOL);
		}
	
	/* Find the corresponding location from the animation viewer. */
	op_anim_ime_gen_pos (MipI_Anvid, src_nx, src_ny, &src_vx, &src_vy);
	op_anim_ime_gen_pos (MipI_Anvid, dest_nx, dest_ny, &dest_vx, &dest_vy);
	
	/* Call the function which will draw pipe based on the location passed to it. */
	mip_sup_draw_pipe_by_position (src_vx, src_vy, dest_vx, dest_vy, color, radius, pipe_ptr);
	
	FOUT;
	}


void
mip_sup_draw_pipe_by_position (int src_vx, int src_vy, int dest_vx, int dest_vy, 
	int color, int radius, MipT_Tunnel_Pipe* pipe_ptr)
	{
	int		props;
	double	slope;
	int		x_min, y_min, x_max, y_max;
	Boolean	x_axis = OPC_FALSE;
	Boolean	vertical_slope = OPC_FALSE;
	/* Function to draw pipe based on the parameters passed to it. */
	FIN (mip_sup_draw_pipe_by_position (params..));
	
	/* Draw intelligently. */
	if (src_vx < dest_vx)
		{
		x_min = src_vx; x_max = dest_vx;
		/* src is on the left of dest. */
		if (src_vy < dest_vy)
			{
			/* src is nw of dest. */
			y_min = src_vy; y_max = dest_vy;
			slope = (double)(y_max - y_min) / (double)(x_max - x_min);
			x_axis = (slope > 1.0) ? OPC_FALSE : OPC_TRUE;
			}
			
		if (src_vy == dest_vy)
			{
			/* src and dest on the same horizontal line. */
			slope = 0.0;
			x_axis = OPC_TRUE;
			}
	
		if (src_vy > dest_vy)
			{
			/* src is sw of dest. */
			y_min = dest_vy; y_max = src_vy;
			slope = -(double)(y_max - y_min) / (double)(x_max - x_min);
			x_axis = (slope < - 1.0) ? OPC_FALSE : OPC_TRUE;
			}
		}
		
	if (src_vx == dest_vx)
		{
		vertical_slope = OPC_TRUE;
		x_axis = OPC_FALSE;
		/* Src and dest on the same vertical line. */
		if (src_vy == dest_vy)
			{
			/* src and dest on the same position */
			FOUT;
			}
		}

	if (src_vx > dest_vx)
		{
		x_min = dest_vx; x_max = src_vx;
		/* Src is on the right of dest. */
		if (src_vy < dest_vy)
			{
			/* src is ne of dest. */
			y_min = src_vy; y_max = dest_vy;
			slope = - (double)(y_max - y_min) / (double)(x_max - x_min);
			x_axis = (slope < -1.0) ? OPC_FALSE : OPC_TRUE;
			}
			
		if (src_vy == dest_vy)
			{
			/* src and dest on the same horizontal line. */
			x_axis = OPC_TRUE;
			}
	
		if (src_vy > dest_vy)
			{
			/* src is se of dest. */
			y_min = dest_vy; y_max = src_vy;
			slope = (double)(y_max - y_min) / (double)(x_max - x_min);
			x_axis = (slope > 1.0) ? OPC_FALSE : OPC_TRUE;
			}
		}
		
	/* Set the properties for the pipe drawings. */
	props = OPC_ANIM_PIXOP_XOR | color | OPC_ANIM_RETAIN ;
	
	/* Start drawing. */
	pipe_ptr->src_center_x = src_vx;
	pipe_ptr->src_center_y = src_vy;
	pipe_ptr->dest_center_x = dest_vx;
	pipe_ptr->dest_center_y = dest_vy;
	pipe_ptr->radius = radius;
	pipe_ptr->color = color;
	
	/* Circles at the end first. */
	pipe_ptr->drawing_did [0] = op_anim_igp_circle_draw (MipI_Anvid, props, src_vx, src_vy, radius);
	pipe_ptr->drawing_did [1] = op_anim_igp_circle_draw (MipI_Anvid, props, dest_vx, dest_vy, radius);
	
	/* Draw the lines for the pipe. */
	if (x_axis)
		{
		/* We use the points on the circle on the y axis from the center of the circle. */
		pipe_ptr->src_point_1_x_1 = pipe_ptr->src_point_1_x = src_vx;
		pipe_ptr->src_point_2_x_1 = pipe_ptr->src_point_2_x = src_vx;
		pipe_ptr->src_point_1_y_1 = pipe_ptr->src_point_1_y = src_vy - radius;
		pipe_ptr->src_point_2_y_1 = pipe_ptr->src_point_2_y = src_vy + radius;
		pipe_ptr->dest_point_1_x_1 = pipe_ptr->dest_point_1_x = dest_vx;
		pipe_ptr->dest_point_2_x_1 = pipe_ptr->dest_point_2_x = dest_vx;
		pipe_ptr->dest_point_1_y_1 = pipe_ptr->dest_point_1_y = dest_vy - radius;
		pipe_ptr->dest_point_2_y_1 = pipe_ptr->dest_point_2_y = dest_vy + radius;
		}
	else
		{
		/* We use the points on the circle on the x axis from the center of the circle. */
		pipe_ptr->src_point_1_x_1 = pipe_ptr->src_point_1_x = src_vx - radius;
		pipe_ptr->src_point_2_x_1 = pipe_ptr->src_point_2_x = src_vx + radius;
		pipe_ptr->src_point_1_y_1 = pipe_ptr->src_point_1_y = src_vy;
		pipe_ptr->src_point_2_y_1 = pipe_ptr->src_point_2_y = src_vy;
		pipe_ptr->dest_point_1_x_1 = pipe_ptr->dest_point_1_x = dest_vx - radius;
		pipe_ptr->dest_point_2_x_1 = pipe_ptr->dest_point_2_x = dest_vx + radius;
		pipe_ptr->dest_point_1_y_1 = pipe_ptr->dest_point_1_y = dest_vy;
		pipe_ptr->dest_point_2_y_1 = pipe_ptr->dest_point_2_y = dest_vy;
		}
		
	/* Draw and store the id. */
	pipe_ptr->drawing_did [2] = op_anim_igp_line_draw (MipI_Anvid, props, pipe_ptr->src_point_1_x, 
		pipe_ptr->src_point_1_y, pipe_ptr->dest_point_1_x, pipe_ptr->dest_point_1_y);
	pipe_ptr->drawing_did [3] = op_anim_igp_line_draw (MipI_Anvid, props, pipe_ptr->src_point_2_x, 
		pipe_ptr->src_point_2_y, pipe_ptr->dest_point_2_x, pipe_ptr->dest_point_2_y);

	/* We will try drawing double width links for outer link only. */
	if (pipe_ptr->radius == MipC_Tunnel_Circle_Radius_Outer)
		{
		if (x_axis)
			{
			pipe_ptr->src_point_1_y_1--;
			pipe_ptr->src_point_2_y_1++;
			
			pipe_ptr->dest_point_1_y_1--;
			pipe_ptr->dest_point_2_y_1++;
			}
		else
			{
			pipe_ptr->src_point_1_x_1--;
			pipe_ptr->src_point_2_x_1++;
			
			pipe_ptr->dest_point_1_x_1--;
			pipe_ptr->dest_point_2_x_1++;
			}
		
		pipe_ptr->drawing_did [4] = op_anim_igp_line_draw (MipI_Anvid, props, pipe_ptr->src_point_1_x_1, 
			pipe_ptr->src_point_1_y_1, pipe_ptr->dest_point_1_x_1, pipe_ptr->dest_point_1_y_1);
		pipe_ptr->drawing_did [5] = op_anim_igp_line_draw (MipI_Anvid, props, pipe_ptr->src_point_2_x_1, 
			pipe_ptr->src_point_2_y_1, pipe_ptr->dest_point_2_x_1, pipe_ptr->dest_point_2_y_1);
		}
	
	FOUT;
	}


void	
mip_sup_pipe_erase( MipT_Tunnel_Pipe *pipe_ptr ) {
	/* Helper function for custom anime. */
	FIN (mip_sup_pipe_erase (pipe_ptr));

	/* Check the validity of the passed tunnel pipe pointer	*/
	if (pipe_ptr == OPC_NIL)
		FOUT;
	
	op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [0], OPC_ANIM_ERASE_MODE_XOR);
	op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [1], OPC_ANIM_ERASE_MODE_XOR);
	op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [2], OPC_ANIM_ERASE_MODE_XOR);
	op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [3], OPC_ANIM_ERASE_MODE_XOR);
	
	/* Draw double width. */
	if (pipe_ptr->radius == MipC_Tunnel_Circle_Radius_Outer) {
		op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [4], OPC_ANIM_ERASE_MODE_XOR);
		op_anim_igp_drawing_erase (MipI_Anvid, pipe_ptr->drawing_did [5], OPC_ANIM_ERASE_MODE_XOR);
  }

	/* Reset the pipe object pointer. */
	pipe_ptr = OPC_NIL;

	FOUT;
}
	
void
mip_sup_mn_position_update (void* PRG_ARG_UNUSED (vptr), int PRG_ARG_UNUSED (code)) {
	int			list_cnt, list_idx, obj_cnt, obj_idx;
	double		lat, lon, alt, x, y, z, mob_nx, mob_ny;
	char		mob_name [128];
	Objid		mob_objid;
	MipT_Tunnel*	tmp_tunnel_obj;
	
	/* Helper function to update mobile node positions and tunnel to the agents. */
	FIN (mip_sup_mn_position_update (vptr, code));
	
	/* Verify the existence of MN list. */
	if (mn_tunnel_lptr != OPC_NIL)
		{
		/* Go through the list passed. */
		list_cnt = op_prg_list_size (mn_tunnel_lptr);
		for ( list_idx=0; list_idx < list_cnt; list_idx++ ) {
			tmp_tunnel_obj = (MipT_Tunnel*) op_prg_list_access (mn_tunnel_lptr, list_idx);
			if ( tmp_tunnel_obj->double_tunnel ) {
				/* See if we have any existing tunnel. */
				if ( tmp_tunnel_obj->inner_pipe_fa_mr ) {
					/* Redraw the tunnel periodically so that the node movements are updated as well. */
					mip_sup_pipe_erase( tmp_tunnel_obj->inner_pipe_fa_mr );
					mip_sup_draw_pipe( tmp_tunnel_obj->mn_objid, tmp_tunnel_obj->fa_objid, MipC_Tunnel_Inner_Color, MipC_Tunnel_Circle_Radius_Inner, 
						&tmp_tunnel_obj->inner_pipe_fa_mr);
					}
				}
			}
		}
	
	/* We want to generally animate movement every so senconds. */
	obj_cnt = op_topo_child_count (MipI_Subnet_Objid, OPC_OBJTYPE_SUBNET_MOB);
	for (obj_idx=0; obj_idx < obj_cnt; obj_idx++)
		{
		/* Access the mobility subnet/node and update location. */
		mob_objid = op_topo_child (MipI_Subnet_Objid, OPC_OBJTYPE_SUBNET_MOB, obj_idx);
			
		/* Force the location update. */
		op_ima_obj_pos_get (mob_objid, &lat, &lon, &alt, &x, &y, &z);
	
		/* relative location. */
		op_ima_obj_attr_get (mob_objid, "x position", &mob_nx);
		op_ima_obj_attr_get (mob_objid, "y position", &mob_ny);
	
		/* Update the node and subnet location in case they moved. */
		op_ima_obj_attr_get (mob_objid, "name", &mob_name);

		/* Update the animation. */
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, mob_name, OPC_ANIM_OBJ_ATTR_XPOS, mob_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_SUBNET, mob_name, OPC_ANIM_OBJ_ATTR_YPOS, mob_ny, OPC_EOL);
		}
	
	/* We want to generally animate movement every so senconds. */
	obj_cnt = op_topo_child_count (MipI_Subnet_Objid, OPC_OBJTYPE_NODE_MOB);
	for (obj_idx=0; obj_idx < obj_cnt; obj_idx++)
		{
		/* Access the mobility subnet/node and update location. */
		mob_objid = op_topo_child (MipI_Subnet_Objid, OPC_OBJTYPE_NODE_MOB, obj_idx);
			
		/* Force the location update. */
		op_ima_obj_pos_get (mob_objid, &lat, &lon, &alt, &x, &y, &z);
	
		/* relative location. */
		op_ima_obj_attr_get (mob_objid, "x position", &mob_nx);
		op_ima_obj_attr_get (mob_objid, "y position", &mob_ny);
	
		/* Update the node and subnet location in case they moved. */
		op_ima_obj_attr_get (mob_objid, "name", &mob_name);

		/* Update the animation. */
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, mob_name, OPC_ANIM_OBJ_ATTR_XPOS, mob_nx, OPC_EOL);
		op_anim_ime_nobj_update (MipI_Anvid, OPC_ANIM_OBJTYPE_NODE, mob_name, OPC_ANIM_OBJ_ATTR_YPOS, mob_ny, OPC_EOL);
		}

	/* Schedule the next call. */
	op_intrpt_schedule_call (op_sim_time () + MipI_Position_Update_Interval, 0, mip_sup_mn_position_update, OPC_NIL);
	
	FOUT;
	}

void
mip_sup_animation_legend (void)
   {
   /* Helper function to draw the legend in case custom animation is used. */
   FIN (mip_sup_animation_legend (void));
   
   /* Write out the title. */
   op_anim_igp_rect_draw (MipI_Anvid, OPC_ANIM_COLOR_BLUE | OPC_ANIM_RETAIN, MipC_Anime_Legend_Position_X,
	   MipC_Anime_Legend_Position_Y, MipC_Anime_Legend_Position_W, MipC_Anime_Legend_Position_H);
	  
   op_anim_igp_text_draw (MipI_Anvid, OPC_ANIM_COLOR_BLACK | OPC_ANIM_RETAIN, MipC_Anime_Legend_Position_X,
	   MipC_Anime_Legend_Position_Y, "LEGEND");
   
   /* Write out the tunnels and all. */
   op_anim_igp_text_draw (MipI_Anvid, OPC_ANIM_COLOR_BLACK | OPC_ANIM_RETAIN, 
	   MipC_Anime_Legend_Position_X + 10, MipC_Anime_Legend_Position_Y + 30, "Outer Tunnel");
   op_anim_igp_text_draw (MipI_Anvid, OPC_ANIM_COLOR_BLACK | OPC_ANIM_RETAIN,
	   MipC_Anime_Legend_Position_X + 10, MipC_Anime_Legend_Position_Y + 60, "Inner Tunnel");
  
   /* Draw the example pipes. */
   mip_sup_draw_pipe_by_position (MipC_Anime_Legend_Position_X + 95, MipC_Anime_Legend_Position_Y + 35,
	   MipC_Anime_Legend_Position_X + 135, MipC_Anime_Legend_Position_Y + 35, MipC_Tunnel_Outer_Color, 
	   MipC_Tunnel_Circle_Radius_Outer, (MipT_Tunnel_Pipe*) op_prg_mem_alloc (sizeof (MipT_Tunnel_Pipe)));
								  
   mip_sup_draw_pipe_by_position (MipC_Anime_Legend_Position_X + 95, MipC_Anime_Legend_Position_Y + 65,
	   MipC_Anime_Legend_Position_X + 135, MipC_Anime_Legend_Position_Y + 65, MipC_Tunnel_Inner_Color, 
	   MipC_Tunnel_Circle_Radius_Inner, (MipT_Tunnel_Pipe*) op_prg_mem_alloc (sizeof (MipT_Tunnel_Pipe)));
   
   FOUT; 
   }

