/* Process model C++ form file: HMIPv6_MAP.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char HMIPv6_MAP_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 4B70C843 4B70C843 1 planet12 Student 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                         ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <opnet.h>
#include <hmipv6_defs.h>
#include <hmipv6_support.h>
#include <hmipv6_common.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ipv6_extension_headers_defs.h>
#include <ipv6_extension_headers_sup.h>
#include <ip_dgram_sup.h>
#include <ipv6_ra.h>
#include <ip_arp.h>
#include <ip_icmp_pk.h>
#include <mobile_ip_support.h>
#include <string.h>
#include <string>
#include <map>

using std::string;
using std::map;

//extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];
int	mobility_msg_size_in_bits [MIPV6C_MOB_MSG_COUNT] = { 64, 128, 128, 192, 192, 128, 128, 192 };

/* Make sure lower modules have registered them selves properly */
#define SELF_NOTIFY  ( op_intrpt_type() == OPC_INTRPT_SELF )

/* Indicates BU arrival from lower layer IP Module */
#define BU_PACKET  ( bu_packet == true )

/**
 * Redirect this packet into map domain.
 */
#define TUNNEL_OUT ( tunnelin == true )

/**
 */
#define TUNNEL_IN ( tunnelout == true )

/* Define the packet source index for incoming stream */
#define IN_STRM   0

/* Define the packet source index for the output stream */
#define OUT_STRM  1


bool is_bind_update( Packet* packet );

bool cache_has_lcoa( std::string address );

/**
 * Make sure the given packet is the correct format
 */
bool correct_packet_fmt( Packet* packet );

/**
 * Set the destination of a packet to new value.
 */
Packet* set_destination( Packet* packet, address_t destination );

/**
 * Obtain the regional care of address from the packet.
 */
address_t get_RCoA( Packet* packet );

/**
 * Send a binding acknowledgment to destination.
 */
void send_BAck( address_t destination, address_t RCoA  );
 
/**
 * This function removes and IPv6 in IPv6 encapsulated packet.
 * It is used at the end point of a HMIPv6 tunnel. 
 */ 
void decapsulate_pkt( Packet** packet );

/** 
 * Encapsulates IPv6 in IPv6 packets to be transported by a MIPv6 tunnel. 
 */
void
tunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** packet, InetT_Address source, InetT_Address dest_address );



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
class HMIPv6_MAP_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		HMIPv6_MAP_state (void);

		/* Destructor contains Termination Block */
		~HMIPv6_MAP_state (void);

		/* State Variables */
		Prohandle	              		selfHndl                                        ;	/* Modules own process handle */
		Prohandle	              		parentHndl                                      ;	/* Modules parent process handle */
		Objid	                  		selfId                                          ;	/* Our own Object ID */
		Objid	                  		parentId                                        ;	/* Object ID of the parent */
		char	                   		modelName[10]                                   ;	/* cstring to hold the this model's name */
		OmsT_Pr_Handle	         		procHndl                                        ;	/* Handle for this process after registration */
		bool	                   		bu_packet                                       ;	/* We received a packet from the IP */
		                        		                                                	/*                                  */
		Packet *	               		currpacket                                      ;
		bool	                   		tunnelout                                       ;
		std::map<std::string, std::string>			bind_cache                                      ;
		std::string	            		dest                                            ;
		bool	                   		tunnelin                                        ;
		std::string	            		src                                             ;
		address_t	              		map_address                                     ;

		/* FSM code */
		void HMIPv6_MAP (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype HMIPv6_MAP_state::obtype = (VosT_Obtype)OPC_NIL;

#define selfHndl                		op_sv_ptr->selfHndl
#define parentHndl              		op_sv_ptr->parentHndl
#define selfId                  		op_sv_ptr->selfId
#define parentId                		op_sv_ptr->parentId
#define modelName               		op_sv_ptr->modelName
#define procHndl                		op_sv_ptr->procHndl
#define bu_packet               		op_sv_ptr->bu_packet
#define currpacket              		op_sv_ptr->currpacket
#define tunnelout               		op_sv_ptr->tunnelout
#define bind_cache              		op_sv_ptr->bind_cache
#define dest                    		op_sv_ptr->dest
#define tunnelin                		op_sv_ptr->tunnelin
#define src                     		op_sv_ptr->src
#define map_address             		op_sv_ptr->map_address

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	HMIPv6_MAP_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((HMIPv6_MAP_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

/**
 * Inspect the given packet, is it a bind update?
 *
 * @param packet - The packet to inspect.
 * @return true if bu, false if not.
 */
bool is_bind_update( Packet* packet ) { 

  List* list;
  IpT_Dgram_Fields* fields;
  Ipv6T_Mobility_Hdr_Info* info;

	FIN( is_bind_update( packet ) );

  if ( correct_packet_fmt( packet ) ) {

    fields = ip_dgram_fields_get( packet );

    /* check the  extionsion types */
    if ( IpC_Procotol_Mobility_Ext_Hdr == fields->protocol ) {

      /* Grab the mobility headers */
      list = ipv6_extension_header_list_get( fields );
      info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );

      if ( Mipv6C_Bind_Update == info->mh_type ) {
        /* This is obviously a binding update */
        puts( "HMIPv6 MAP: Got Binding Update" );
        FRET( true );
      }
    }
  }

  FRET( false );
}

/**
 * Reverse lookup the LCoA in the binding cache
 *
 * @param address - The address we are looking for.
 * @return true if found, false if not.
 */
bool cache_has_lcoa( std::string address ) { 

  std::map<std::string,std::string>::iterator i;

	FIN( cache_has_lcoa( void ) );

  for( i = bind_cache.begin(); i != bind_cache.end(); i++ ) {
    if ( address.compare( i->second ) == 0 )
      printf( "HMIPv6 MAP: Cache has: %s", address.c_str() );
      FRET( true );
  }

  printf( "HMIPv6 MAP: !Cache missing: %s", address.c_str() );
  FRET( false );
}

/**
 * Set the destination of a packet to new value.
 */
Packet* set_source( Packet* packet, std::string src_str ) {

  address_t source;
  IpT_Dgram_Fields* fields;

	FIN( set_destination( packet, src_str ) );

  source = stringToAddress( src_str );

	op_pk_nfd_access( packet, "fields", &fields );

  fields->src_addr = inet_address_copy( source );
  fields->src_internal_addr = inet_rtab_addr_convert( fields->src_addr );

	op_pk_nfd_set( packet, "fields", fields );

  FRET( packet );
}


/**
 * Set the destination of a packet to new value.
 */
Packet* set_destination( Packet* packet, std::string dest_str ) {

  address_t destination;
  IpT_Dgram_Fields* fields;

	FIN( set_destination( packet, dest_str ) );

  destination = stringToAddress( dest_str );

	op_pk_nfd_access( packet, "fields", &fields );

  fields->dest_addr = inet_address_copy( destination );
  fields->dest_internal_addr = inet_rtab_addr_convert( fields->dest_addr );

	op_pk_nfd_set( packet, "fields", fields );

  FRET( packet );
}


/**
 * Obtain the regional care of address from the packet.
 *
 * @param packet - The packet to inspect
 * @return the regional care of address from the mobility headers.
 */
address_t get_RCoA( Packet* packet ) {
  
  List* list;
  address_t RCoA;
  IpT_Dgram_Fields* fields;
  Ipv6T_Mobility_Hdr_Info* info;
  std::string address;

  FIN( get_RCoA( packet ) ); 

  fields = ip_dgram_fields_get( packet );
  /* Grab the mobility headers */
  list = ipv6_extension_header_list_get( fields );
  info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );

   

  RCoA = inet_address_copy( info->msg_data.bind_update.home_address );

  address = addressToString( RCoA );
  printf( "HMIPv6 MAP: RCoA obtained: %s", address.c_str() );

  FRET( RCoA );
}

/**
 * Send a binding acknowledgment to destination.
 */
void send_BAck( address_t destination, address_t RCoA ) {
  Packet*           packet;
  OpT_Packet_Size   ext_hdr_len;
  IpT_Dgram_Fields* dgram;
  Ipv6T_Mobility_Hdr_Info*  header;

  FIN( send_BAck( destination ) ); 
  
  /* Create the IP datagram. */
  packet = ip_dgram_create();
  
  /* Get the size contributed by the mobility header. */
  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_ACK];
  
  /* Create IP datagram fields data structure. */
  dgram = ip_dgram_fdstruct_create();

  /* Assign values to members of the field structure. */
  /* Set the source address to be the global address of interface. */
  
  /* The ha iface ptr must be obtained from the ha iface table. */  
  // TODO: Get MAP's actuall IP Address
  //dgram->src_addr     = inet_address_copy( *(module_data_ptr->mipv6_info_ptr->care_of_addr_ptr));
  //dgram->src_internal_addr  = inet_rtab_addr_convert( dgram->src_addr );
  dgram->src_addr = inet_address_copy( InetI_Default_v6_Addr );
  dgram->src_internal_addr = inet_rtab_addr_convert( InetI_Default_v6_Addr );
  
  /* Set the destination address (MN). */  
  dgram->dest_addr          = inet_address_copy( destination );
  dgram->dest_internal_addr = inet_rtab_addr_convert( destination );

  /* No data packet is encapsulated in this datagram, use */
  /* the length fields to model the extension header size.*/
  dgram->orig_len = ext_hdr_len;
  dgram->frag_len = ext_hdr_len;
  dgram->ttl      = 255;
  
  /* The protocol field (next header in IPv6) must    */
  /* indicate that this is a mobility extension header. */
  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;

  /* Set the message fields to the indicated values. */
  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Ack );
  header->msg_data.bind_update.home_address = inet_address_copy( RCoA );

  /* Set the mobility header information in the datagram fields. */
  ipv6_mobility_hdr_insert( dgram, header );
  
  /* Set the datagram fields into the IPv6 datagram. */
  ip_dgram_fields_set( packet, dgram );

  /* Refresh the IP packet fields. */
  op_pk_nfd_access( packet, "fields", &dgram );

  /* Alter the header field size to model the mob msg size. */ 

  /* Add the size of the mobility extension header into */
  /* the packet. Modify the size of the header fields in   */
  /* the IPv6 packet to achieve this.           */

  ip_dgram_sup_ipv6_extension_hdr_size_add( &packet, &dgram,
      IpC_Procotol_Mobility_Ext_Hdr, (int) ext_hdr_len );

  /* Uninstall the event state. */
  op_ev_state_install( OPC_NIL, OPC_NIL);
    
  /* Deliver this IPv6 datagram to the IP module. */
  op_pk_deliver( packet, selfId, OUT_STRM );

  FOUT;
} 

/**
 * This function removes and IPv6 in IPv6 encapsulated packet.
 * It is used at the end point of a HMIPv6 tunnel. 
 */ 
void decapsulate_pkt( Packet** packet ) {

  Packet* encapsulated_packet;

  FIN( decapsulate_pkt( packet ) );

  /* Access the encapsulated packet. */
  op_pk_nfd_get( *packet, "data", &encapsulated_packet );
  
  /* Destroy the carrier packet. */
  op_pk_destroy( *packet );
  
  /* Give the encapsulated packet to the caller. */
  *packet = encapsulated_packet;

  FOUT;
}

/** 
 * Encapsulates IPv6 in IPv6 packets to be transported by a MIPv6 tunnel. 
 */
void
tunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** packet, InetT_Address source, InetT_Address dest_address ) {

  Packet* ip_packet;
  IpT_Dgram_Fields* new_datagram;
  IpT_Dgram_Fields* old_datagram;

  FIN( tunnel_pkt( iprmd_ptr, packet, source, dest_address ) );

  /* Access the old field information.            */
  op_pk_nfd_access( *packet, "fields", &old_datagram );

  /* Create the IP datagram. */
  ip_packet = ip_dgram_create();

  /* Set the bulk size of the IP packet to model the space  */
  /* occupied by the encapsulated IP packet. This is equal to */
  /* the data packet plus the size of the ICMP header.    */
  op_pk_bulk_size_set( ip_packet, op_pk_total_size_get( *packet ) );

  /* Since no request should be made to the IP process,   */
  /* explicitly de-install any outstanding ICIs.        */
  op_ici_install( OPC_NIL );

  /* Copy the old info field to create new one for the outer packet. */
  new_datagram = ip_dgram_fdstruct_copy( old_datagram );

  /* Remove the extension headers if any. The outer packet  */
  /* of a MIPv6 tunnel must not carry any IPv6 extension    */
  /* headers, otherwise MIPv6 may process it as a MIPv6     */
  /* control message.                     */
  if ( ipv6_extension_header_exists( new_datagram ) ) {
    /* Remove the extension headers from the outer packet.  */
    ip_dgram_extension_headers_info_destroy( new_datagram );   
  }

  /* While copying the contents of the IPv6 header fields   */
  /* copies of the original source and destination IPv6     */
  /* addresses were allocated in memory. They must be     */
  /* destroyed since they will be replaced by the tunnels   */
  /* source and destination addresses.            */
  inet_address_destroy( new_datagram->src_addr );
  inet_address_destroy( new_datagram->dest_addr );
  
  /* Set the destination address for this IP datagram.    */
  new_datagram->src_addr = inet_address_copy( source );

  /* Also set the internal source address.          */
  new_datagram->src_internal_addr = inet_rtab_addr_convert( source );

  /* Set the destination address for this IP datagram.    */
  new_datagram->dest_addr = inet_address_copy( dest_address );

  /* Also set the internal destination address.       */  
  new_datagram->dest_internal_addr = inet_rtab_addr_convert( dest_address );
  
  /* The protocol fields  must indicate that there is an IPv6 */
  /* datagram encapsulated in this packet.          */
  new_datagram->protocol = IpC_Protocol_IPv6;
  
  /* Set the packet size-related fields of the IP datagram. */
  new_datagram->orig_len = op_pk_total_size_get( *packet ) / 8;
  new_datagram->frag_len = new_datagram->orig_len;
  new_datagram->original_size = 160 + new_datagram->orig_len * 8;

  /* Indicate that the packet is not yet fragmented.      */
  new_datagram->frag = 0;

  /* Set the encapsulation count for sim efficiency.      */
  new_datagram->encap_count++;

  new_datagram->dest_internal_addr = IPC_FAST_ADDR_INVALID;
  new_datagram->src_internal_addr  = IPC_FAST_ADDR_INVALID;

  /*  Set the fields structure inside the ip datagram.    */
  op_pk_nfd_set( ip_packet, "fields", new_datagram, 
      ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields) );

  /* Set the original IP packet in the data field of the new  IP datagram. */
  op_pk_nfd_set( ip_packet, "data", *packet );

  /* Return the outer packet. */
  *packet = ip_packet;
  
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

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef selfHndl
#undef parentHndl
#undef selfId
#undef parentId
#undef modelName
#undef procHndl
#undef bu_packet
#undef currpacket
#undef tunnelout
#undef bind_cache
#undef dest
#undef tunnelin
#undef src
#undef map_address

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_HMIPv6_MAP_init (int * init_block_ptr);
	VosT_Address _op_HMIPv6_MAP_alloc (VosT_Obtype, int);
	void HMIPv6_MAP (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MAP_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->HMIPv6_MAP (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MAP_svar (void *, const char *, void **);

	void _op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MAP_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MAP_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (HMIPv6_MAP_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
HMIPv6_MAP_state::HMIPv6_MAP (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (HMIPv6_MAP_state::HMIPv6_MAP ());
	try
		{


		FSM_ENTER ("HMIPv6_MAP")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "HMIPv6_MAP [init enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [init enter execs]", state0_enter_exec)
				{
				/***
				 * 1) Register process in the global table.
				 * 2) Obtain model parameters
				 *      e.g. operation mode
				 *
				 *
				 * Declared in State Variables:
				 *  - selfId
				 *  - parentId
				 *  - selfHndl
				 *  - parentHndl
				 *  - modelName 
				 *  - procHndl
				 ***/
				
				/* Get self id and our parent's id */
				selfId   = op_id_self();
				parentId = op_topo_parent( selfId );
				
				/* Obtain process model name */
				op_ima_obj_attr_get( selfId, "process model", modelName );
				
				/* Obtain handles for our self and our parent */
				selfHndl   = op_pro_self();
				parentHndl = op_pro_parent( selfHndl );  
				
				
				/* Register the process in model-wide registry */
				procHndl = (OmsT_Pr_Handle)oms_pr_process_register( parentId, selfId, selfHndl, modelName );
				
				/* Register the protocol attribute in the	registry. */
				oms_pr_attr_set( procHndl, "protocol", OMSC_PR_STRING, "mipv6", OPC_NIL );
				
				puts( "HMIPv6 MAP: Initialized MAP"  );
				
				/* Initialize state variables */
				bu_packet = false;
				tunnelout = false;
				tunnelin  = false;
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"HMIPv6_MAP")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "HMIPv6_MAP [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFY), 1, state1_enter_exec, ;, init, "SELF_NOTIFY", "", "init", "idle", "tr_16", "HMIPv6_MAP [init -> idle : SELF_NOTIFY / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "idle", state1_enter_exec, "HMIPv6_MAP [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"HMIPv6_MAP")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "idle", "HMIPv6_MAP [idle exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [idle exit execs]", state1_exit_exec)
				{
				/***
				 * Sate Variables:
				 *   Packet * currpacket 
				 *   bool bu_packet
				 *   bool redirect 
				 *   map<string,string> bind_cache
				 *
				 * Purpose: Inspect incoming packets 
				 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
				 */
				
				if( op_intrpt_type() == OPC_INTRPT_STRM ) {
				
				    puts( "HMIPv6 MAP: got packet\n" );
				    currpacket = op_pk_get( IN_STRM );
				
				    /* Make sure the packet is sound */
				    if ( (NULL != currpacket) && correct_packet_fmt( currpacket ) ) {
				
				      dest = addressToString( dest_address( currpacket ) );
				      src  = addressToString(  src_address( currpacket ) );
				
				      /* Check if the packet is a bind update */
				      if ( is_bind_update( currpacket ) ) {
				        bu_packet = true;
				        /* Try to find an address for the destination */
				      } else if ( bind_cache.find( dest ) != bind_cache.end() ) { 
				        tunnelin = true;
				        /* Try to find an address for the source */
				      } else if ( cache_has_lcoa( src ) ) {
				        tunnelout = true;
				      } else {
				        op_pk_destroy( currpacket );
				      }
				    } else {
				      op_pk_destroy( currpacket );
				    }
				}
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [idle trans conditions]", state1_trans_conds)
			FSM_INIT_COND (BU_PACKET)
			FSM_TEST_COND (TUNNEL_OUT)
			FSM_TEST_COND (TUNNEL_IN)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 2, state2_enter_exec, ;, "BU_PACKET", "", "idle", "BU", "tr_3", "HMIPv6_MAP [idle -> BU : BU_PACKET / ]")
				FSM_CASE_TRANSIT (1, 4, state4_enter_exec, ;, "TUNNEL_OUT", "", "idle", "TNL_OUT", "tr_14", "HMIPv6_MAP [idle -> TNL_OUT : TUNNEL_OUT / ]")
				FSM_CASE_TRANSIT (2, 3, state3_enter_exec, ;, "TUNNEL_IN", "", "idle", "TNL_IN", "tr_20", "HMIPv6_MAP [idle -> TNL_IN : TUNNEL_IN / ]")
				FSM_CASE_TRANSIT (3, 1, state1_enter_exec, ;, "default", "", "idle", "idle", "tr_24", "HMIPv6_MAP [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (BU) enter executives **/
			FSM_STATE_ENTER_FORCED (2, "BU", state2_enter_exec, "HMIPv6_MAP [BU enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [BU enter execs]", state2_enter_exec)
				{
				/**
				 * Modify Source Address if RCoA is active.
				 * Relay currpacket to PPP
				 */
				
				puts( "HMIPv6 MAP: Process Binding Update\n" );
				
				std::string LCoA = addressToString( src_address( currpacket ) );
				
				std::string RCoA = addressToString( get_RCoA( currpacket ) );
				
				/* Insert address into cache */
				bind_cache[RCoA] = LCoA;
				
				/* Send a binding acknoledgement to the MN */
				send_BAck( stringToAddress( LCoA ), stringToAddress( RCoA ) );
				
				op_pk_destroy( currpacket );
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** state (BU) exit executives **/
			FSM_STATE_EXIT_FORCED (2, "BU", "HMIPv6_MAP [BU exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [BU exit execs]", state2_exit_exec)
				{
				// Reset our state back to false
				bu_packet = false;
				}
				FSM_PROFILE_SECTION_OUT (state2_exit_exec)


			/** state (BU) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "BU", "idle", "tr_2", "HMIPv6_MAP [BU -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (TNL_IN) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "TNL_IN", state3_enter_exec, "HMIPv6_MAP [TNL_IN enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [TNL_IN enter execs]", state3_enter_exec)
				{
				/**
				 * Sate Variables:
				 *   Packet * currpacket 
				 *   bool bu_packet
				 *   bool redirect 
				 *
				 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
				 * Action: Update variables to indicate that RCoA is active
				 */
				
				puts( "HMIPv6 MAP: Tunnel packet in\n" );
				
				/* Obtaion the currpackets regional care of address */
				std::string RCoA = addressToString( dest_address( currpacket ) );
				
				// Set the destionation address of the currpacket
				// to the cached local care of address 
				currpacket = set_destination( currpacket, bind_cache[RCoA] );
				
				/* Send the currpacket back to the IP module */
				op_pk_send( currpacket, OUT_STRM );
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (TNL_IN) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "TNL_IN", "HMIPv6_MAP [TNL_IN exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [TNL_IN exit execs]", state3_exit_exec)
				{
				// Reset our state back to false
				tunnelin = false;
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (TNL_IN) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "TNL_IN", "idle", "tr_21", "HMIPv6_MAP [TNL_IN -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (TNL_OUT) enter executives **/
			FSM_STATE_ENTER_FORCED (4, "TNL_OUT", state4_enter_exec, "HMIPv6_MAP [TNL_OUT enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [TNL_OUT enter execs]", state4_enter_exec)
				{
				/**
				 * Sate Variables:
				 *   Packet * currpacket 
				 *   bool bu_packet
				 *   bool redirect 
				 *
				 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
				 * Action: Update variables to indicate that RCoA is active
				 */
				
				puts( "HMIPv6 MAP: Tunnel packet out\n" );
				
				std::map<string,string>::iterator it;
				
				/* Obtaion the currpackets regional care of address */
				std::string LCoA = addressToString( src_address( currpacket ) );
				std::string RCoA("");
				/* look up the RCoA care of address for this */
				for( it = bind_cache.begin(); it != bind_cache.end(); it++ ) {
				  if ( LCoA.compare( it->second ) == 0 ) {
				    RCoA = it->first;
				    break;
				  }
				}
				
				// Set the destionation address of the currpacket
				// to the cached local care of address 
				currpacket = set_source( currpacket, RCoA );
				
				/* Send the currpacket back to the IP module */
				op_pk_send( currpacket, OUT_STRM );
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** state (TNL_OUT) exit executives **/
			FSM_STATE_EXIT_FORCED (4, "TNL_OUT", "HMIPv6_MAP [TNL_OUT exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [TNL_OUT exit execs]", state4_exit_exec)
				{
				// Reset state back to false
				tunnelout = false;
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (TNL_OUT) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "TNL_OUT", "idle", "tr_15", "HMIPv6_MAP [TNL_OUT -> idle : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"HMIPv6_MAP")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (HMIPv6_MAP)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
HMIPv6_MAP_state::_op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
HMIPv6_MAP_state::operator delete (void* ptr)
	{
	FIN (HMIPv6_MAP_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

HMIPv6_MAP_state::~HMIPv6_MAP_state (void)
	{

	FIN (HMIPv6_MAP_state::~HMIPv6_MAP_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
HMIPv6_MAP_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (HMIPv6_MAP_state::operator new ());

	new_ptr = Vos_Alloc_Object (HMIPv6_MAP_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

HMIPv6_MAP_state::HMIPv6_MAP_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "HMIPv6_MAP [init enter execs]";
#endif
	}

VosT_Obtype
_op_HMIPv6_MAP_init (int * init_block_ptr)
	{
	FIN_MT (_op_HMIPv6_MAP_init (init_block_ptr))

	HMIPv6_MAP_state::obtype = Vos_Define_Object_Prstate ("proc state vars (HMIPv6_MAP)",
		sizeof (HMIPv6_MAP_state));
	*init_block_ptr = 0;

	FRET (HMIPv6_MAP_state::obtype)
	}

VosT_Address
_op_HMIPv6_MAP_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	HMIPv6_MAP_state * ptr;
	FIN_MT (_op_HMIPv6_MAP_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new HMIPv6_MAP_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new HMIPv6_MAP_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_HMIPv6_MAP_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	HMIPv6_MAP_state		*prs_ptr;

	FIN_MT (_op_HMIPv6_MAP_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (HMIPv6_MAP_state *)gen_ptr;

	if (strcmp ("selfHndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->selfHndl);
		FOUT
		}
	if (strcmp ("parentHndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->parentHndl);
		FOUT
		}
	if (strcmp ("selfId" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->selfId);
		FOUT
		}
	if (strcmp ("parentId" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->parentId);
		FOUT
		}
	if (strcmp ("modelName" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->modelName);
		FOUT
		}
	if (strcmp ("procHndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->procHndl);
		FOUT
		}
	if (strcmp ("bu_packet" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bu_packet);
		FOUT
		}
	if (strcmp ("currpacket" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->currpacket);
		FOUT
		}
	if (strcmp ("tunnelout" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tunnelout);
		FOUT
		}
	if (strcmp ("bind_cache" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bind_cache);
		FOUT
		}
	if (strcmp ("dest" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->dest);
		FOUT
		}
	if (strcmp ("tunnelin" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->tunnelin);
		FOUT
		}
	if (strcmp ("src" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->src);
		FOUT
		}
	if (strcmp ("map_address" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->map_address);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

