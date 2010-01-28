/* Process model C++ form file: HMIPv6_MN_NEW.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char HMIPv6_MN_NEW_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 4B5A3FCB 4B5A3FCB 1 planet12 Student 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                         ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <opnet.h>
#include <hmipv6_defs.h>
#include <hmipv6_defs.h>
#include <hmipv6_support.h>
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

extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];

/* Make sure processes of lower modules have registered in global process */
#define SELF_NOTIF   ( op_intrpt_type() == OPC_INTRPT_SELF )
/* Stream interupt indicating packet arrival from higher layer IP Module */
#define INCOMING_PKT  ( incomingpkt == true ) 

#define ADDRESS_CHANGED ( address_changed == true )

/* Define the packet source index for incoming stream */
#define IN_STRM   0

/* Define the packet source index for the output stream */
#define OUT_STRM  1

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
class HMIPv6_MN_NEW_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		HMIPv6_MN_NEW_state (void);

		/* Destructor contains Termination Block */
		~HMIPv6_MN_NEW_state (void);

		/* State Variables */
		address_t	              		lcoa                                            ;
		Prohandle	              		selfHndl                                        ;
		Prohandle	              		parentHndl                                      ;
		Objid	                  		selfId                                          ;
		Objid	                  		parentId                                        ;
		address_t	              		map_address                                     ;
		Packet *	               		currpacket                                      ;
		bool	                   		address_changed                                 ;
		address_t	              		rcoa                                            ;
		char	                   		modelName[10]                                   ;
		OmsT_Pr_Handle	         		procHndl                                        ;

		/* FSM code */
		void HMIPv6_MN_NEW (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_HMIPv6_MN_NEW_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype HMIPv6_MN_NEW_state::obtype = (VosT_Obtype)OPC_NIL;

#define lcoa                    		op_sv_ptr->lcoa
#define selfHndl                		op_sv_ptr->selfHndl
#define parentHndl              		op_sv_ptr->parentHndl
#define selfId                  		op_sv_ptr->selfId
#define parentId                		op_sv_ptr->parentId
#define map_address             		op_sv_ptr->map_address
#define currpacket              		op_sv_ptr->currpacket
#define address_changed         		op_sv_ptr->address_changed
#define rcoa                    		op_sv_ptr->rcoa
#define modelName               		op_sv_ptr->modelName
#define procHndl                		op_sv_ptr->procHndl

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	HMIPv6_MN_NEW_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((HMIPv6_MN_NEW_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

/**
 * Make sure the given packet is the correct format
 */
bool correct_packet_fmt( Packet* packet ) {

  char format[100];

	FIN( correct_packet_fmt( packet ) );

  op_pk_format( packet, format );

  if ( strcmp( "ip_dgram_v4", format ) == 0 ) {
    FRET( true );
  } else {
    FRET( false );
  }
}

/**
 * Inspect the given packet, is it a Binding Ack?
 *
 * @param packet - The packet to inspect.
 * @return true if BAck, false if not.
 */
bool is_bind_ack( Packet* packet ) { 

  List* list;
  IpT_Dgram_Fields* fields;
  Ipv6T_Mobility_Hdr_Info* info;

	FIN( is_bind_ack( packet ) );

  if ( correct_packet_fmt( packet ) ) {

    fields = ip_dgram_fields_get( packet );

    /* check the  extionsion types */
    if ( IpC_Procotol_Mobility_Ext_Hdr == fields->protocol ) {

      /* Grab the mobility headers */
      list = ipv6_extension_header_list_get( fields );
      info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );

      if ( Mipv6C_Bind_Ack == info->mh_type ) {
        /* This is obviously a binding update */
        FRET( true );
      }
    }
  }
  FRET( false );
}

/**
 * Generate a regional care of address.
 */
address_t generate_rcoa( void ) {
  address_t RCoA;

  FIN( get_lcoa( void ) );

  RCoA = InetI_Invalid_Addr;

  FRET( RCoA );
}

/**
 * Obtain the current ip_address of the mobile node
 */
address_t get_lcoa( void ) {
  address_t LCoA;

  FIN( get_lcoa( void ) );

  LCoA = inet_support_address_from_node_id_get( parentId, InetC_Addr_Family_v6 );

  FRET( LCoA );
}

/**
 * Determine if our ip_address had changed
 */
bool has_lcoa_changed( void ) {
  address_t my_address;

  FIN( has_lcoa_changed( void ) );

  my_address = get_lcoa();

  if ( inet_address_equal( my_address, lcoa ) ) {
    FRET( false  );
  }
  FRET( true );
}

/**
 * Obtain the source address from the packet 
 */
address_t src_address( Packet* packet ) { 

  address_t source;
  IpT_Dgram_Fields* fields;

	FIN( src_address( packet ) );

	op_pk_nfd_access( packet, "fields", &fields );

  source = inet_address_copy( fields->src_addr );

  FRET( source );
}

/**
 * Obtain the destination address from the packet 
 */
address_t dest_address( Packet* packet ) { 

  address_t destination;
  IpT_Dgram_Fields* fields;
  
	FIN( dest_address( packet ) );

	op_pk_nfd_access( packet, "fields", &fields );

  destination = inet_address_copy( fields->dest_addr );

  FRET( destination );
}

/** 
 * This function creates and sends an IPv6 datagram 
 * that carries a Binding Update MIPv6 message.    
 *
 * @param dest_addr - Destination Address
 */
static void
bu_msg_send( address_t dest_addr, address_t suggestedRCoA ) {

  Packet*           packet;
  OpT_Packet_Size   ext_hdr_len;
  IpT_Dgram_Fields* dgram;
  Ipv6T_Mobility_Hdr_Info*  header;
  
  FIN( bu_msg_send( dest_addr, suggestedRCoA ) );

  /* Create the IP datagram. */
  packet = ip_dgram_create( );
  
  /* Get the size contributed by the mobility header. */
  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_UPDATE];
  
  /* Create IP datagram fields data structure. */
  dgram = ip_dgram_fdstruct_create();

  /* Assign values to members of the field structure. */
  /* Set the source address to be the global address of interface. */
  
  /* The ha iface ptr must be obtained from the ha iface table. */  
  dgram->src_addr     = inet_address_copy( lcoa );
  dgram->src_internal_addr  = inet_rtab_addr_convert( dgram->src_addr );
  
  /* Set the destination address (MN). */  
  dgram->dest_addr          = inet_address_copy( dest_addr );
  dgram->dest_internal_addr = inet_rtab_addr_convert( dgram->dest_addr );

  /* No data packet is encapsulated in this datagram, use */
  /* the length fields to model the extension header size.*/
  dgram->orig_len = ext_hdr_len;
  dgram->frag_len = ext_hdr_len;
  dgram->ttl      = 255;
  
  /* The protocol field (next header in IPv6) must    */
  /* indicate that this is a mobility extension header. */
  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;

  /* Set the message fields to the indicated values. */
  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Update );
  header->msg_data.bind_update.home_address = inet_address_copy( suggestedRCoA );

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
#undef lcoa
#undef selfHndl
#undef parentHndl
#undef selfId
#undef parentId
#undef map_address
#undef currpacket
#undef address_changed
#undef rcoa
#undef modelName
#undef procHndl

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_HMIPv6_MN_NEW_init (int * init_block_ptr);
	VosT_Address _op_HMIPv6_MN_NEW_alloc (VosT_Obtype, int);
	void HMIPv6_MN_NEW (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MN_NEW_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->HMIPv6_MN_NEW (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MN_NEW_svar (void *, const char *, void **);

	void _op_HMIPv6_MN_NEW_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MN_NEW_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_HMIPv6_MN_NEW_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MN_NEW_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (HMIPv6_MN_NEW_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
HMIPv6_MN_NEW_state::HMIPv6_MN_NEW (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (HMIPv6_MN_NEW_state::HMIPv6_MN_NEW ());
	try
		{


		FSM_ENTER_NO_VARS ("HMIPv6_MN_NEW")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "HMIPv6_MN_NEW [init enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MN_NEW [init enter execs]", state0_enter_exec)
				{
				/***
				 * 1) Register process in the global table.
				 * 2) Obtain model parameters
				 *      e.g. operation mode
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
				procHndl = (OmsT_Pr_Handle)oms_pr_process_register( parentId, selfId,
				                                           selfHndl, modelName );
				
				/* Register the protocol attribute in the	registry. */
				oms_pr_attr_set( procHndl, "protocol", OMSC_PR_STRING, "hmipv6", OPC_NIL );
				
				address_changed = false;
				rcoa = InetI_Invalid_Addr;
				map_address = InetI_Invalid_Addr;
				lcoa = inet_address_copy( get_lcoa() );
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"HMIPv6_MN_NEW")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "HMIPv6_MN_NEW [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 1, state1_enter_exec, ;, init, "SELF_NOTIF", "", "init", "init2", "tr_14", "HMIPv6_MN_NEW [init -> init2 : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (init2) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "init2", state1_enter_exec, "HMIPv6_MN_NEW [init2 enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MN_NEW [init2 enter execs]", state1_enter_exec)
				{
				/* Obtain handles to lower layer modules. */
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"HMIPv6_MN_NEW")


			/** state (init2) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "init2", "HMIPv6_MN_NEW [init2 exit execs]")


			/** state (init2) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIF), 2, state2_enter_exec, ;, init2, "SELF_NOTIF", "", "init2", "idle", "tr_16", "HMIPv6_MN_NEW [init2 -> idle : SELF_NOTIF / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "idle", state2_enter_exec, "HMIPv6_MN_NEW [idle enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MN_NEW [idle enter execs]", state2_enter_exec)
				{
				if ( has_lcoa_changed() ) {
				  address_changed = true;
				} else if ( op_intrpt_type() == OPC_INTRPT_STRM ) {
				
				  currpacket = op_pk_get( IN_STRM );
				
				  /* Make sure the packet is sound */
				  if ( (NULL != currpacket) && correct_packet_fmt( currpacket ) ) {
				
				    /* Check if the packet is a binding acknowledgment */
				    if ( is_bind_ack( currpacket ) ) {
				      map_address = src_address( currpacket );
				    }
				  } 
				  op_pk_destroy( currpacket );
				}
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"HMIPv6_MN_NEW")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "idle", "HMIPv6_MN_NEW [idle exit execs]")


			/** state (idle) transition processing **/
			FSM_TRANSIT_ONLY ((ADDRESS_CHANGED), 3, state3_enter_exec, ;, idle, "ADDRESS_CHANGED", "", "idle", "SEND BU", "tr_17", "HMIPv6_MN_NEW [idle -> SEND BU : ADDRESS_CHANGED / ]")
				/*---------------------------------------------------------*/



			/** state (SEND BU) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "SEND BU", state3_enter_exec, "HMIPv6_MN_NEW [SEND BU enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MN_NEW [SEND BU enter execs]", state3_enter_exec)
				{
				/**
				 * State Variables:
				 *  - Packet* currpacket 
				 *  - bool address_changed
				 *  - address_t map_address
				 *  - address_t lcoa
				 */
				
				
				lcoa = inet_address_copy( get_lcoa() ); 
				
				/* If we don't have a RCoA yet, generate one */
				if ( inet_address_equal(rcoa, InetI_Invalid_Addr) ) { 
				  rcoa = generate_rcoa();
				}
				
				bu_msg_send( map_address, rcoa );
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (SEND BU) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "SEND BU", "HMIPv6_MN_NEW [SEND BU exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MN_NEW [SEND BU exit execs]", state3_exit_exec)
				{
				/* reset the state variable */
				address_changed = false;
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (SEND BU) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "SEND BU", "idle", "tr_18", "HMIPv6_MN_NEW [SEND BU -> idle : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"HMIPv6_MN_NEW")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (HMIPv6_MN_NEW)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
HMIPv6_MN_NEW_state::_op_HMIPv6_MN_NEW_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
HMIPv6_MN_NEW_state::operator delete (void* ptr)
	{
	FIN (HMIPv6_MN_NEW_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

HMIPv6_MN_NEW_state::~HMIPv6_MN_NEW_state (void)
	{

	FIN (HMIPv6_MN_NEW_state::~HMIPv6_MN_NEW_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
HMIPv6_MN_NEW_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (HMIPv6_MN_NEW_state::operator new ());

	new_ptr = Vos_Alloc_Object (HMIPv6_MN_NEW_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

HMIPv6_MN_NEW_state::HMIPv6_MN_NEW_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "HMIPv6_MN_NEW [init enter execs]";
#endif
	}

VosT_Obtype
_op_HMIPv6_MN_NEW_init (int * init_block_ptr)
	{
	FIN_MT (_op_HMIPv6_MN_NEW_init (init_block_ptr))

	HMIPv6_MN_NEW_state::obtype = Vos_Define_Object_Prstate ("proc state vars (HMIPv6_MN_NEW)",
		sizeof (HMIPv6_MN_NEW_state));
	*init_block_ptr = 0;

	FRET (HMIPv6_MN_NEW_state::obtype)
	}

VosT_Address
_op_HMIPv6_MN_NEW_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	HMIPv6_MN_NEW_state * ptr;
	FIN_MT (_op_HMIPv6_MN_NEW_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new HMIPv6_MN_NEW_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new HMIPv6_MN_NEW_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_HMIPv6_MN_NEW_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	HMIPv6_MN_NEW_state		*prs_ptr;

	FIN_MT (_op_HMIPv6_MN_NEW_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (HMIPv6_MN_NEW_state *)gen_ptr;

	if (strcmp ("lcoa" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->lcoa);
		FOUT
		}
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
	if (strcmp ("map_address" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->map_address);
		FOUT
		}
	if (strcmp ("currpacket" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->currpacket);
		FOUT
		}
	if (strcmp ("address_changed" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->address_changed);
		FOUT
		}
	if (strcmp ("rcoa" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rcoa);
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
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

