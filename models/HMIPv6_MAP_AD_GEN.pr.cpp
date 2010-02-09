/* Process model C++ form file: HMIPv6_MAP_AD_GEN.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char HMIPv6_MAP_AD_GEN_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 4B70C809 4B70C809 1 planet12 Student 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                         ";
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

extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];

#define TIMER_INTERRUPT 99

/* How often to check for packets in seconds */
#define TIME_LIMIT 	1.0

#define TIMER_END       (op_intrpt_type () == OPC_INTRPT_SELF && op_intrpt_code() == TIMER_INTERRUPT)

#define CAN_SEND ((op_intrpt_type() == OPC_INTRPT_SELF) && (op_intrpt_code() == TIMER_INTERRUPT))

#define DISABLED (disabled == true)

#define OUT_STRM 0

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
class HMIPv6_MAP_AD_GEN_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		HMIPv6_MAP_AD_GEN_state (void);

		/* Destructor contains Termination Block */
		~HMIPv6_MAP_AD_GEN_state (void);

		/* State Variables */
		bool	                   		ap_enable                                       ;
		bool	                   		disabled                                        ;
		InetT_Address	          		map_address                                     ;

		/* FSM code */
		void HMIPv6_MAP_AD_GEN (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_HMIPv6_MAP_AD_GEN_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype HMIPv6_MAP_AD_GEN_state::obtype = (VosT_Obtype)OPC_NIL;

#define ap_enable               		op_sv_ptr->ap_enable
#define disabled                		op_sv_ptr->disabled
#define map_address             		op_sv_ptr->map_address

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	HMIPv6_MAP_AD_GEN_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((HMIPv6_MAP_AD_GEN_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* No Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ };
#endif

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef ap_enable
#undef disabled
#undef map_address

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_HMIPv6_MAP_AD_GEN_init (int * init_block_ptr);
	VosT_Address _op_HMIPv6_MAP_AD_GEN_alloc (VosT_Obtype, int);
	void HMIPv6_MAP_AD_GEN (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MAP_AD_GEN_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->HMIPv6_MAP_AD_GEN (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MAP_AD_GEN_svar (void *, const char *, void **);

	void _op_HMIPv6_MAP_AD_GEN_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((HMIPv6_MAP_AD_GEN_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_HMIPv6_MAP_AD_GEN_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_HMIPv6_MAP_AD_GEN_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (HMIPv6_MAP_AD_GEN_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
HMIPv6_MAP_AD_GEN_state::HMIPv6_MAP_AD_GEN (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (HMIPv6_MAP_AD_GEN_state::HMIPv6_MAP_AD_GEN ());
	try
		{


		FSM_ENTER ("HMIPv6_MAP_AD_GEN")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "HMIPv6_MAP_AD_GEN [init enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP_AD_GEN [init enter execs]", state0_enter_exec)
				{
				/**
				 * Check paramaters, if not an ap, destory this module.
				 */
				int ap_flag;
				Objid myid;
				Objid paramid;
				
				/* Obtain the values assigned to the various attributes	*/
				myid = op_id_self();
				op_ima_obj_attr_get( myid, "Wireless LAN Parameters", &paramid );
				paramid = op_topo_child( paramid, OPC_OBJTYPE_GENERIC, 0 );
				
				op_ima_obj_attr_get( paramid, "Access Point Functionality", &ap_flag);
				
				char name[100];
				op_ima_obj_hname_get( op_id_self(), name, 100 );
				
				/* If this isn't an access point, don't generate advertisements */
				if ( ap_flag != OPC_BOOLINT_ENABLED ) { 
					printf( "Destroying HMIPv6 MN Advertiser in %s\n", name ); 
				  op_pro_destroy( op_pro_self() );
				  disabled = true;
				} else {
					printf( "Starting HMIPv6 MN Advertiser in %s\n", name ); 
				}
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"HMIPv6_MAP_AD_GEN")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "HMIPv6_MAP_AD_GEN [init exit execs]")


			/** state (init) transition processing **/
			FSM_PROFILE_SECTION_IN ("HMIPv6_MAP_AD_GEN [init trans conditions]", state0_trans_conds)
			FSM_INIT_COND ((1))
			FSM_TEST_COND (DISABLED)
			FSM_TEST_LOGIC ("init")
			FSM_PROFILE_SECTION_OUT (state0_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 1, state1_enter_exec, ;, "", "", "init", "idle", "tr_0", "HMIPv6_MAP_AD_GEN [init -> idle :  / ]")
				FSM_CASE_TRANSIT (1, 3, state3_enter_exec, ;, "DISABLED", "", "init", "FAIL", "tr_5", "HMIPv6_MAP_AD_GEN [init -> FAIL : DISABLED / ]")
				}
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "idle", state1_enter_exec, "HMIPv6_MAP_AD_GEN [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"HMIPv6_MAP_AD_GEN")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "idle", "HMIPv6_MAP_AD_GEN [idle exit execs]")


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("HMIPv6_MAP_AD_GEN [idle trans conditions]", state1_trans_conds)
			FSM_INIT_COND (CAN_SEND)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 2, state2_enter_exec, ;, "CAN_SEND", "", "idle", "SEND AD", "tr_3", "HMIPv6_MAP_AD_GEN [idle -> SEND AD : CAN_SEND / ]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, ;, "default", "", "idle", "idle", "tr_2", "HMIPv6_MAP_AD_GEN [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (SEND AD) enter executives **/
			FSM_STATE_ENTER_FORCED (2, "SEND AD", state2_enter_exec, "HMIPv6_MAP_AD_GEN [SEND AD enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP_AD_GEN [SEND AD enter execs]", state2_enter_exec)
				{
				
				/* generate one advertisement */
				  Packet*           packet;
				  OpT_Packet_Size   ext_hdr_len;
				  IpT_Dgram_Fields* dgram;
				  Ipv6T_Mobility_Hdr_Info*  header;
				
				  /* Create the IP datagram. */
				  packet = ip_dgram_create();
				  
				  /* Get the size contributed by the mobility header. */
				  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_ACK];
				  
				  /* Create IP datagram fields data structure. */
				  dgram = ip_dgram_fdstruct_create();
				  dgram->src_addr = inet_support_address_from_node_id_get( op_topo_parent(op_id_self()), InetC_Addr_Family_v6 );
				  dgram->src_internal_addr = inet_rtab_addr_convert( dgram->src_addr );
				  dgram->orig_len = ext_hdr_len;
				  dgram->frag_len = ext_hdr_len;
				  dgram->ttl      = 255;
				  
				  /* The protocol field (next header in IPv6) must    */
				  /* indicate that this is a mobility extension header. */
				  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;
				
				  /* Set the message fields to the indicated values. */
				  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Ack );
				  header->msg_data.bind_update.home_address = inet_address_copy( map_address );
				
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
				  op_pk_send( packet, OUT_STRM );
				  printf( "HMIPv6 MAP AD: Sending packet!\n" );
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** state (SEND AD) exit executives **/
			FSM_STATE_EXIT_FORCED (2, "SEND AD", "HMIPv6_MAP_AD_GEN [SEND AD exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP_AD_GEN [SEND AD exit execs]", state2_exit_exec)
				{
				
				/* Set the timer interrupt */
				op_intrpt_schedule_self(op_sim_time() + TIME_LIMIT, TIMER_INTERRUPT); 
				}
				FSM_PROFILE_SECTION_OUT (state2_exit_exec)


			/** state (SEND AD) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "SEND AD", "idle", "tr_4", "HMIPv6_MAP_AD_GEN [SEND AD -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (FAIL) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "FAIL", state3_enter_exec, "HMIPv6_MAP_AD_GEN [FAIL enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"HMIPv6_MAP_AD_GEN")


			/** state (FAIL) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "FAIL", "HMIPv6_MAP_AD_GEN [FAIL exit execs]")


			/** state (FAIL) transition processing **/
			FSM_TRANSIT_MISSING ("FAIL")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"HMIPv6_MAP_AD_GEN")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (HMIPv6_MAP_AD_GEN)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
HMIPv6_MAP_AD_GEN_state::_op_HMIPv6_MAP_AD_GEN_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
HMIPv6_MAP_AD_GEN_state::operator delete (void* ptr)
	{
	FIN (HMIPv6_MAP_AD_GEN_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

HMIPv6_MAP_AD_GEN_state::~HMIPv6_MAP_AD_GEN_state (void)
	{

	FIN (HMIPv6_MAP_AD_GEN_state::~HMIPv6_MAP_AD_GEN_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
HMIPv6_MAP_AD_GEN_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (HMIPv6_MAP_AD_GEN_state::operator new ());

	new_ptr = Vos_Alloc_Object (HMIPv6_MAP_AD_GEN_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

HMIPv6_MAP_AD_GEN_state::HMIPv6_MAP_AD_GEN_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "HMIPv6_MAP_AD_GEN [init enter execs]";
#endif
	}

VosT_Obtype
_op_HMIPv6_MAP_AD_GEN_init (int * init_block_ptr)
	{
	FIN_MT (_op_HMIPv6_MAP_AD_GEN_init (init_block_ptr))

	HMIPv6_MAP_AD_GEN_state::obtype = Vos_Define_Object_Prstate ("proc state vars (HMIPv6_MAP_AD_GEN)",
		sizeof (HMIPv6_MAP_AD_GEN_state));
	*init_block_ptr = 0;

	FRET (HMIPv6_MAP_AD_GEN_state::obtype)
	}

VosT_Address
_op_HMIPv6_MAP_AD_GEN_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	HMIPv6_MAP_AD_GEN_state * ptr;
	FIN_MT (_op_HMIPv6_MAP_AD_GEN_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new HMIPv6_MAP_AD_GEN_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new HMIPv6_MAP_AD_GEN_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_HMIPv6_MAP_AD_GEN_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	HMIPv6_MAP_AD_GEN_state		*prs_ptr;

	FIN_MT (_op_HMIPv6_MAP_AD_GEN_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (HMIPv6_MAP_AD_GEN_state *)gen_ptr;

	if (strcmp ("ap_enable" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ap_enable);
		FOUT
		}
	if (strcmp ("disabled" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->disabled);
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

