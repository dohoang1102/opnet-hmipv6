/* Process model C form file: HMIPv6_MAP.pr.c */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char HMIPv6_MAP_pr_c [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 4B4CDF4F 4B4CDF4F 1 planet12 Student 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                         ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <opnet.h>
#include <hmipv6_defs.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ipv6_extension_headers_defs.h>
#include <ipv6_extension_headers_sup.h>
#include <ip_dgram_sup.h>
#include <ipv6_ra.h>
#include <ip_arp.h>
#include <ip_icmp_pk.h>
#include <mobile_ip_support.h>
/* Make sure lower modules have registered them selves properly */
#define SELF_NOTIFY  ( op_intrpt_type() == OPC_INTRPT_SELF )

/* Indicates packet arrival from lower layer IP Module */
#define PKT_FROM_IP  ( packet_from_ip == OPC_TRUE )

/**
 * Self Interrupt indicating that MN has switched and 
 * must redirect from oCoA to nCoA.
 */
#define REDIRECT

/* Define the packet source index for the up-link */
#define UPLINK   0

/* Define the packet source index for the down-link */
#define DOWNLINK 1

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
	Prohandle	              		selfHndl                                        ;	/* Modules own process handle */
	Prohandle	              		parentHndl                                      ;	/* Modules parent process handle */
	Objid	                  		selfId                                          ;	/* Our own Object ID */
	Objid	                  		parentId                                        ;	/* Object ID of the parent */
	char	                   		modelName[10]                                   ;	/* cstring to hold the this model's name */
	OmsT_Pr_Handle	         		procHndl                                        ;	/* Handle for this process after registration */
	Boolean	                		packet_from_ip                                  ;	/* We received a packet from the IP */
	                        		                                                	/*                                  */
	} HMIPv6_MAP_state;

#define selfHndl                		op_sv_ptr->selfHndl
#define parentHndl              		op_sv_ptr->parentHndl
#define selfId                  		op_sv_ptr->selfId
#define parentId                		op_sv_ptr->parentId
#define modelName               		op_sv_ptr->modelName
#define procHndl                		op_sv_ptr->procHndl
#define packet_from_ip          		op_sv_ptr->packet_from_ip

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


void hmipv6_sup_pk_cleanup( MipT_Invocation_Info* info ) {
	/** PURPOSE: Clean up the packet and associated ICI when MIP procs are done. **/
	/** REQUIRES: Invocation struct pointer.	**/
	/** EFFECTS: Packet gets destroyed and the pointer reset, ICI destroyed. **/
	FIN( hmipv6_sup_pk_cleanup( info ) );

	/* Destroy the packet and reset the pointer. */
	op_pk_destroy( info->pk_ptr );
	info->pk_ptr = OPC_NIL;

	/* Clean up ICI as well. */
	ip_rte_ind_ici_fdstruct_destroy( info->rte_info_ici_ptr );

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
	void HMIPv6_MAP (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_HMIPv6_MAP_init (int * init_block_ptr);
	void _op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_HMIPv6_MAP_terminate (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Address _op_HMIPv6_MAP_alloc (VosT_Obtype, int);
	void _op_HMIPv6_MAP_svar (void *, const char *, void **);


#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
HMIPv6_MAP (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (HMIPv6_MAP ());

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
				
				
				/* Initialize state variables */
				packet_from_ip = OPC_FALSE;
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"HMIPv6_MAP")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "HMIPv6_MAP [init exit execs]")


			/** state (init) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFY), 1, state1_enter_exec, ;, init, "SELF_NOTIFY", "", "init", "init2", "tr_0", "HMIPv6_MAP [init -> init2 : SELF_NOTIFY / ]")
				/*---------------------------------------------------------*/



			/** state (init2) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "init2", state1_enter_exec, "HMIPv6_MAP [init2 enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [init2 enter execs]", state1_enter_exec)
				{
				
				/**
				 * Obtain handles to lower layer modules 
				 */
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"HMIPv6_MAP")


			/** state (init2) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "init2", "HMIPv6_MAP [init2 exit execs]")


			/** state (init2) transition processing **/
			FSM_TRANSIT_ONLY ((SELF_NOTIFY), 2, state2_enter_exec, ;, init2, "SELF_NOTIFY", "", "init2", "idle", "tr_7", "HMIPv6_MAP [init2 -> idle : SELF_NOTIFY / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "idle", state2_enter_exec, "HMIPv6_MAP [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"HMIPv6_MAP")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "idle", "HMIPv6_MAP [idle exit execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [idle exit execs]", state2_exit_exec)
				{
				intrpt_type = op_intrpt_type ();
				
				if ( intrpt_type == OPC_INTRPT_SELF ) {
				
					is_timer = OPC_TRUE;
				
				} else {
				
					/* Check the argument. */
					invoke_info_ptr = (MipT_Invocation_Info*) op_pro_argmem_access();
				
					if ( invoke_info_ptr != OPC_NIL ) {
				
						if ( invoke_info_ptr->invocation_type == MipC_Invoke_Type_IRDP ) {
				
							/* We have an IRDP packet.  But which kind though? */
							if ( invoke_info_ptr->irdp_type == IcmpC_Type_IRDP_Sol ) {
				
								/* Slicitation. */
								is_solicit = OPC_TRUE;
				
				      } else {
				
								/* This must be an advertisement from another agent. */
								is_adv_pk = OPC_TRUE;
				
							}
				
							/* Clean up. */
							hmipv6_sup_pk_cleanup( invoke_info_ptr );
				
				    } else {
							is_ip_pk = OPC_TRUE;
				    }
				  } else {
						is_regist_pk = OPC_TRUE;
				  }
				}
				}
				FSM_PROFILE_SECTION_OUT (state2_exit_exec)


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [idle trans conditions]", state2_trans_conds)
			FSM_INIT_COND (PKT_FROM_IP)
			FSM_TEST_COND (REDIRECT)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state2_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 3, state3_enter_exec, ;, "PKT_FROM_IP", "", "idle", "IP_HANDLE", "tr_3", "HMIPv6_MAP [idle -> IP_HANDLE : PKT_FROM_IP / ]")
				FSM_CASE_TRANSIT (1, 4, state4_enter_exec, ;, "REDIRECT", "", "idle", "RCoA_ACTIVE", "tr_4", "HMIPv6_MAP [idle -> RCoA_ACTIVE : REDIRECT / ]")
				FSM_CASE_TRANSIT (2, 2, state2_enter_exec, ;, "default", "", "idle", "idle", "tr_11", "HMIPv6_MAP [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (IP_HANDLE) enter executives **/
			FSM_STATE_ENTER_FORCED (3, "IP_HANDLE", state3_enter_exec, "HMIPv6_MAP [IP_HANDLE enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [IP_HANDLE enter execs]", state3_enter_exec)
				{
				
				/**
				 * Modify Source Address if RCoA is active.
				 * Relay Packet to PPP
				 */
				}
				FSM_PROFILE_SECTION_OUT (state3_enter_exec)

			/** state (IP_HANDLE) exit executives **/
			FSM_STATE_EXIT_FORCED (3, "IP_HANDLE", "HMIPv6_MAP [IP_HANDLE exit execs]")


			/** state (IP_HANDLE) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "IP_HANDLE", "idle", "tr_2", "HMIPv6_MAP [IP_HANDLE -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (RCoA_ACTIVE) enter executives **/
			FSM_STATE_ENTER_FORCED (4, "RCoA_ACTIVE", state4_enter_exec, "HMIPv6_MAP [RCoA_ACTIVE enter execs]")
				FSM_PROFILE_SECTION_IN ("HMIPv6_MAP [RCoA_ACTIVE enter execs]", state4_enter_exec)
				{
				
				/**
				 * Update variables to indicate that RCoA is active
				 */
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** state (RCoA_ACTIVE) exit executives **/
			FSM_STATE_EXIT_FORCED (4, "RCoA_ACTIVE", "HMIPv6_MAP [RCoA_ACTIVE exit execs]")


			/** state (RCoA_ACTIVE) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "RCoA_ACTIVE", "idle", "tr_6", "HMIPv6_MAP [RCoA_ACTIVE -> idle : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"HMIPv6_MAP")
		}
	}




void
_op_HMIPv6_MAP_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}




void
_op_HMIPv6_MAP_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{

	FIN_MT (_op_HMIPv6_MAP_terminate ())


	/* No Termination Block */

	Vos_Poolmem_Dealloc (op_sv_ptr);

	FOUT
	}


/* Undefine shortcuts to state variables to avoid */
/* syntax error in direct access to fields of */
/* local variable prs_ptr in _op_HMIPv6_MAP_svar function. */
#undef selfHndl
#undef parentHndl
#undef selfId
#undef parentId
#undef modelName
#undef procHndl
#undef packet_from_ip

#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_HMIPv6_MAP_init (int * init_block_ptr)
	{
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_HMIPv6_MAP_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (HMIPv6_MAP)",
		sizeof (HMIPv6_MAP_state));
	*init_block_ptr = 0;

	FRET (obtype)
	}

VosT_Address
_op_HMIPv6_MAP_alloc (VosT_Obtype obtype, int init_block)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	HMIPv6_MAP_state * ptr;
	FIN_MT (_op_HMIPv6_MAP_alloc (obtype))

	ptr = (HMIPv6_MAP_state *)Vos_Alloc_Object (obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "HMIPv6_MAP [init enter execs]";
#endif
		}
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
	if (strcmp ("packet_from_ip" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->packet_from_ip);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

