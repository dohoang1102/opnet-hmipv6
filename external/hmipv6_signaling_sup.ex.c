/* mipv6_signaling_sup.ex.c */
/* Support routines for processing of IPv6 mobility headers and */
/* used by MIPv6.                       */

/****************************************/
/*      Copyright (c) 2004-2008       */
/*      by OPNET Technologies, Inc.     */
/*       (A Delaware Corporation)       */
/*    7255 Woodmont Av., Suite 250      */
/*          Bethesda, MD, U.S.A.        */
/*       All Rights Reserved.           */
/****************************************/

#include "ipv6_extension_headers_sup.h"
#include "hmipv6_support.h"
#include "ip_rte_support.h"
#include "hmipv6_signaling_sup.h"
#include <hmipv6_support.h>
#include <math.h>
#include <prg_bin_hash.h>
#include <ip_dgram_sup.h>

/* Variables defined for Pooled Memory allocation for MIPv6. */
static Pmohandle hmipv6_bind_cache_entry_struct_pmh = VOSC_NIL;
static Pmohandle hmipv6_bind_update_entry_struct_pmh = VOSC_NIL;

/*******   Function definitions.    *******/

void 
hmipv6_pooled_memory_package_init( void ) {

  /**  Initialize PMO memory needed by MIPv6 protocol.  **/
  FIN (hmipv6_pooled_memory_package_init (void));
  
  if (hmipv6_bind_cache_entry_struct_pmh == VOSC_NIL) {
    /* Initialize the pool memory object handlers for */
    /* entries of the Binding Cache Table.        */
    hmipv6_bind_cache_entry_struct_pmh  = op_prg_pmo_define(
        "MIPv6 Binding Cache Table Entry", sizeof( hmipv6_cache_entry ), 64 );

    /* Initialize the pool memory object handlers for */
    /* entries of the Binding Update List.        */
    hmipv6_bind_update_entry_struct_pmh = op_prg_pmo_define(
        "MIPv6 Binding Update Table Entry", sizeof( hmipv6_bu_entry ), 64 );
  }

  FOUT;
}
    
Ipv6T_Mobility_Hdr_Info*
hmipv6_binding_update_msg_create (InetT_Address home_addr, OpT_uInt16 seq, Boolean ack, Boolean home_reg, OpT_uInt16 lifetime) {

  Ipv6T_Mobility_Hdr_Info* mob_hdr;
  
  /** This functions creates a mobility header that contains  **/
  /** a Binding Update message. Binding Update message's    **/
  /** fields are set as requested by the caller.        **/
  FIN (hmipv6_binding_update_msg_create (OpT_uInt16 seq, Boolean ack, Boolean home_reg, OpT_uInt16 lifetime));

  /* First allocate memory for the mobility extension header. */
  mob_hdr = (Ipv6T_Mobility_Hdr_Info *) ipv6_mobility_header_create(BIND_UPDATE);

  /* Set the message fields to the indicated values. */
  mob_hdr->msg_data.bind_update.seq = seq;
  mob_hdr->msg_data.bind_update.ack = ack;
  mob_hdr->msg_data.bind_update.home_reg = home_reg;
  mob_hdr->msg_data.bind_update.lifetime = lifetime;
  mob_hdr->msg_data.bind_update.home_address = inet_address_copy( home_addr ); /**ip_address_copy (&home_addr);*/
  
  /* Return the mobility header. */
  FRET( mob_hdr );
}

Ipv6T_Mobility_Hdr_Info*
hmipv6_binding_ack_msg_create( hmipv6_bind_ack_status status, OpT_uInt16 seq, OpT_uInt16 lifetime ) {

  Ipv6T_Mobility_Hdr_Info* mob_hdr;
  
  /** This functions creates a mobility header that contains  **/
  /** a Binding Acknoledgement message. Binding Acknoledgement**/
  /** message's fields are set as requested by the caller.  **/
  FIN( hmipv6_binding_ack_msg_create( hmipv6_bind_ack_status status, OpT_uInt16 seq, OpT_uInt16 lifetime));

  /* First allocate memory for the mobility extension header. */
  mob_hdr = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( BIND_ACK );

  /* Set the corresponding message type. */
  mob_hdr->mh_type = BIND_ACK;
  
  /* Set the message fields to the indicated values. */
  mob_hdr->msg_data.bind_ack.status   = status;
  mob_hdr->msg_data.bind_ack.seq      = seq;
  mob_hdr->msg_data.bind_ack.lifetime = lifetime;
  
  /* Return the mobility header. */
  FRET( mob_hdr );
}

Ipv6T_Mobility_Hdr_Info*
hmipv6_route_test_msg_create(Mipv6T_Mobity_Hdr_Type msg_type) {

  Ipv6T_Mobility_Hdr_Info* mob_hdr;
  
  /** This functions creates a mobility header that contains  **/
  /** a Binding Acknoledgement message. Binding Acknoledgement**/
  /** message's fields are set as requested by the caller.  **/
  FIN( hmipv6_route_test_msg_create(ipv6T_Mobity_Hdr_Type msg_type) );

  /* First allocate memory for the mobility extension header. */
  mob_hdr = (Ipv6T_Mobility_Hdr_Info *) ipv6_mobility_header_create( msg_type );

  /* Set the corresponding message type. */
  mob_hdr->mh_type = msg_type;
  
  /* Return the mobility header. */
  FRET( mob_hdr );
}

Ipv6T_Mobility_Hdr_Info*
hmipv6_binding_error_msg_create( Mipv6T_Bind_Error_Status_Value status, InetT_Address home_address) {

  Ipv6T_Mobility_Hdr_Info* mob_hdr;
  
  /** This functions creates a mobility header that contains  **/
  /** a Binding Error message. Binding Error message's fields **/
  /** are set as requested by the caller.           **/
  FIN( hmipv6_binding_error_msg_create( Mipv6T_Bind_Error_Status_Value status, InetT_Address home_address ) );

  /* First allocate memory for the mobility extension header. */
  mob_hdr = (Ipv6T_Mobility_Hdr_Info *) ipv6_mobility_header_create( BIND_ERR );

  /* Set the message fields to the indicated values. */
  mob_hdr->msg_data.bind_error.status       = status;
  mob_hdr->msg_data.bind_error.home_address = inet_address_copy( home_address );
  
  /* Return the mobility header. */
  FRET( mob_hdr );
}

Boolean
hmipv6_dest_addr_is_bound( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr) {
  /** This functions search through the Binding Update List   **/
  /** of a mobile node to see if a given destination address  **/
  /** is already bound. A binding with a CN is considered   **/
  /** completed the the CN address is included in the Binding **/
  /** Update List of the MN and the entry is tag as       **/
  /** binding_complete.                   **/
  FIN( hmipv6_dest_addr_is_bound( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );
  
  FRET( hmipv6_bind_update_entry_status_get( iprmd_ptr, bind_addr ) == BU_ENTRY_BINDING_COMPLETE );
}

hmipv6_bu_entry*
hmipv6_bind_update_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {

  char string[128];
  char addr_str[INETC_ADDR_STR_LEN];   
  hmipv6_bu_entry* entry;

  /** Return the element from the Binding Update Table that **/
  /** corresponds to the specified destination address. */
  /** An OPC_NIL value is returned if no entry is found.  **/
  FIN( hmipv6_bind_update_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );

  /* Print debug trace messages. */
  if (op_prg_odb_ltrace_active( "hmipv6_bu_tbl" )) {
    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, bind_addr );
    sprintf( string, "Binding Update List: searching for Addr(%s)", addr_str );
    op_prg_odb_print_major( string, OPC_NIL );
  }

  /* Get the element of the binary hash table that corresponds*/  
  /* to the provided destination address. */
  entry = (hmipv6_bu_entry *) prg_bin_hash_table_item_get(
      iprmd_ptr->mipv6_info_ptr->binding_update_hashtbl_ptr,
      (Ipv6T_Address *)(bind_addr.address.ipv6_addr_ptr) );    
    
  /* Return the entry address. */
  FRET( entry );
}

int
hmipv6_bind_cache_num_entries_get( IpT_Rte_Module_Data* iprmd_ptr ) {
  /** Returns the number of entries currently in the binding cache table. **/
  FIN( hmipv6_bind_cache_num_entries_get( IpT_Rte_Module_Data* iprmd_ptr ) );

  /* For now return the size of the aux list. */
  FRET( op_prg_list_size( iprmd_ptr->mipv6_info_ptr->bind_cache_table_lptr ) );
}

int 
hmipv6_bind_update_num_entries_get( IpT_Rte_Module_Data* iprmd_ptr ) {
  /** Returns the number of entries currently in the binding update list. **/
  FIN (hmipv6_bind_update_num_entries_get (IpT_Rte_Module_Data* iprmd_ptr));

  /* For now return the size of the aux list. */
  FRET( op_prg_list_size( iprmd_ptr->mipv6_info_ptr->bind_update_list_lptr ) );
} 

hmipv6_bu_entry_status
hmipv6_bind_update_entry_status_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {

  hmipv6_bu_entry* entry;
  /** This functions searchs for a given address in the     **/
  /** Binding Update List of a MN. It may return one of the   **/
  /** following values to the caller:             **/
  /**  Mipv6_Bul_Entry_Not_Found. The specified address is  **/
  /**               not an existing entry.    **/     
  /**  Mipv6_Bul_Entry_Route_Pending. A Routability test is   **/
  /**               currently performed.    **/
  /**  Mipv6_Bul_Entry_Binding_Complete. The destination is   **/
  /**               bound .           **/ 
  /**  Mipv6_Bul_Entry_No_Future_Binding. Binding is not    **/
  /**               possible with this adddres. **/

  FIN( hmipv6_bind_update_entry_status_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );

  /* Look for the specified address in the Binding Update List. */
  entry = (hmipv6_bu_entry *) hmipv6_bind_update_entry_info_get( iprmd_ptr, bind_addr );   
  
  /* Check if entry was found. */
  if (entry == OPC_NIL) {
    /* Entry pointer is OPC_NIL, return the corresponding status. */  
    FRET( Mipv6C_Bind_Update_Entry_Not_Found );
  } else {
    /* An entry was found return its status as stored. */
    FRET( entry->status );
  }
}


hmipv6_bind_cache_entry*
hmipv6_bind_cache_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {
  char string[128];
  char addr_str[INETC_ADDR_STR_LEN];    
  hmipv6_cache_entry* entry;

  /** Return the element from the Binding Update Table that **/
  /** corresponds to the specified destination address. An  **/
  /** OPC_NIL value is returned if no entry is found.     **/
  FIN( hmipv6_bind_cache_entry_info_get( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr) );

  /* Get the element of the binary hash table that corresponds*/  
  /* to the provided destination address.           */
  
  /* Print debug trace messages. */
  if (op_prg_odb_ltrace_active ("mipv6_bind_cache")) {
    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, bind_addr );
    sprintf( string, "Binding Cache: searching for Addr(%s)", addr_str );
    op_prg_odb_print_major( string, OPC_NIL );
  }
  
  /* Search the bind_addr in the bin hash table. */  
  entry = (hmipv6_cache_entry *) prg_bin_hash_table_item_get( 
      iprmd_ptr->mipv6_info_ptr->binding_cache_hashtbl_ptr,
      (Ipv6T_Address *)(bind_addr.address.ipv6_addr_ptr) );   

  /* Return the entry address. */
  FRET( entry );
}

Boolean
hmipv6_dest_addr_is_binding_cache( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {
  hmipv6_cache_entry* entry;
  /** This functions search through the Binding Cache of  **/
  /** a node (HA orCN) to see if a given destination    **/
  /** address is already bound.               **/
  FIN( hmipv6_dest_addr_is_binding_cache( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );
  
  /* Access the binding cache table. */
  entry = (hmipv6_cache_entry *) hmipv6_bind_cache_entry_info_get( iprmd_ptr, bind_addr );

  /* Check if entry was found. */
  if ( entry == OPC_NIL ) {
    /* Entry pointer is OPC_NIL, return the corresponding status. */  
    FRET( OPC_FALSE );
  } else {
    /* An entry was found return its status as stored.  */
    FRET( OPC_TRUE );
  }
}

hmipv6_cache_entry*
hmipv6_bind_cache_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr,
                                    InetT_Address home_addr,
                                    InetT_Address co_addr,
                                    IpT_Interface_Info* current_ha_iface_info_ptr ) {

  char string[128];
  char addr_str[INETC_ADDR_STR_LEN];    
  InetT_Address* tmp_mn_addr_ptr;
  hmipv6_cache_entry* entry = OPC_NIL;  
  
  /** This function inserts an entry into the binding cache **/
  /** hash table. The key to the hash table is the home     **/
  /** address of a mobile node. The care-of address of the  **/
  /** mobile is kept in the entry.              **/
  /** A event is scheduled to indicate the lifetime of the  **/
  /** entry, a state is attached to it containing the key   **/
  /** for that hash element.                  **/
  FIN( hmipv6_bind_cache_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address dest_address ) );

  /* Allocate memory for the hash table entry. */
  entry = (hmipv6_cache_entry *) op_prg_pmo_alloc( hmipv6_bind_cache_entry_struct_pmh );
  
  /* Store the care-of address of the mobile node. */
  entry->co_address = inet_address_copy( co_addr );  
  
  /* Store a reference to the interface related to the    */
  /* current entry. For a Home Agent node, this is used to  */
  /* associate the serving interface for a givent entry.    */
  entry->serving_ha_iface_ptr = current_ha_iface_info_ptr;
  
  /* Schedule an event for the expiration of the lifetime of  */
  /* this entry. The hash key is attached to the event as an  */
  /* state.Curently no lifetime timers are supported.     */
  
  /* Print debug trace messages. */
  if ( op_prg_odb_ltrace_active( "hmipv6_bind_cache" ) ) {
    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, home_addr );
    sprintf (string, "Binding Cache: inserting Addr(%s)", addr_str);
    op_prg_odb_print_major (string, OPC_NIL);
  }
  
  /* Insert the element of the binary hash table that */
  /* corresponds to the provided destination address. */
  prg_bin_hash_table_item_insert( 
      iprmd_ptr->mipv6_info_ptr->binding_cache_hashtbl_ptr, 
      (Ipv6T_Address *)home_addr.address.ipv6_addr_ptr,
      (hmipv6_cache_entry *) entry,
      (void **) PRGC_NIL );    

  /* ToDo. For now keep a list of the hash keys in a list.  */
  tmp_mn_addr_ptr = (InetT_Address *) op_prg_mem_alloc( sizeof( InetT_Address ) );
  *tmp_mn_addr_ptr = inet_address_copy( home_addr );
  op_prg_list_insert( iprmd_ptr->mipv6_info_ptr->bind_cache_table_lptr,
      tmp_mn_addr_ptr, OPC_LISTPOS_TAIL );
  
  /* Record the number of entries. */
  hmipv6_binding_cache_table_size_stat_update( iprmd_ptr );

  /* Return the entry address. */
  FRET( entry );
}
      
hmipv6_cache_entry*
hmipv6_bind_cache_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {
  int  i, num_items; 
  char addr_str[INETC_ADDR_STR_LEN];    
  char addr_str2[INETC_ADDR_STR_LEN];     
  char string[128];
  InetT_Address*      tmp_mn_addr_ptr;  
  hmipv6_cache_entry* entry;

  /** Return the element from the Binding Update Table that **/
  /** corresponds to the specified destination address. An  **/
  /** OPC_NIL value is returned if no entry is found.     **/
  FIN( hmipv6_bind_cache_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );

  /* Get the element of the binary hash table that corresponds*/  
  /* to the provided destination address. */
  
  /* Print debug trace messages. */
  if ( op_prg_odb_ltrace_active( "hmipv6_cache" ) ) {

    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, bind_addr );
    sprintf( string, "Binding Cache: removing Addr(%s)", addr_str );
    op_prg_odb_print_major( string, OPC_NIL );
  }

  /* Remove the entry from the IPv6 hash table. */
  entry = (hmipv6_cache_entry *) prg_bin_hash_table_item_remove(
      iprmd_ptr->mipv6_info_ptr->binding_cache_hashtbl_ptr,
      (Ipv6T_Address *) bind_addr.address.ipv6_addr_ptr );    
      
  /* This must be replaced once hash bin functions are    */
  /* available. ToDo                      */
  /* Get the number of elements in the list.          */
  num_items = hmipv6_bind_cache_num_entries_get( iprmd_ptr );
  
  /* Loop through the list and remove the entry just removed  */
  /* from the hash table.                   */
  for (i = 0; i < num_items ; i++) {
    /* Access the ith element of the list.          */
    tmp_mn_addr_ptr  = (InetT_Address *) op_prg_list_access( iprmd_ptr->mipv6_info_ptr->bind_cache_table_lptr, i );
  
    /* Print debug trace messages. */
    if ( op_prg_odb_ltrace_active( "hmipv6_bc_tbl" ) ) {
      /* Converting the IPv6 address into a string. */
      inet_address_print( addr_str, bind_addr );
    
      inet_address_print( addr_str2, (*tmp_mn_addr_ptr) );
      
      sprintf( string, "Binding Cache Table: removing Addr(%s) List(%s)", addr_str, addr_str2 );
      op_prg_odb_print_major( string, OPC_NIL );
    }

    if ( inet_address_equal( (*tmp_mn_addr_ptr ), bind_addr ) ) {
      tmp_mn_addr_ptr = (InetT_Address *) op_prg_list_remove( iprmd_ptr->mipv6_info_ptr->bind_cache_table_lptr, i );
      op_prg_mem_free( tmp_mn_addr_ptr );

      /* Print debug trace messages. */
      if (op_prg_odb_ltrace_active( "hmipv6_bc_tbl" ) ) {
        /* Converting the IPv6 address into a string. */
        inet_address_print( addr_str, bind_addr );
    
        sprintf( string, "List removal" );
        op_prg_odb_print_major( string, OPC_NIL );
      }
      break;
    }
  }

  /* Update the statistic value for the binding update list size. */
  hmipv6_binding_cache_table_size_stat_update( iprmd_ptr ); 
  
  /* Return the entry address. */
  FRET( entry );
}
  

hmipv6_bu_entry*
hmipv6_bind_update_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr, hmipv6_bu_entry_Status status ) {
  char string[128];
  char addr_str[INETC_ADDR_STR_LEN];    
  hmipv6_bu_entry* entry;
  InetT_Address*   cn_addr;

  /** This function inserts an entry into the binding update  **/
  /** list hash table. The key to the hash table is the bind  **/
  /** address of a correspondent node or home agent node. The **/
  /** status of the binding is kept in the entry.       **/
  /** A event is scheduled to indicate the lifetime of the  **/
  /** entry, a state is attached to it containing the key   **/
  /** for that hash element.                  **/
  FIN( hmipv6_bind_update_entry_info_insert( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr, hmipv6_bu_entry_Status status ) );

  /* Allocate memory for the hash table entry. */
  entry = (hmipv6_bu_entry *) op_prg_pmo_alloc( hmipv6_bind_update_entry_struct_pmh );
  
  /* Store the IPv6 address of the node for which this entry is added. */
  entry->bind_address = inet_address_copy( bind_addr ); /**ip_address_copy (&bind_address); */

  /* ToDo. Start the lifetime timer. */
  
  /* Store the status of the binding update entry.      */
  entry->status = status;

  /* Initrialize the flags in this entry. */
  /* Indicates if a Home Test message has been received back. */
  entry->home_test_ok = OPC_FALSE;
  
  /* Indicates if a Care-of Test message has been received back. */  
  entry->care_of_test_ok = OPC_FALSE;
  
  /* Indicates if this entry is for a Home Agent. Otherwise */
  /* it is a Correspondent Node.                */
  entry->home_agent_entry = OPC_FALSE;

  /* Print debug trace messages. */
  if (op_prg_odb_ltrace_active( "hmipv6_bu_tbl" ) ) {
    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, bind_addr );
    
    sprintf( string, "Binding Update List: Adding Addr(%s)", addr_str );
    op_prg_odb_print_major( string, OPC_NIL );
  }
  
  /* Insert the element of the binary hash table that     */
  /* corresponds to the provided destination address.     */
  prg_bin_hash_table_item_insert(
      iprmd_ptr->mipv6_info_ptr->binding_update_hashtbl_ptr, 
      (Ipv6T_Address*) bind_addr.address.ipv6_addr_ptr,
      (hmipv6_bu_entry*) entry,
      (void **) PRGC_NIL );    
      
  /* For now keep a list with the hash keys. */
  cn_addr = (InetT_Address *) op_prg_mem_alloc( sizeof( InetT_Address ) );
  *cn_addr = inet_address_copy( bind_addr );
  op_prg_list_insert( iprmd_ptr->hmipv6_info_ptr->bind_update_list_lptr, cn_addr, OPC_LISTPOS_TAIL );

  /* Record the number of entries. */
  hmipv6_binding_update_list_size_stat_update( iprmd_ptr );

  /* Return the entry address, so it can be modified by the caller. */
  FRET( entry );
}

hmipv6_bu_entry*
hmipv6_bind_update_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) {

  int  i;
  int  num_items;
  char addr_str[INETC_ADDR_STR_LEN];    
  char addr_str2[INETC_ADDR_STR_LEN];     
  char string[128];
  InetT_Address*   cn_addr;  
  hmipv6_bu_entry* entry;

  /** Return the element from the Binding Update Table that **/
  /** corresponds to the specified destination address. An  **/
  /** OPC_NIL value is returned if no entry is found.     **/
  FIN( hmipv6_bind_update_entry_info_remove( IpT_Rte_Module_Data* iprmd_ptr, InetT_Address bind_addr ) );

  /* Get the element of the binary hash table that corresponds*/  
  /* to the provided destination address.           */
  
  /* Print debug trace messages. */
  if ( op_prg_odb_ltrace_active( "hmipv6_bu_tbl" ) ) {
    /* Converting the IPv6 address into a string. */
    inet_address_print( addr_str, bind_addr );
    sprintf( string, "Binding Update List: removing Addr(%s)", addr_str );
    op_prg_odb_print_major( string, OPC_NIL );
  }

  /* Remove the entry from the IPv6 hash table. */
  entry = (hmipv6_bu_entry *) prg_bin_hash_table_item_remove( 
      iprmd_ptr->mipv6_info_ptr->binding_update_hashtbl_ptr,
      (Ipv6T_Address *)(bind_addr.address.ipv6_addr_ptr) );    
    
  /* ToDo. Get the number of elements in the list. */
  num_items = hmipv6_bind_update_num_entries_get( iprmd_ptr );
  
  /* Loop through the list and remove entry just removed from the hash table. */
  for ( i = 0; i < num_items ; i++ ) {
    /* Access the ith element of the list. */
    cn_addr  = (InetT_Address *) op_prg_list_access (iprmd_ptr->mipv6_info_ptr->bind_update_list_lptr, i);
  
    /* Print debug trace messages. */
    if ( op_prg_odb_ltrace_active( "hmipv6_bu_tbl" ) ) {

      /* Converting the IPv6 address into a string. */
      inet_address_print( addr_str, bind_addr );
      inet_address_print( addr_str2, (*cn_addr) );
      
      sprintf( string, "Binding Update List: removing Addr(%s) List(%s)", addr_str, addr_str2 );
      op_prg_odb_print_major( string, OPC_NIL );
    }

    if ( inet_address_equal( (*cn_addr), bind_addr ) ) {
      cn_addr  = (InetT_Address *) op_prg_list_remove( iprmd_ptr->mipv6_info_ptr->bind_update_list_lptr, i );
      op_prg_mem_free( cn_addr );

      /* Print debug trace messages.            */
      if ( op_prg_odb_ltrace_active( "hmipv6_bu_tbl" ) ) {
        /* Converting the IPv6 address into a string. */
        inet_address_print( addr_str, bind_addr );
    
        sprintf( string, "List removal" );
        op_prg_odb_print_major( string, OPC_NIL );
      }
      break;
    }
  }
  
  /* Update the statistic value for the binding update list size. */
  hmipv6_binding_update_list_size_stat_update( iprmd_ptr );

  /* Return the entry address. */
  FRET( entry );
}

void
hmipv6_tunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_ptr, InetT_Address src_address, InetT_Address dest_address ) {
  double    inner_pkt_size;
  char      string[256];
  char      addr_str[INETC_ADDR_STR_LEN];    
  char      addr2_str[INETC_ADDR_STR_LEN];   
  Packet*   ip_pkptr;
  IpT_Dgram_Fields  *new_ip_dgram_fd_ptr,
  IpT_Dgram_Fields *old_ip_dgram_fd_ptr;

  /** Encapsulates IPv6 in IPv6 packets to be transported by a MIPv6 tunnel. **/
  FIN( hmipv6_tunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_ptr, InetT_Address src_address, InetT_Address dest_address ) );

  /* Obtain the size of the packet that will be encapsulated. */
  inner_pkt_size = (double)op_pk_total_size_get( *orig_ip_pk_ptr );
  
  /* Access the old field information.            */
  op_pk_nfd_access( *orig_ip_pk_ptr, "fields", &old_ip_dgram_fd_ptr );

  /* Print debug trace messages.                */
  if ( op_prg_odb_ltrace_active( "hmipv6_tunnel" ) ) {
    /* Converting the IPv6 address into a string.     */
    inet_address_print( addr_str, old_ip_dgram_fd_ptr->dest_addr );
    
    /* Converting the IPv6 address into a string.     */
    inet_address_print( addr2_str, dest_address );
    

    sprintf( string, "Original destination (%s), new destination (%s)", addr_str, addr2_str );
    op_prg_odb_print_major( "MIPv6: Tunneling packet.", string, OPC_NIL );
  }
  
  /* Create the IP datagram. */
  ip_pkptr = ip_dgram_create();

  /* Set the bulk size of the IP packet to model the space  */
  /* occupied by the encapsulated IP packet. This is equal to */
  /* the data packet plus the size of the ICMP header.    */
  op_pk_bulk_size_set( ip_pkptr, op_pk_total_size_get( *orig_ip_pk_ptr ) );

  /* Since no request should be made to the IP process,   */
  /* explicitly de-install any outstanding ICIs.        */
  op_ici_install( OPC_NIL );

  /* Copy the old info field to create new one for the outer packet. */
  new_ip_dgram_fd_ptr = ip_dgram_fdstruct_copy (old_ip_dgram_fd_ptr);

  /* Remove the extension headers if any. The outer packet  */
  /* of a MIPv6 tunnel must not carry any IPv6 extension    */
  /* headers, otherwise MIPv6 may process it as a MIPv6     */
  /* control message.                     */
  if ( ipv6_extension_header_exists( new_ip_dgram_fd_ptr ) ) {
    /* Remove the extension headers from the outer packet.  */
    ip_dgram_extension_headers_info_destroy( new_ip_dgram_fd_ptr );   
  }

  /* While copying the contents of the IPv6 header fields   */
  /* copies of the original source and destination IPv6     */
  /* addresses were allocated in memory. They must be     */
  /* destroyed since they will be replaced by the tunnels   */
  /* source and destination addresses.            */
  inet_address_destroy (new_ip_dgram_fd_ptr->src_addr);
  inet_address_destroy (new_ip_dgram_fd_ptr->dest_addr);
  
  /* Set the destination address for this IP datagram.    */
  new_ip_dgram_fd_ptr->src_addr = inet_address_copy( src_address );

  /* Also set the internal source address.          */
  new_ip_dgram_fd_ptr->src_internal_addr = inet_rtab_addr_convert( src_address );

  /* Set the destination address for this IP datagram.    */
  new_ip_dgram_fd_ptr->dest_addr = inet_address_copy( dest_address );

  /* Also set the internal destination address.       */  
  new_ip_dgram_fd_ptr->dest_internal_addr = inet_rtab_addr_convert( dest_address );
  
  /* The protocol fields  must indicate that there is an IPv6 */
  /* datagram encapsulated in this packet.          */
  new_ip_dgram_fd_ptr->protocol = IpC_Protocol_IPv6;
  
  /* Set the packet size-related fields of the IP datagram. */
  new_ip_dgram_fd_ptr->orig_len = op_pk_total_size_get( *orig_ip_pk_ptr ) / 8;
  new_ip_dgram_fd_ptr->frag_len = new_ip_dgram_fd_ptr->orig_len;
  new_ip_dgram_fd_ptr->original_size = 160 + new_ip_dgram_fd_ptr->orig_len * 8;

  /* Indicate that the packet is not yet fragmented.      */
  new_ip_dgram_fd_ptr->frag = 0;

  /* Set the encapsulation count for sim efficiency.      */
  new_ip_dgram_fd_ptr->encap_count++;

  new_ip_dgram_fd_ptr->dest_internal_addr = IPC_FAST_ADDR_INVALID;
  new_ip_dgram_fd_ptr->src_internal_addr  = IPC_FAST_ADDR_INVALID;

  /*  Set the fields structure inside the ip datagram.    */
  op_pk_nfd_set( ip_pkptr, "fields", new_ip_dgram_fd_ptr, 
      ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields) );

  /* Set the original IP packet in the data field of the new  */
  /* IP datagram.                       */
  op_pk_nfd_set( ip_pkptr, "data", *orig_ip_pk_ptr );

  /* Update the tunneled traffic statistics. */
  hmipv6_tunnel_traffic_sent_stat_update( iprmd_ptr, &ip_pkptr, inner_pkt_size );

  /* Return the outer packet.                 */
  *orig_ip_pk_ptr = ip_pkptr;
  
  FOUT;
}

Boolean  
hmipv6_tunnel_end_point_pkt_process( IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_pptr, IpT_Rte_Ind_Ici_Fields** intf_ici_fdstruct_pptr ) {
  char addr_str[INETC_ADDR_STR_LEN];    
  char string[256], str2[256];
  char addr2_str[INETC_ADDR_STR_LEN];   
  IpT_Dgram_Fields*       ip_dgram_fd_ptr;
  hmipv6_bu_entry*        bind_update_list_entry_ptr;
  hmipv6_route_opt_evnt*  cn_node_info_ptr;

  /** This functions process IPv6 process  packets at the   **/
  /** end point of a MIPv6 tunnel. The enpoints can be a    **/
  /** Home Agent or a Mobile Node.              **/
  FIN(hmipv6_tunnel_end_point_pkt_process (IpT_Rte_Module_Data* iprmd_ptr, Packet** orig_ip_pk_pptr, IpT_Rte_Ind_Ici_Fields** intf_ici_fdstruct_pptr));

  /* Update the tunneled traffic statistics.          */
  hmipv6_tunnel_traffic_received_stat_update (iprmd_ptr, *orig_ip_pk_pptr);

  /* Print debug trace messages.                */
  if ( op_prg_odb_ltrace_active( "mipv6_tunnel" ) ) {
    /* Check the original source of this packet.      */
    op_pk_nfd_access (*orig_ip_pk_pptr, "fields", &ip_dgram_fd_ptr);

    /* Converting the IPv6 address into a string.     */
    inet_address_print (addr_str, ip_dgram_fd_ptr->src_addr);
  
    /* Converting the IPv6 address into a string.     */
    inet_address_print (addr2_str, ip_dgram_fd_ptr->dest_addr);
      
    sprintf (string, "Outer packet:  Source[%s], Destination [%s]", addr_str, addr2_str);
    
    op_prg_odb_print_major( "MIPv6 Tunnel: Decapsulating packet.", string, OPC_NIL );
  }

  /* Decapsulate the original packet. */
  hmipv6_decapsulate_pkt( orig_ip_pk_pptr );

  /* Access the IP header fields. */
  op_pk_nfd_access( *orig_ip_pk_pptr, "fields", &ip_dgram_fd_ptr );
  
  /* Check if this is a mobile node.              */
  if (ip_rte_node_is_mipv6_mobile_node( iprmd_ptr ) && iprmd_ptr->mipv6_info_ptr->out_of_home ) {
    /* Check for IPv6 extension headers carried by the packet. */
    if ( ipv6_protocol_is_extension_header( (IpT_Protocol_Type) ip_dgram_fd_ptr->protocol ) ) {
      /* Process the IPv6 extension headers.        */
      if (ipv6_extension_header_process( iprmd_ptr, orig_ip_pk_pptr, &ip_dgram_fd_ptr, intf_ici_fdstruct_pptr, OPC_TRUE ) == OPC_FALSE ) {
        /* If the IPv6 datagram was processed and  */
        /* destroyed in the process then do not proceed.  */
        FRET (OPC_FALSE);
      }
      /* Check the original source of this packet.    */
      op_pk_nfd_access (*orig_ip_pk_pptr, "fields", &ip_dgram_fd_ptr);
    }
      
    /* Print debug trace messages. */
    if (op_prg_odb_ltrace_active ("hmipv6_tunnel")) {
      /* Converting the IPv6 address into a string. */
      inet_address_print (addr_str, ip_dgram_fd_ptr->src_addr);
    
      /* Converting the IPv6 address into a string. */
      inet_address_print (addr2_str, ip_dgram_fd_ptr->dest_addr);
    
      sprintf( str2, "Inner packet Source[%s], Destination [%s], Extensions [%d]", addr_str, addr2_str,
        ipv6_protocol_is_extension_header ((IpT_Protocol_Type) ip_dgram_fd_ptr->protocol));
      
      op_prg_odb_print_minor (str2, OPC_NIL);
    }

    /* Check if an entry already exist. */
    bind_update_list_entry_ptr = (hmipv6_bu_entry *) hmipv6_bind_update_entry_info_get (iprmd_ptr, ip_dgram_fd_ptr->src_addr);
  
    /* If the source address of the sender is not yet in  */
    /* the binding update list, or if it is notmarked as no */
    /* future binding, then inform the Mipv6 process so the */
    /* route optimization procedure starts.         */
    if (bind_update_list_entry_ptr == OPC_NIL) {
      cn_node_info_ptr = (hmipv6_route_opt_evnt *) op_prg_mem_alloc (sizeof (hmipv6_route_opt_evnt));
      /* No entry exists in the binding table. */
      /* Inform Mipv6 process. */

      cn_node_info_ptr->cn_address = inet_address_copy (ip_dgram_fd_ptr->src_addr);
      
      /* A Process interrupt will the used. Use the router*/
      /* list entry as the event state.         */
      op_ev_state_install (cn_node_info_ptr, hmipv6_sup_bind_addr_print_proc);

      /* Schedule the process interrupt.          */
      op_intrpt_schedule_process (iprmd_ptr->mipv6_info_ptr->mipv6_mn_prohandle, op_sim_time (), MIPV6C_START_BINDING_INTRPT_CODE);
      
      /* Uninstall the event state.           */
      op_ev_state_install (OPC_NIL, OPC_NIL);
      }
    }

  /* In order to prevent filters, route maps etc. of the    */
  /* incoming physical interface from being applied on this   */
  /*  packet again, we flag that this packet is a tunnel    */
  /* packet at the source. If this tunnel is happening is   */
  /* the current node is either a Home Agent or a Mobile Node.*/
  /* The flag will be reset by ip_rte_packet_arrival at this  */
  /* node itself.                       */
  ip_dgram_fd_ptr->tunnel_pkt_at_src = OPC_TRUE;

  /* If the source is not yet in the binding          */
  /* Return the packet back to IP.              */
  op_pk_deliver (*orig_ip_pk_pptr,  iprmd_ptr->module_id, (*intf_ici_fdstruct_pptr)->instrm);
  
  FRET( OPC_FALSE );
}
  
void
hmipv6_sup_bind_addr_print_proc( const void* state_ptr, PrgT_List* dump_lptr ) {

  char ip_addr_str[INETC_ADDR_STR_LEN];
  char line[256];
  hmipv6_route_opt_evnt*  cn_node_info_ptr;

  /** Print the contents of a CN list entry.      **/
  FIN( hmipv6_sup_bind_addr_print_proc( const void* state_ptr, PrgT_List* dump_lptr ) );

  /* Cast the state_ptr to the correct type.      */
  cn_node_info_ptr = (hmipv6_route_opt_evnt *) state_ptr;

  /* Print the IP address of this entry.        */
  inet_address_print( ip_addr_str, cn_node_info_ptr->cn_address );

  sprintf (line, "Start binding with address [%s]", ip_addr_str);
  prg_list_insert (dump_lptr, prg_string_copy (line), PRGC_LISTPOS_TAIL);

  FOUT;
}
  
void    
hmipv6_decapsulate_pkt( Packet** orig_ip_pk_ptr ) {

  Packet* encap_pkptr;

  /** This function removes and IPv6 in IPv6 encapsulated **/
  /** packet. It is used at the end point of a MIPv6 tunnel. **/
  FIN( hmipv6_decapsulate_pkt( Packet** orig_ip_pk_ptr ) );

  /* Access the encapsulated packet. */
  op_pk_nfd_get( *orig_ip_pk_ptr, "data", &encap_pkptr );
  
  /* Destroy the carrier. */
  op_pk_destroy( *orig_ip_pk_ptr );
  
  /* Give the encapsulated packet to the caller. */
  *orig_ip_pk_ptr = encap_pkptr;

  FOUT;
}
