MIL_3_Tfile_Hdr_ 145A 140A modeler 9 4B469696 4B747708 33 planet12 Student 0 0 none none 0 0 none 555E194F 43FF 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                              ��g�      @   D   H      (4  ?�  ?�  ?�  ?�  A�  A�  A�  ((           	   begsim intrpt             ����      doc file            	nd_module      endsim intrpt             ����      failure intrpts            disabled      intrpt interval         ԲI�%��}����      priority              ����      recovery intrpts            disabled      subqueue                     count    ���   
   ����   
      list   	���   
          
      super priority             ����             address_t	\lcoa;       Prohandle	\selfHndl;       Prohandle	\parentHndl;       Objid	\selfId;       Objid	\parentId;       address_t	\map_address;       Packet *	\currpacket;       bool	\address_changed;       address_t	\rcoa;       char	\modelName[10];       OmsT_Pr_Handle	\procHndl;       bool	\tunneld;       bool	\have_map_addr;           T   #include <opnet.h>   #include <hmipv6_defs.h>   #include <hmipv6_common.h>   #include <hmipv6_support.h>   #include <ip_rte_v4.h>   #include <ip_rte_support.h>   (#include <ipv6_extension_headers_defs.h>   '#include <ipv6_extension_headers_sup.h>   #include <ip_dgram_sup.h>   #include <ipv6_ra.h>   #include <ip_arp.h>   #include <ip_icmp_pk.h>   #include <mobile_ip_support.h>   #include <string.h>   #include <string>   #include <map>       ;extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];       L/* Make sure processes of lower modules have registered in global process */   <#define SELF_NOTIF   ( op_intrpt_type() == OPC_INTRPT_SELF )       K/* Stream interupt indicating packet arrival from higher layer IP Module */   0#define INCOMING_PKT    ( true == incomingpkt )        3#define ADDRESS_CHANGED ( true == address_changed )       1#define HAVE_MAP_ADDR   ( true == have_map_addr )       +#define PKT_IS_TUNNELD  ( true == tunneld )       8/* Define the packet source index for incoming stream */   #define IN_STRM   0       :/* Define the packet source index for the output stream */   #define OUT_STRM  1       #define HEX_FMT   16       /**   3 * Make sure the given packet is the correct format    */   *bool correct_packet_fmt( Packet* packet );       /**   7 * Inspect the given packet, is it a MAP Advertisement?    *   E * @NOTE!: For simplicity we use the  Mipv6C_Bind_Ref_Req header type   < * to represent a MAP Advertisement packet. The home_address    * will hold the MAP Address.    *   ) * @param packet - The packet to inspect.   , * @return true if MAP Advert, false if not.    */   %bool is_map_advert( Packet* packet );       /**   # * Obtain the MAP Address from the     */   ,address_t get_map_address( Packet* packet );       /**   ' * Generate a regional care of address.    */    address_t generate_rcoa( void );       /**   3 * Obtain the current ip_address of the mobile node    */   address_t get_lcoa( void );       /**   * * Determine if our ip_address had changed    */   bool has_lcoa_changed( void );       /**    4 * This function creates and sends an IPv6 datagram    3 * that carries a Binding Update MIPv6 message.        *   ) * @param dest_addr - Destination Address    */   static void   <bu_msg_send( address_t dest_addr, address_t suggestedRCoA );   �   /**   7 * Inspect the given packet, is it a MAP Advertisement?    *   E * @NOTE!: For simplicity we use the  Mipv6C_Bind_Ref_Req header type   < * to represent a MAP Advertisement packet. The home_address    * will hold the MAP Address.    *   ) * @param packet - The packet to inspect.   , * @return true if MAP Advert, false if not.    */   'bool is_map_advert( Packet* packet ) {          List* list;     IpT_Dgram_Fields* fields;      Ipv6T_Mobility_Hdr_Info* info;       	FIN( is_bind_ack( packet ) );       '  if ( correct_packet_fmt( packet ) ) {   +    fields = ip_dgram_fields_get( packet );   $    /* check the  extension types */   >    if ( IpC_Procotol_Mobility_Ext_Hdr == fields->protocol ) {   %      /* Grab the mobility headers */   6      list = ipv6_extension_header_list_get( fields );   U      info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );   '      /* This is a MAP advertisement */   3      if ( Mipv6C_Bind_Ref_Req == info->mh_type ) {   7        puts( "HMIPv6 MN: Packet is a MAP Advert\n" );            FRET( true );         }       }     }   5  puts( "HMIPv6 MN: Packet is NOT a MAP Advert\n" );      FRET( false );   }       /**   0 * Obtain the MAP Address from the given packet.   0 * @param packet - The map advertisement packet.   4 * @return - The MAP address from the advertisement.    */   .address_t get_map_address( Packet* packet ) {          List* list;     IpT_Dgram_Fields* fields;   "  Ipv6T_Mobility_Hdr_Info* header;     std::string address;       	FIN( is_bind_ack( packet ) );       )  fields = ip_dgram_fields_get( packet );       !  /* Grab the mobility headers */   2  list = ipv6_extension_header_list_get( fields );   S  header = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );   I  address = addressToString( header->msg_data.bind_update.home_address );   >  printf( "HMIPv6 MN: MAP Address - %s\n", address.c_str() );        I  FRET( inet_address_copy( header->msg_data.bind_update.home_address ) );   }       /**   ' * Generate a regional care of address.   6 * @return a newly generated regional care of address.    */   !address_t generate_rcoa( void ) {     address_t RCoA;     char buffer[33];     std::string map_addr;     unsigned int rand_int;     PrgT_Random_Gen* my_rng;         FIN( get_lcoa( void ) );       ,  /* Create a new random number generator */   *  my_rng = op_prg_random_gen_create( 99 );       ;  // Generate a random integer in the interval [0000,FFFF]    '  // The largest and smallest HEX Octet   >  rand_int = ( op_prg_random_integer_gen( my_rng ) % 0xFFFF );   +  /* Destroy the random number generator */   &  op_prg_random_gen_destroy( my_rng );         /* Build the RCoA string */   ,  map_addr = addressToString( map_address );     map_addr.append(":");   %  _itoa( rand_int, buffer, HEX_FMT );     map_addr.append( buffer );       B  printf( "HMIPv6 MN: Generated RCoa - %s\n", map_addr.c_str() );        /  /* Convert the generated string to address */   &  RCoA = stringToAddress( map_addr );          FRET( RCoA );   }       /**   3 * Obtain the current ip_address of the mobile node   % * @return the link care of address.     */   address_t get_lcoa( void ) {     address_t LCoA;     std::string address;         FIN( get_lcoa( void ) );       Q  LCoA = inet_support_address_from_node_id_get( parentId, InetC_Addr_Family_v6 );       $  address = addressToString( LCoA );   8  printf( "HMIPv6 MN: LCoA is %s\n", address.c_str() );      FRET( LCoA );   }       /**   * * Determine if our ip_address had changed   ) * @return true if changed, false if not.    */   bool has_lcoa_changed( void ) {     address_t my_address;       "  FIN( has_lcoa_changed( void ) );         my_address = get_lcoa();       1  if ( inet_address_equal( my_address, lcoa ) ) {   /    puts( "HMIPv6 MN: LCoA hasn't changed\n");        FRET( false  );     }   *  puts( "HMIPv6 MN: LCoA has changed\n");      FRET( true );   }       /**    4 * This function creates and sends an IPv6 datagram    3 * that carries a Binding Update MIPv6 message.        *   5 * @param dest_addr - Destination address to send bu.   P * @param suggestedRCoA - The regional care of address we would like to be ours.    */   static void   =bu_msg_send( address_t dest_addr, address_t suggestedRCoA ) {         Packet*           packet;      OpT_Packet_Size   ext_hdr_len;     IpT_Dgram_Fields* dgram;   #  Ipv6T_Mobility_Hdr_Info*  header;        1  FIN( bu_msg_send( dest_addr, suggestedRCoA ) );         /* Create the IP datagram. */     packet = ip_dgram_create();        8  /* Get the size contributed by the mobility header. */   I  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_UPDATE];        1  /* Create IP datagram fields data structure. */   %  dgram = ip_dgram_fdstruct_create();       8  /* Assign values to members of the field structure. */   E  /* Set the source address to be the global address of interface. */        D  /* The ha iface ptr must be obtained from the ha iface table. */     7  dgram->src_addr          = inet_address_copy( lcoa );   G  dgram->src_internal_addr = inet_rtab_addr_convert( dgram->src_addr );        +  /* Set the destination address (MN). */     =  dgram->dest_addr          = inet_address_copy( dest_addr );   I  dgram->dest_internal_addr = inet_rtab_addr_convert( dgram->dest_addr );       <  /* No data packet is encapsulated in this datagram, use */   <  /* the length fields to model the extension header size.*/      dgram->orig_len = ext_hdr_len;      dgram->frag_len = ext_hdr_len;     dgram->ttl      = 255;        8  /* The protocol field (next header in IPv6) must    */   :  /* indicate that this is a mobility extension header. */   2  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;       7  /* Set the message fields to the indicated values. */   X  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Update );   Q  header->msg_data.bind_update.home_address = inet_address_copy( suggestedRCoA );       C  /* Set the mobility header information in the datagram fields. */   ,  ipv6_mobility_hdr_insert( dgram, header );        7  /* Set the datagram fields into the IPv6 datagram. */   '  ip_dgram_fields_set( packet, dgram );       %  /* Refresh the IP packet fields. */   /  op_pk_nfd_access( packet, "fields", &dgram );       ?  /* Alter the header field size to model the mob msg size. */        :  /* Add the size of the mobility extension header into */   =  /* the packet. Modify the size of the header fields in   */   2  /* the IPv6 packet to achieve this.           */       <  ip_dgram_sup_ipv6_extension_hdr_size_add( &packet, &dgram,   9      IpC_Procotol_Mobility_Ext_Hdr, (int) ext_hdr_len );       "  /* Uninstall the event state. */   )  op_ev_state_install( OPC_NIL, OPC_NIL);          4  /* Deliver this IPv6 datagram to the IP module. */   ,  op_pk_deliver( packet, selfId, OUT_STRM );         FOUT;   }                                              Z   �          
   init   
       J   *   /***   + * 1) Register process in the global table.    * 2) Obtain model parameters    *      e.g. operation mode    *    * Declared in State Variables:    *  - selfId    *  - parentId    *  - selfHndl    *  - parentHndl    *  - modelName     *  - procHndl    ***/       %/* Get self id and our parent's id */   selfId   = op_id_self();   $parentId = op_topo_parent( selfId );       /* Obtain process model name */   :op_ima_obj_attr_get( selfId, "process model", modelName );       0/* Obtain handles for our self and our parent */   selfHndl   = op_pro_self();   )parentHndl = op_pro_parent( selfHndl );         1/* Register the process in model-wide registry */   EprocHndl = (OmsT_Pr_Handle)oms_pr_process_register( parentId, selfId,   A                                           selfHndl, modelName );       6/* Register the protocol attribute in the	registry. */   Koms_pr_attr_set( procHndl, "protocol", OMSC_PR_STRING, "hmipv6", OPC_NIL );       %/* Set up state transfer variables */   address_changed = false;   have_map_addr   = false;   tunneld         = false;       rcoa = InetI_Invalid_Addr;   !map_address = InetI_Invalid_Addr;   'lcoa = inet_address_copy( get_lcoa() );       0puts( "HMIPv6 MN: Initialized mobile node.\n" );   J                         ����             pr_state         �   �          J   GET MAP   J       J      %/* Attempt to grab the map address */       (/* Handle the interrupt appropriately */   switch( op_intrpt_type() ) {       "  /* We have a incoming packet. */     case OPC_INTRPT_STRM: {       &    puts( "HMIPv6 MN: Got packet\n" );   &    currpacket = op_pk_get( IN_STRM );       '    /* Make sure the packet is sound */   E    if ( (NULL != currpacket) && correct_packet_fmt( currpacket ) ) {   6      /* Check if the packet is a MAP Advertisement */   *      if ( is_map_advert( currpacket ) ) {   !        /* Snag that address ! */   4        puts( "HMIPv6 MN: Got MAP Advertisment\n" );   4        map_address = get_map_address( currpacket );           have_map_addr = true;         }       }         op_pk_destroy( currpacket );   
    break;     }       }   J                         ����             pr_state        �   �          
   idle   
       J   *       6/* Check if we our link care of address has changed */   if ( has_lcoa_changed() ) {       B  /* It has changed, change state so we can send a Bind Update. */     address_changed = true;       } else {       *  /* Handle the interrupt appropriately */     switch( op_intrpt_type() ) {          $    /* We have a incoming packet. */       case OPC_INTRPT_STRM: {       (      puts( "HMIPv6 MN: Got packet\n" );   (      currpacket = op_pk_get( IN_STRM );       )      /* Make sure the packet is sound */   G      if ( (NULL != currpacket) && correct_packet_fmt( currpacket ) ) {       8        /* Check if the packet is a MAP Advertisement */   ,        if ( is_map_advert( currpacket ) ) {   #          /* Snag that address ! */   6          map_address = get_map_address( currpacket );   	        }       5        /* Check that this is the tunnel end point */   -        if ( tunneled( currpacket, lcoa ) ) {   B          puts( "HMIPv6 MN: tunneled packet is at endpoint. \n" );   $          op_pk_print( currpacket );   =          /* Decapsulate packet and foreword too ip module */   )          decapsulate_pkt( &currpacket );   -          op_pk_send( currpacket, OUT_STRM );             break;   	        }         }    "      op_pk_destroy( currpacket );         break;       }     }   }   J                         ����             pr_state        �             
   SEND BU   
       J      /**    * State Variables:    *  - Packet* currpacket     *  - bool address_changed    *  - address_t map_address    *  - address_t lcoa    */           (lcoa = inet_address_copy( get_lcoa() );        //* If we don't have a RCoA yet, generate one */   6if ( inet_address_equal(rcoa, InetI_Invalid_Addr) ) {      rcoa = generate_rcoa();   }       4std::string mapstr = addressToString( map_address );   @printf( "HMIPv6 MN: Sending BU to MAP - %s\n", mapstr.c_str() );   !bu_msg_send( map_address, rcoa );   J       
      /* reset the state variable */   address_changed = false;   
       
   ����   
          pr_state        �            J   GOT_TNLD   J                                   J   ����   J          pr_state                       �   �      o   �   �   �          
   tr_14   
       J����   J       ����          
    ����   
          ����                       pr_transition              -   �      �   �  h   �          
   tr_16   
       J   HAVE_MAP_ADDR   J       ����          
    ����   
          ����                       pr_transition              <   _     t   �  u   7          
   tr_17   
       
   ADDRESS_CHANGED   
       ����          
@   ����   
          ����                       pr_transition              �   X     �   /  �   �          
   tr_18   
       ����          ����          
@   ����   
          ����                       pr_transition               �   �      �   �     �   �   �   �   �          
   tr_21   
       
   default   
       ����          
    ����   
          ����                       pr_transition              �   �     �   �  �   �  �   �  �   �          J   tr_22   J       J   default   J       ����          J    ����   J          ����                       pr_transition              ?   �     u   �  s   �          J   tr_23   J       J   PKT_IS_TUNNELD   J       ����          J    ����   J          ����                       pr_transition              �   �     �   �  �   �          J   tr_24   J       ����          ����          J    ����   J          ����                       pr_transition                           hmipv6_common   ip_acl_support   
ip_addr_v4   ip_attr_def_support   ip_auto_addr_sup_v4   ip_cmn_rte_table   ip_dgram_sup   ip_frag_sup_v3   ip_rtab_sup_v4   ip_rte_map_support   ip_rte_slot   ip_rte_sup_v4   ip_rte_support   ip_rte_table_v4   ip_sim_attr_cache   
ip_support   ip_te_support   ip_vpn_conf_log_support   ip_vpn_support   ip_vrf_table   ipv6_dest_cache   ipv6_extension_headers_sup   ipv6_nd   ipv6_ra   mipv6_signaling_sup   	mipv6_sup   mobile_ip_support   mobility_support   oms_dt   oms_pr                    