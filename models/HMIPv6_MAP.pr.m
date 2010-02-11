MIL_3_Tfile_Hdr_ 145A 140A modeler 9 4B46A52B 4B746B7E 50 planet12 Student 0 0 none none 0 0 none F1704EC7 58DE 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                              ��g�      @   D   H      8�  U   U$  U(  U,  V�  V�  V�  8�           	   begsim intrpt             ����      doc file            	nd_module      endsim intrpt             ����      failure intrpts            disabled      intrpt interval         ԲI�%��}����      priority              ����      recovery intrpts            disabled      subqueue                     count    ���   
   ����   
      list   	���   
          
      super priority             ����          $    /* Modules own process handle */   Prohandle	\selfHndl;       #/* Modules parent process handle */   Prohandle	\parentHndl;       /* Our own Object ID */   Objid	\selfId;       /* Object ID of the parent */   Objid	\parentId;       +/* cstring to hold the this model's name */   char	\modelName[10];       0/* Handle for this process after registration */   OmsT_Pr_Handle	\procHndl;       &/* We received a packet from the IP */   &/*                                  */   bool	\bu_packet;       Packet *	\currpacket;       bool	\tunnelout;       /std::map<std::string, std::string>	\bind_cache;       std::string	\dest;       bool	\tunnelin;       std::string	\src;       address_t	\map_address;           S   #include <opnet.h>   #include <hmipv6_defs.h>   #include <hmipv6_support.h>   #include <hmipv6_common.h>   #include <ip_rte_v4.h>   #include <ip_rte_support.h>   (#include <ipv6_extension_headers_defs.h>   '#include <ipv6_extension_headers_sup.h>   #include <ip_dgram_sup.h>   #include <ipv6_ra.h>   #include <ip_arp.h>   #include <ip_icmp_pk.h>   #include <mobile_ip_support.h>   #include <string.h>   #include <string>   #include <map>       using std::string;   using std::map;       =//extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];   aint	mobility_msg_size_in_bits [MIPV6C_MOB_MSG_COUNT] = { 64, 128, 128, 192, 192, 128, 128, 192 };       B/* Make sure lower modules have registered them selves properly */   <#define SELF_NOTIFY  ( op_intrpt_type() == OPC_INTRPT_SELF )       5/* Indicates BU arrival from lower layer IP Module */   (#define BU_PACKET  ( bu_packet == true )       /**   ( * Redirect this packet into map domain.    */   '#define TUNNEL_OUT ( tunnelin == true )       /**    */   '#define TUNNEL_IN ( tunnelout == true )       8/* Define the packet source index for incoming stream */   #define IN_STRM   0       :/* Define the packet source index for the output stream */   #define OUT_STRM  1       #define MAP_ADDR "1:1:1:1"       &bool is_bind_update( Packet* packet );       +bool cache_has_lcoa( std::string address );       /**   3 * Make sure the given packet is the correct format    */   *bool correct_packet_fmt( Packet* packet );       /**   0 * Set the destination of a packet to new value.    */   APacket* set_destination( Packet* packet, address_t destination );       /**   7 * Obtain the regional care of address from the packet.    */   %address_t get_RCoA( Packet* packet );       /**   0 * Send a binding acknowledgment to destination.    */   9void send_BAck( address_t destination, address_t RCoA  );       /**   > * This function removes and IPv6 in IPv6 encapsulated packet.   3 * It is used at the end point of a HMIPv6 tunnel.     */    (void decapsulate_pkt( Packet** packet );       /**    J * Encapsulates IPv6 in IPv6 packets to be transported by a MIPv6 tunnel.     */   void   ptunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** packet, InetT_Address source, InetT_Address dest_address );          A   /**   1 * Inspect the given packet, is it a bind update?    *   ) * @param packet - The packet to inspect.   $ * @return true if bu, false if not.    */   (bool is_bind_update( Packet* packet ) {          List* list;     IpT_Dgram_Fields* fields;      Ipv6T_Mobility_Hdr_Info* info;       !	FIN( is_bind_update( packet ) );       '  if ( correct_packet_fmt( packet ) ) {       +    fields = ip_dgram_fields_get( packet );       %    /* check the  extionsion types */   >    if ( IpC_Procotol_Mobility_Ext_Hdr == fields->protocol ) {       %      /* Grab the mobility headers */   6      list = ipv6_extension_header_list_get( fields );   U      info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );       2      if ( Mipv6C_Bind_Update == info->mh_type ) {   0        /* This is obviously a binding update */   1        puts( "HMIPv6 MAP: Got Binding Update" );           FRET( true );         }       }     }         FRET( false );   }       /**   / * Reverse lookup the LCoA in the binding cache    *   3 * @param address - The address we are looking for.   ' * @return true if found, false if not.    */   -bool cache_has_lcoa( std::string address ) {        0  std::map<std::string,std::string>::iterator i;       	FIN( cache_has_lcoa( void ) );       =  for( i = bind_cache.begin(); i != bind_cache.end(); i++ ) {   ,    if ( address.compare( i->second ) == 0 )   =      printf( "HMIPv6 MAP: Cache has: %s", address.c_str() );         FRET( true );     }       >  printf( "HMIPv6 MAP: !Cache missing: %s", address.c_str() );     FRET( false );   }       /**   0 * Set the destination of a packet to new value.    */   ;Packet* set_source( Packet* packet, std::string src_str ) {         address_t source;     IpT_Dgram_Fields* fields;       +	FIN( set_destination( packet, src_str ) );       &  source = stringToAddress( src_str );       /	op_pk_nfd_access( packet, "fields", &fields );       1  fields->src_addr = inet_address_copy( source );   I  fields->src_internal_addr = inet_rtab_addr_convert( fields->src_addr );       +	op_pk_nfd_set( packet, "fields", fields );         FRET( packet );   }           /**   0 * Set the destination of a packet to new value.    */   APacket* set_destination( Packet* packet, std::string dest_str ) {         address_t destination;     IpT_Dgram_Fields* fields;       ,	FIN( set_destination( packet, dest_str ) );       ,  destination = stringToAddress( dest_str );       /	op_pk_nfd_access( packet, "fields", &fields );       7  fields->dest_addr = inet_address_copy( destination );   K  fields->dest_internal_addr = inet_rtab_addr_convert( fields->dest_addr );       +	op_pk_nfd_set( packet, "fields", fields );         FRET( packet );   }           /**   7 * Obtain the regional care of address from the packet.    *   ( * @param packet - The packet to inspect   B * @return the regional care of address from the mobility headers.    */   &address_t get_RCoA( Packet* packet ) {          List* list;     address_t RCoA;     IpT_Dgram_Fields* fields;      Ipv6T_Mobility_Hdr_Info* info;     std::string address;         FIN( get_RCoA( packet ) );        )  fields = ip_dgram_fields_get( packet );   !  /* Grab the mobility headers */   2  list = ipv6_extension_header_list_get( fields );   Q  info = (Ipv6T_Mobility_Hdr_Info*) op_prg_list_access( list, OPC_LISTPOS_HEAD );                 F  RCoA = inet_address_copy( info->msg_data.bind_update.home_address );       $  address = addressToString( RCoA );   =  printf( "HMIPv6 MAP: RCoA obtained: %s", address.c_str() );         FRET( RCoA );   }       /**   0 * Send a binding acknowledgment to destination.    */   9void send_BAck( address_t destination, address_t RCoA ) {     Packet*           packet;      OpT_Packet_Size   ext_hdr_len;     IpT_Dgram_Fields* dgram;   #  Ipv6T_Mobility_Hdr_Info*  header;       #  FIN( send_BAck( destination ) );           /* Create the IP datagram. */     packet = ip_dgram_create();        8  /* Get the size contributed by the mobility header. */   F  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_ACK];        1  /* Create IP datagram fields data structure. */   %  dgram = ip_dgram_fdstruct_create();       8  /* Assign values to members of the field structure. */   E  /* Set the source address to be the global address of interface. */        D  /* The ha iface ptr must be obtained from the ha iface table. */     '  // TODO: Get MAP's actuall IP Address   c  //dgram->src_addr     = inet_address_copy( *(module_data_ptr->mipv6_info_ptr->care_of_addr_ptr));   J  //dgram->src_internal_addr  = inet_rtab_addr_convert( dgram->src_addr );   ?  dgram->src_addr = inet_address_copy( InetI_Default_v6_Addr );   M  dgram->src_internal_addr = inet_rtab_addr_convert( InetI_Default_v6_Addr );        +  /* Set the destination address (MN). */     ?  dgram->dest_addr          = inet_address_copy( destination );   D  dgram->dest_internal_addr = inet_rtab_addr_convert( destination );       <  /* No data packet is encapsulated in this datagram, use */   <  /* the length fields to model the extension header size.*/      dgram->orig_len = ext_hdr_len;      dgram->frag_len = ext_hdr_len;     dgram->ttl      = 255;        8  /* The protocol field (next header in IPv6) must    */   :  /* indicate that this is a mobility extension header. */   2  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;       7  /* Set the message fields to the indicated values. */   U  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Ack );   H  header->msg_data.bind_update.home_address = inet_address_copy( RCoA );       C  /* Set the mobility header information in the datagram fields. */   ,  ipv6_mobility_hdr_insert( dgram, header );        7  /* Set the datagram fields into the IPv6 datagram. */   '  ip_dgram_fields_set( packet, dgram );       %  /* Refresh the IP packet fields. */   /  op_pk_nfd_access( packet, "fields", &dgram );       ?  /* Alter the header field size to model the mob msg size. */        :  /* Add the size of the mobility extension header into */   =  /* the packet. Modify the size of the header fields in   */   2  /* the IPv6 packet to achieve this.           */       <  ip_dgram_sup_ipv6_extension_hdr_size_add( &packet, &dgram,   9      IpC_Procotol_Mobility_Ext_Hdr, (int) ext_hdr_len );       "  /* Uninstall the event state. */   )  op_ev_state_install( OPC_NIL, OPC_NIL);          4  /* Deliver this IPv6 datagram to the IP module. */   ,  op_pk_deliver( packet, selfId, OUT_STRM );         FOUT;   }        /**   > * This function removes and IPv6 in IPv6 encapsulated packet.   3 * It is used at the end point of a HMIPv6 tunnel.     */    )void decapsulate_pkt( Packet** packet ) {         Packet* encapsulated_packet;       #  FIN( decapsulate_pkt( packet ) );       '  /* Access the encapsulated packet. */   9  op_pk_nfd_get( *packet, "data", &encapsulated_packet );        #  /* Destroy the carrier packet. */     op_pk_destroy( *packet );        3  /* Give the encapsulated packet to the caller. */      *packet = encapsulated_packet;         FOUT;   }       /**    J * Encapsulates IPv6 in IPv6 packets to be transported by a MIPv6 tunnel.     */   void   qtunnel_pkt( IpT_Rte_Module_Data* iprmd_ptr, Packet** packet, InetT_Address source, InetT_Address dest_address ) {         Packet* ip_packet;   !  IpT_Dgram_Fields* new_datagram;   !  IpT_Dgram_Fields* old_datagram;       ?  FIN( tunnel_pkt( iprmd_ptr, packet, source, dest_address ) );       4  /* Access the old field information.            */   7  op_pk_nfd_access( *packet, "fields", &old_datagram );         /* Create the IP datagram. */      ip_packet = ip_dgram_create();       >  /* Set the bulk size of the IP packet to model the space  */   @  /* occupied by the encapsulated IP packet. This is equal to */   <  /* the data packet plus the size of the ICMP header.    */   D  op_pk_bulk_size_set( ip_packet, op_pk_total_size_get( *packet ) );       <  /* Since no request should be made to the IP process,   */   :  /* explicitly de-install any outstanding ICIs.        */     op_ici_install( OPC_NIL );       G  /* Copy the old info field to create new one for the outer packet. */   8  new_datagram = ip_dgram_fdstruct_copy( old_datagram );       >  /* Remove the extension headers if any. The outer packet  */   >  /* of a MIPv6 tunnel must not carry any IPv6 extension    */   >  /* headers, otherwise MIPv6 may process it as a MIPv6     */   ,  /* control message.                     */   7  if ( ipv6_extension_header_exists( new_datagram ) ) {   >    /* Remove the extension headers from the outer packet.  */   ?    ip_dgram_extension_headers_info_destroy( new_datagram );        }       >  /* While copying the contents of the IPv6 header fields   */   >  /* copies of the original source and destination IPv6     */   <  /* addresses were allocated in memory. They must be     */   >  /* destroyed since they will be replaced by the tunnels   */   4  /* source and destination addresses.            */   1  inet_address_destroy( new_datagram->src_addr );   2  inet_address_destroy( new_datagram->dest_addr );        <  /* Set the destination address for this IP datagram.    */   7  new_datagram->src_addr = inet_address_copy( source );       6  /* Also set the internal source address.          */   E  new_datagram->src_internal_addr = inet_rtab_addr_convert( source );       <  /* Set the destination address for this IP datagram.    */   >  new_datagram->dest_addr = inet_address_copy( dest_address );       :  /* Also set the internal destination address.       */     L  new_datagram->dest_internal_addr = inet_rtab_addr_convert( dest_address );        @  /* The protocol fields  must indicate that there is an IPv6 */   6  /* datagram encapsulated in this packet.          */   -  new_datagram->protocol = IpC_Protocol_IPv6;        >  /* Set the packet size-related fields of the IP datagram. */   ?  new_datagram->orig_len = op_pk_total_size_get( *packet ) / 8;   2  new_datagram->frag_len = new_datagram->orig_len;   A  new_datagram->original_size = 160 + new_datagram->orig_len * 8;       <  /* Indicate that the packet is not yet fragmented.      */     new_datagram->frag = 0;       <  /* Set the encapsulation count for sim efficiency.      */     new_datagram->encap_count++;       ;  new_datagram->dest_internal_addr = IPC_FAST_ADDR_INVALID;   ;  new_datagram->src_internal_addr  = IPC_FAST_ADDR_INVALID;       <  /*  Set the fields structure inside the ip datagram.    */   4  op_pk_nfd_set( ip_packet, "fields", new_datagram,    U      ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof (IpT_Dgram_Fields) );       M  /* Set the original IP packet in the data field of the new  IP datagram. */   .  op_pk_nfd_set( ip_packet, "data", *packet );          /* Return the outer packet. */     *packet = ip_packet;          FOUT;   }                                         Z   �          
   init   
       J   )   /***   + * 1) Register process in the global table.    * 2) Obtain model parameters    *      e.g. operation mode    *    *    * Declared in State Variables:    *  - selfId    *  - parentId    *  - selfHndl    *  - parentHndl    *  - modelName     *  - procHndl    ***/       %/* Get self id and our parent's id */   selfId   = op_id_self();   $parentId = op_topo_parent( selfId );       /* Obtain process model name */   :op_ima_obj_attr_get( selfId, "process model", modelName );       0/* Obtain handles for our self and our parent */   selfHndl   = op_pro_self();   )parentHndl = op_pro_parent( selfHndl );             1/* Register the process in model-wide registry */   \procHndl = (OmsT_Pr_Handle)oms_pr_process_register( parentId, selfId, selfHndl, modelName );       6/* Register the protocol attribute in the	registry. */   Joms_pr_attr_set( procHndl, "protocol", OMSC_PR_STRING, "mipv6", OPC_NIL );       'puts( "HMIPv6 MAP: Initialized MAP"  );        /* Initialize state variables */   +/* TODO: Hard coding MAP Address for now */   9map_address = stringToAddress( std::string( MAP_ADDR ) );   bu_packet = false;   tunnelout = false;   tunnelin  = false;   J                         ����             pr_state         �   �          
   idle   
                     J   (   /***    * Sate Variables:    *   Packet * currpacket     *   bool bu_packet    *   bool redirect    " *   map<string,string> bind_cache    *   % * Purpose: Inspect incoming packets    1 * Author: Brian Gianforcaro (b.gianfo@gmail.com)    */       +if( op_intrpt_type() == OPC_INTRPT_STRM ) {       '    puts( "HMIPv6 MAP: got packet\n" );   &    currpacket = op_pk_get( IN_STRM );       '    /* Make sure the packet is sound */   E    if ( (NULL != currpacket) && correct_packet_fmt( currpacket ) ) {       ;      dest = addressToString( dest_address( currpacket ) );   ;      src  = addressToString(  src_address( currpacket ) );       0      /* Check if the packet is a bind update */   +      if ( is_bind_update( currpacket ) ) {           bu_packet = true;   8        /* Try to find an address for the destination */   P        /* Packet coming above (outside) MAP needs to be tunneled in (under). */   B      } else if ( bind_cache.find( dest ) != bind_cache.end() ) {            tunnelin = true;   3        /* Try to find an address for the source */   Q        /* Packet coming bellow (inside) MAP needs to be tunneled out (above). */   +      } else if ( cache_has_lcoa( src ) ) {           tunnelout = true;         } else {   $        op_pk_destroy( currpacket );         }       } else {   "      op_pk_destroy( currpacket );       }   }   J           ����             pr_state         �             
   BU   
       
      /**   + * Modify Source Address if RCoA is active.    * Relay currpacket to PPP    */       /puts( "HMIPv6 MAP: Process Binding Update\n" );       @std::string LCoA = addressToString( src_address( currpacket ) );       =std::string RCoA = addressToString( get_RCoA( currpacket ) );       /* Insert address into cache */   bind_cache[RCoA] = LCoA;       -/* Send a binding acknoledgement to the MN */   >send_BAck( stringToAddress( LCoA ), stringToAddress( RCoA ) );       op_pk_destroy( currpacket );   
       
       // Reset our state back to false   bu_packet = false;   
       
   ����   
          pr_state        J            
   TNL_IN   
       J      /*   ** Sate Variables:   **   Packet * currpacket    3**   std::map<std::string, std::string> bind_cache;   **   1** Author: Brian Gianforcaro (b.gianfo@gmail.com)   ;** Action: Update variables to indicate that RCoA is active   */       0/* Packet coming in from top of MAP down into */   )puts( "HMIPv6 MAP: Tunnel packet in\n" );       7/* Obtain the curr packet's regional care of address */   Astd::string RCoA = addressToString( dest_address( currpacket ) );       /*   1** Set the destination address of the curr packet   '** to the cached local care of address    */   ?//currpacket = set_destination( currpacket, bind_cache[RCoA] );       Ltunnel_pkt( &currpacket, map_address, stringToAddress( bind_cache[RCoA] ) );       0/* Send the curr packet back to the IP module */   #op_pk_send( currpacket, OUT_STRM );   J       
       // Reset our state back to false   tunnelin = false;   
       
   ����   
          pr_state        �   �          
   TNL_OUT   
       J   #   /**    * Sate Variables:    *   Packet * currpacket     *   bool bu_packet    *   bool redirect     *   1 * Author: Brian Gianforcaro (b.gianfo@gmail.com)   ; * Action: Update variables to indicate that RCoA is active    */       </* Packet coming from inside MAP needs to be tunneled out */   *puts( "HMIPv6 MAP: Tunnel packet out\n" );       %std::map<string,string>::iterator it;       6/* Obtaion the currpackets regional care of address */   @std::string LCoA = addressToString( src_address( currpacket ) );   std::string RCoA("");   //* look up the RCoA care of address for this */   >for( it = bind_cache.begin(); it != bind_cache.end(); it++ ) {   *  if ( LCoA.compare( it->second ) == 0 ) {       RCoA = it->first;   
    break;     }   }       1// Set the destionation address of the currpacket   '// to the cached local care of address    .//currpacket = set_source( currpacket, RCoA );       A// Decapsulate packet since it has reached the end of it's tunnel   decapsulate_pkt( &currpacket );       //* Send the currpacket back to the IP module */   #op_pk_send( currpacket, OUT_STRM );   J       
      // Reset state back to false   tunnelout = false;   
       
   ����   
          pr_state                      �   _      �   '   �   �          
   tr_2   
       ����          ����          
    ����   
          ����                       pr_transition               �   d      �   �   �   9          
   tr_3   
       
   	BU_PACKET   
       ����          
    ����   
          ����                       pr_transition              -   {      �   �  o   �          
   tr_14   
       
   
TUNNEL_OUT   
       ����          
    ����   
          ����                       pr_transition              5   y     p   �   �   �          
   tr_15   
       
����   
       ����          
    ����   
          ����                       pr_transition                �   �      o   �   �   �          
   tr_16   
       J����   J       ����          
    ����   
          ����                       pr_transition              U   �      �   �  H   �          
   tr_20   
       
   	TUNNEL_IN   
       ����          
    ����   
          ����                       pr_transition                 �     /     �   �          
   tr_21   
       ����          ����          
    ����   
          ����                       pr_transition               �   �      �   �   �   �   �   �   �   �          
   tr_24   
       
   default   
       ����          
    ����   
       
    ����   
                    pr_transition                           hmipv6_common   
ip_addr_v4   ip_attr_def_support   ip_auto_addr_sup_v4   ip_dgram_sup   ip_rtab_sup_v4   ip_rte_map_support   ip_rte_slot   ip_rte_sup_v4   ip_rte_support   ip_rte_table_v4   ip_sim_attr_cache   
ip_support   ipv6_dest_cache   ipv6_extension_headers_sup   ipv6_nd   ipv6_ra   mipv6_signaling_sup   	mipv6_sup   mobile_ip_support   mobility_support   oms_dl          ip_dgram_v4            