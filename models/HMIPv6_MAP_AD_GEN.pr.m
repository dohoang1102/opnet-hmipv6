MIL_3_Tfile_Hdr_ 145A 140A modeler 9 4B624B23 4B70C7B9 10 planet12 Student 0 0 none none 0 0 none 2785AD96 1A36 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                              ��g�      @   D   H      �  e  i  m  q  *  .  2  �           	   begsim intrpt             ����      doc file            	nd_module      endsim intrpt             ����      failure intrpts            disabled      intrpt interval         ԲI�%��}����      priority              ����      recovery intrpts            disabled      subqueue                     count    ���   
   ����   
      list   	���   
          
      super priority             ����             bool	\ap_enable;       bool	\disabled;       InetT_Address	\map_address;              #include <opnet.h>   #include <hmipv6_defs.h>   #include <hmipv6_defs.h>   #include <hmipv6_support.h>   #include <ip_rte_v4.h>   #include <ip_rte_support.h>   (#include <ipv6_extension_headers_defs.h>   '#include <ipv6_extension_headers_sup.h>   #include <ip_dgram_sup.h>   #include <ipv6_ra.h>   #include <ip_arp.h>   #include <ip_icmp_pk.h>   #include <mobile_ip_support.h>       ;extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];       #define TIMER_INTERRUPT 99       //* How often to check for packets in seconds */   #define TIME_LIMIT 	1.0       e#define TIMER_END       (op_intrpt_type () == OPC_INTRPT_SELF && op_intrpt_code() == TIMER_INTERRUPT)       a#define CAN_SEND ((op_intrpt_type() == OPC_INTRPT_SELF) && (op_intrpt_code() == TIMER_INTERRUPT))       ##define DISABLED (disabled == true)       #define OUT_STRM 0                                             Z   Z          
   init   
       
      /**   7 * Check paramaters, if not an ap, destory this module.    */   int ap_flag;   Objid myid;   Objid paramid;       :/* Obtain the values assigned to the various attributes	*/   myid = op_id_self();   Aop_ima_obj_attr_get( myid, "Wireless LAN Parameters", &paramid );   ;paramid = op_topo_child( paramid, OPC_OBJTYPE_GENERIC, 0 );       Fop_ima_obj_attr_get( paramid, "Access Point Functionality", &ap_flag);       char name[100];   0op_ima_obj_hname_get( op_id_self(), name, 100 );       B/* If this isn't an access point, don't generate advertisements */   (if ( ap_flag != OPC_BOOLINT_ENABLED ) {    <	printf( "Destroying HMIPv6 MN Advertiser in %s\n", name );    "  op_pro_destroy( op_pro_self() );     disabled = true;   } else {   :	printf( "Starting HMIPv6 MN Advertiser in %s\n", name );    }   
                         ����             pr_state           �          
   idle   
                                       ����             pr_state                    
   SEND AD   
       
   5        /* generate one advertisement */     Packet*           packet;      OpT_Packet_Size   ext_hdr_len;     IpT_Dgram_Fields* dgram;   #  Ipv6T_Mobility_Hdr_Info*  header;         /* Create the IP datagram. */     packet = ip_dgram_create();        8  /* Get the size contributed by the mobility header. */   F  ext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_ACK];        1  /* Create IP datagram fields data structure. */   %  dgram = ip_dgram_fdstruct_create();   p  dgram->src_addr = inet_support_address_from_node_id_get( op_topo_parent(op_id_self()), InetC_Addr_Family_v6 );   G  dgram->src_internal_addr = inet_rtab_addr_convert( dgram->src_addr );      dgram->orig_len = ext_hdr_len;      dgram->frag_len = ext_hdr_len;     dgram->ttl      = 255;        8  /* The protocol field (next header in IPv6) must    */   :  /* indicate that this is a mobility extension header. */   2  dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;       7  /* Set the message fields to the indicated values. */   U  header = (Ipv6T_Mobility_Hdr_Info *)ipv6_mobility_header_create( Mipv6C_Bind_Ack );   O  header->msg_data.bind_update.home_address = inet_address_copy( map_address );       C  /* Set the mobility header information in the datagram fields. */   ,  ipv6_mobility_hdr_insert( dgram, header );        7  /* Set the datagram fields into the IPv6 datagram. */   '  ip_dgram_fields_set( packet, dgram );       %  /* Refresh the IP packet fields. */   /  op_pk_nfd_access( packet, "fields", &dgram );       ?  /* Alter the header field size to model the mob msg size. */        :  /* Add the size of the mobility extension header into */   =  /* the packet. Modify the size of the header fields in   */   2  /* the IPv6 packet to achieve this.           */       <  ip_dgram_sup_ipv6_extension_hdr_size_add( &packet, &dgram,   9      IpC_Procotol_Mobility_Ext_Hdr, (int) ext_hdr_len );       "  /* Uninstall the event state. */   )  op_ev_state_install( OPC_NIL, OPC_NIL);          4  /* Deliver this IPv6 datagram to the IP module. */   !  op_pk_send( packet, OUT_STRM );   /  printf( "HMIPv6 MAP AD: Sending packet!\n" );   
       
          /* Set the timer interrupt */   Fop_intrpt_schedule_self(op_sim_time() + TIME_LIMIT, TIMER_INTERRUPT);    
       
   ����   
          pr_state                     
   FAIL   
                                       ����             pr_state                        �   x      p   Y   �   �          
   tr_0   
       ����          ����          
    ����   
          ����                       pr_transition              S   �     #   �  j   ]  j   �  !   �          
   tr_2   
       
   default   
       ����          
    ����   
          ����                       pr_transition               �   �      �   �   �   �          
   tr_3   
       
   CAN_SEND   
       ����          
@   ����   
          ����                       pr_transition              %   �     %   �  %   �          
   tr_4   
       ����          ����          
@   ����   
          ����                       pr_transition                �   +      m   Q   �   !          
   tr_5   
       
   DISABLED   
       ����          
    ����   
          ����                       pr_transition                        
   hmipv6_common   
ip_addr_v4   
ip_support   ipv6_dest_cache   ipv6_extension_headers_sup   ipv6_nd   ipv6_ra   mipv6_signaling_sup   	mipv6_sup   mobile_ip_support                    