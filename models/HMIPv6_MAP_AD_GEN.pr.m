MIL_3_Tfile_Hdr_ 145A 140A modeler 9 4B624B23 4B796E80 27 planet12 Student 0 0 none none 0 0 none 32EC89F4 1FC6 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                              ��g�      @   D   H      �  �  �  �    �  �  �  �           	   begsim intrpt             ����      doc file            	nd_module      endsim intrpt             ����      failure intrpts            disabled      intrpt interval         ԲI�%��}����      priority              ����      recovery intrpts            disabled      subqueue                     count    ���   
   ����   
      list   	���   
          
      super priority             ����             bool	\ap_enable;       bool	\disabled;       InetT_Address	\map_address;              #include <opnet.h>   #include <hmipv6_defs.h>   #include <hmipv6_defs.h>   #include <hmipv6_support.h>   #include <ip_rte_v4.h>   #include <ip_rte_support.h>   (#include <ipv6_extension_headers_defs.h>   '#include <ipv6_extension_headers_sup.h>   #include <ip_dgram_sup.h>   #include <ipv6_ra.h>   #include <ip_arp.h>   #include <ip_icmp_pk.h>   #include <mobile_ip_support.h>       ;extern int mobility_msg_size_in_bits[MIPV6C_MOB_MSG_COUNT];       #define TIMER_INTERRUPT 99       ,/* How often to create packets in seconds */   #define TIME_LIMIT 	1.0       a#define CAN_SEND ((op_intrpt_type() == OPC_INTRPT_SELF) && (op_intrpt_code() == TIMER_INTERRUPT))       ##define DISABLED (disabled == true)       ##define ENABLED (disabled == false)       #define OUT_STRM 0                                             Z   Z          
   init   
       
   ?   /*   ** Check AP parameters:   '**   If not an AP, destroy this module.   **   else, continue.   */   !puts(" What's up from MAP AD!" );       .Objid parentid = op_topo_parent(op_id_self());   Prohandle pro = op_pro_self();       :/* Obtain the values assigned to the various attributes	*/   PObjid macid = op_id_from_name( parentid, OPC_OBJTYPE_PROC, "wireless_lan_mac" );       4/* Get access point functionality for this module */   int ap_flag;   Objid paramid;   Objid mac_param_child;   Bop_ima_obj_attr_get( macid, "Wireless LAN Parameters", &paramid );   Cmac_param_child = op_topo_child( paramid, OPC_OBJTYPE_GENERIC, 0 );   Oop_ima_obj_attr_get( mac_param_child, "Access Point Functionality", &ap_flag );       /* Register this shizzle */       (/* Get the name of the process model. */   char modelname[40];   @op_ima_obj_attr_get( op_id_self(), "process model" ,modelname );       OmsT_Pr_Handle procHndl;   6/* Register the process in the model-wide registry. */   MprocHndl = oms_pr_process_register( parentid, op_id_self(), pro, modelname );       5/* Register the protocol attribute and the module 	*/   %/* Object ID in the registry.						*/   oms_pr_attr_set( procHndl,    .  "protocol" , OMSC_PR_STRING, "ip-ip (MIP)",    8  "module ID", OMSC_PR_OBJID , op_id_self() , OPC_NIL );           /* Get process name */   char name[100];   0op_ima_obj_hname_get( op_id_self(), name, 100 );       B/* If this isn't an access point, don't generate advertisements */   (if ( ap_flag != OPC_BOOLINT_ENABLED ) {        K	printf( "HMIPv6 MAP AD: Destroying HMIPv6 MN Advertiser in %s\n", name );    "  op_pro_destroy( op_pro_self() );     disabled = true;       } else {         disabled = false;   I	printf( "HMIPv6 MAP AD: Starting HMIPv6 MN Advertiser in %s\n", name );    J  op_intrpt_schedule_self( op_sim_time() + TIME_LIMIT, TIMER_INTERRUPT );        '  ipv6_extension_header_package_init();       %  int protoNum = IpC_Protocol_Ip_Mip;   A	Inet_Higher_Layer_Protocol_Register( "ip-ip (MIP)", &protoNum );       }           
                     
   ����   
          pr_state           �          
   idle   
                                       ����             pr_state                    
   SEND AD   
       
   ;        /* Generate one advertisement */   Packet*           packet;   OpT_Packet_Size   ext_hdr_len;   IpT_Dgram_Fields* dgram;   !Ipv6T_Mobility_Hdr_Info*  header;       /* Create the IP datagram. */   packet = ip_dgram_create();       6/* Get the size contributed by the mobility header. */   Dext_hdr_len = (OpT_Packet_Size) mobility_msg_size_in_bits[BIND_ACK];       .Objid module = op_topo_parent( op_id_self() );       //* Create IP datagram fields data structure. */   #dgram = ip_dgram_fdstruct_create();   Xdgram->src_addr = inet_support_address_from_node_id_get( module, InetC_Addr_Family_v6 );   Edgram->src_internal_addr = inet_rtab_addr_convert( dgram->src_addr );   dgram->orig_len = ext_hdr_len;   dgram->frag_len = ext_hdr_len;   dgram->ttl      = 255;       6/* The protocol field (next header in IPv6) must    */   8/* indicate that this is a mobility extension header. */   0dgram->protocol = IpC_Procotol_Mobility_Ext_Hdr;       /*    E** @NOTE!: For simplicity we use the  Mipv6C_Bind_Ref_Req header type   <** to represent a MAP Advertisement packet. The home_address   ** will hold the MAP Address   */   <header = ipv6_mobility_header_create( Mipv6C_Bind_Ref_Req );   Mheader->msg_data.bind_update.home_address = inet_address_copy( map_address );       A/* Set the mobility header information in the datagram fields. */   *ipv6_mobility_hdr_insert( dgram, header );       5/* Set the datagram fields into the IPv6 datagram. */   %ip_dgram_fields_set( packet, dgram );       #/* Refresh the IP packet fields. */   -op_pk_nfd_access( packet, "fields", &dgram );       =/* Alter the header field size to model the mob msg size. */        8/* Add the size of the mobility extension header into */   ;/* the packet. Modify the size of the header fields in   */   0/* the IPv6 packet to achieve this.           */       :ip_dgram_sup_ipv6_extension_hdr_size_add( &packet, &dgram,   7    IpC_Procotol_Mobility_Ext_Hdr, (int) ext_hdr_len );       !/* Un-install the event state. */   'op_ev_state_install( OPC_NIL, OPC_NIL);        2/* Deliver this IPv6 datagram to the IP module. */   op_pk_send( packet, OUT_STRM );   -printf( "HMIPv6 MAP AD: Sending packet!\n" );   
       
          /* Set the timer interrupt */   Fop_intrpt_schedule_self(op_sim_time() + TIME_LIMIT, TIMER_INTERRUPT);    
       
   ����   
          pr_state                     
   FAIL   
                                       ����             pr_state                        �   �      p   Y   �   �          
   tr_0   
       
   ENABLED   
       ����          
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
          ����                       pr_transition                 ^        .  5   Q   �   N      '          J   tr_6   J       J   default   J       ����          J    ����   J          ����                       pr_transition                        
   hmipv6_common   
ip_addr_v4   
ip_support   ipv6_dest_cache   ipv6_extension_headers_sup   ipv6_nd   ipv6_ra   mipv6_signaling_sup   	mipv6_sup   mobile_ip_support                    