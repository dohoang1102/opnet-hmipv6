MIL_3_Tfile_Hdr_ 145A 140A modeler 6 4B4F9C15 4B99B3EB 6 planet12 Student 0 0 none none 0 0 none 40C0D6E5 1D338 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                              Ф═gЅ      8   Ъ   В  >  B  k  Ё  љ$  ░╣  ░┴ ¤Ф ¤»      node   IP   UDP   RIP   TCP   hidden   TCP   workstation   OSPF   WLAN   RSVP   DHCP   wkstn_wless_wlan   wkstn_wless_wlan           Wireless LAN Workstation    ~   General Node Functions:       -----------------------       )The wlan_wkstn_adv node model represents    !a workstation with client-server    %applications running over TCP/IP and    %UDP/IP. The workstation supports one    (underlying Wlan connection at 1 Mbps, 2    Mbps, 5.5 Mbps, and 11 Mbps.                )This workstation requires a fixed amount    !of time to route each packet, as    'determined by the "IP Forwarding Rate"    *attribute of the node. Packets are routed    *on a first-come-first-serve basis and may    (encounter queuing at the lower protocol    &layers, depending on the transmission    "rates of the corresponding output    interfaces.               
Protocols:       
----------       $RIP, UDP, IP, TCP, IEEE 802.11, OSPF               Interconnections:       -----------------       Either of the following:       1) 1 WLAN connection at 1 Mbps,       2) 1 WLAN connection at 2 Mbps,       !3) 1 WLAN connection at 5.5 Mbps,        4) 1 WLAN connection at 11 Mbps                Attributes:       -----------       "Client Custom Application, Client    $Database Application, Client Email,    *Client Ftp, Client Remote Login, Client X    $Windows, Client Video Conferencing,    %Client Start Time:  These attributes    allow for the specification of    &application traffic generation in the    node.               *Transport Address:  This attribute allows    (for the specification of the address of    	the node.               )"IP Forwarding Rate": specifies the rate    *(in packets/second) at which the node can    "perform a routing decision for an    'arriving packet and transfer it to the    appropriate output interface.               )"IP Gateway Function": specifies whether    *the local IP node is acting as a gateway.    )Workstations should not act as gateways,    (as they only have one network interface.               *"RIP Process Mode": specifies whether the    (RIP process is silent or active. Silent    &RIP processes do not send any routing    (updates but simply receive updates. All    )RIP processes in a workstation should be    silent RIP processes.               ("TCP Connection Information": specifies    )whether diagnostic information about TCP    #connections from this node will be    'displayed at the end of the simulation.               '"TCP Maximum Segment Size": determines    'the size of segments sent by TCP. This    'value should be set to largest segment    %size that the underlying network can    carry unfragmented.               )"TCP Receive Buffer Capacity": specifies    $the size of the buffer used to hold    (received data before it is forwarded to    the application.               <<Summary>>       General Function: workstation       *Supported Protocols: UDP, IP, IEEE802.11,    RIP, TCP, OSPF       Port Interface Description:       '  1 WLAN connection at 1,2,5.5,11 Mbps        E      1AD-HOC Routing ParametersAD-HOC Routing Protocol      $ip.manet_mgr.AD-HOC Routing Protocol                                                                  )AD-HOC Routing ParametersAODV Parameters      ip.manet_mgr.AODV Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       ARP Parameters      arp.ARP Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       #Application: ACE Tier Configuration      "application.ACE Tier Configuration                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       $Application: Destination Preferences      #application.Destination Preferences                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       'Application: Multicasting Specification      &application.Multicasting Specification                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       Application: RSVP Parameters      'application.RSVP Application Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       Application: Segment Size      application.Segment Size                                                                                          Application: Source Preferences      application.Source Preferences                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       Application: Supported Profiles      application.Supported Profiles                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       Application: Supported Services      application.Services                                                        count                                0                                     0                 1                2                3                   Supported applications on    server.Applications are   defined in 'Application    Configuration' object.ЦZ             list   	          	                                                    Name                    љ      None                             All Services      All Services      None      None         Services enabled in server.       !These services are configured in    !application configuration object.       "All Services" enables all    services defined in all    "application configuration objects    present in network.                                           gna_active_attrib_handler   (gna_supported_services_get_click_handler            ЦZ             Description                             	Supported                             Not Supported               count          
          
      list   	      
          
      	Supported               count          
          
      list   	      
            Service Status          
       Enabled   
   
      9   Parameters to start and    setup Custom Application    service.                                                                                                                                                                                                                           count                                                                            ЦZ             list   	          	                                                    Service Status                              Disabled                                     Disabled                 Enabled                   Specifies whether this    service is supported on this    server. ЦZ             Processing Speed                	bytes/sec      A.ёђ       	1,000,000                                             10,000   @├ѕ               100,000   @Эj               	1,000,000   A.ёђ                 The processing time required    is based on the response    size for FTP Get, Email    Recv, Database Query    application types and on the    request sizes for the rest   of the applications.    ЦZ             Overhead                sec/request      >░кэахьЇ   1E-06                                             1E-06   >░кэахьЇ          1E-03   ?PbMмыЕЧ             Overhead involved in    processing an application    	request.                                                             ЦZ             Selection Weight                       @$         10                                             10   @$                20   @4                   The popularity of this    server when it comes to    choose between two or more    servers running the    supporting the same service.    ЦZ             Type of Service                      0          As Requested by Client                                  	   As Requested by Client                 Best Effort (0)                 Background (1)                Standard (2)                Excellent Effort (3)                Streaming Multimedia (4)                Interactive Multimedia (5)                Interractive Voice (6)                Unspecified (7)                #   Type of Service (ToS)    assigned to packets sent    from this server.                It represents an application    attribute which allows    packests to be processed    faster in ip queues.                It is an integer between        0 - 7, 7 being the highest    
priority.                Server has an option to    respond to a client's    request with packets having    the same type of service as    packets sent by client    (value: "As Requested by    Client") or it can define    its own type of service for    outgoing packets.        In the latter case client's    packets will use the ToS    specified at the client and    server's responses will    contain the server's ToS. ЦZ          ЦZ          ЦZ          ЦZ                       -Application: Transport Protocol Specification      application.Transport Protocol                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       #H323Assigned Administrative Domain      3application.h323_mgr.Assigned Administrative Domain                                                                  H323Assigned Gatekeeper      (application.h323_mgr.Assigned Gatekeeper                                                                  	BGP Based      ip.BGP L2VPN/VPLS Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       CPU Background Utilization      CPU.background utilization                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       CPU Resource Parameters      CPU.Resource Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                        H323Call Signaling Mode      (application.h323_mgr.Call Signaling Mode                                                                               Client Address      tpal.Address                                                                  ;VPN.Network Based.L2VPN/VPLS InstancesCross Connect Groups      ip.Cross Connect Groups                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       @VPN.Network Based.L2VPN/VPLS InstancesCross-Connects Parameters      %ip.mpls_mgr.Cross-Connects Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       DHCPv6 Client Parameters      dhcp.DHCPv6 Client Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       DHCPv6 Server Parameters      dhcp.DHCPv6 Server Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       (AD-HOC Routing ParametersDSR Parameters      ip.manet_mgr.DSR Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       DVMRP Parameters      ip.DVMRP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       (AD-HOC Routing ParametersGRP Parameters      ip.manet_mgr.GRP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       H323H323 Device Role      %application.h323_mgr.H323 Device Role                                                                  IP MulticastingIGMP Parameters      ip.ip_igmp_host.IGMP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       ReportsIP Forwarding Table      ip.IP Forwarding Table                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       IP Gateway Function      
ip.gateway                                                                              IP Host Parameters      ip.ip host parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       IP Multicast Group-to-RP Table      !ip.IP Multicast Group-to-RP Table                                                                              IPIP NAT Parameters      ip.NAT Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       IP Processing Information      ip.ip processing information                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       IP QoS Parameters      ip.ip qos parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       IP Slot Information      ip.ip slot information                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       IPv6 Parameters      ip.ipv6 parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       $L2TPL2TP Control Channel Parameters      "ip.L2TP Control Channel Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                        LACP System Priority      ip.LACP System Priority                    ╚h                                                        LAN Supported Profiles      "application.LAN Supported Profiles                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       	LDP Based      ip.LDP L2VPN/VPLS Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       MSDP Parameters      ip.MSDP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       Mainframe Parameters      $CPU.mframe_base.Mainframe Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       )ReportsMainframe Workload Activity Table      1CPU.mframe_base.Mainframe Workload Activity Table                                                                               H323Max Number of Calls      (application.h323_mgr.Max Number of Calls                                                                               3IP.Mobile IP Host ParametersMobile IPv4 Parameters      #mobile_ip.Mobile IP Host Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       3IP.Mobile IP Host ParametersMobile IPv6 Parameters      %mobile_ip.Mobile IPv6 Host Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       NHRPNHRP Parameters      ip.nhrp.NHRP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       )AD-HOC Routing ParametersOLSR Parameters      manet_rte_mgr.OLSR Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       PIM Parameters      ip.PIM Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       %PIM-DVMRP Interoperability Parameters      (ip.PIM-DVMRP Interoperability Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       PIM-SM Routing Table      ip.PIM-SM Routing Table                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       9VPN.Network Based.L2VPN/VPLS InstancesPseudowire Classes      ip.Pseudowire Classes                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       RSVP Protocol Parameters      rsvp.RSVP Protocol Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       H323Reporting End Time      'application.h323_mgr.Reporting End Time                                                                                          H323Reporting Start Time      )application.h323_mgr.Reporting Start Time                                                                                          SIP Proxy Server Parameters      3application.sip_UAS_mgr.SIP Proxy Server Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       SIP UAC Parameters      *application.sip_UAC_mgr.SIP UAC Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       Security Parameters      ip.ip security parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       %Server: Advanced Server Configuration      !CPU.Advanced Server Configuration                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                        Server: Modeling Method      CPU.Compatibility Mode                                                                               TCP Parameters      tcp.TCP Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       .AD-HOC Routing ParametersTORA/IMEP Parameters      !ip.manet_mgr.TORA/IMEP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       VRF Instances      ip.VRF Instances                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       ReportsVRF Table      ip.VRF Table                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                        Wireless LAN MAC Address      wireless_lan_mac.Address                                                                               Wireless LAN Parameters      (wireless_lan_mac.Wireless LAN Parameters                                                        count                                                                        ЦZ             list   	          	                                                  ЦZ                       ip.IGMP Parameters      ip.IGMP Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                       DIP.Mobile IP Host Parametersmobile_ip.Mobile IPv6 Router Parameters      'mobile_ip.Mobile IPv6 Router Parameters                                                        count                                                                       ЦZ             list   	          	                                                  ЦZ                    S   AD-HOC Routing Protocol            None      AODV Parameters               Default      ARP Parameters         
      Default   
   #Application: ACE Tier Configuration         
      Unspecified   
   $Application: Destination Preferences         
      None   
   'Application: Multicasting Specification         
      None   
   Application: RSVP Parameters         
      None   
   Application: Segment Size         
           64,000   
   Application: Source Preferences         
      None   
   Application: Supported Profiles         
      None   
   Application: Supported Services         
      None   
   -Application: Transport Protocol Specification         
      Default   
   Assigned Administrative Domain            	opnet.com      Assigned Gatekeeper            Auto Assigned      	BGP Based               None      CPU Background Utilization         
      None   
   CPU Resource Parameters         
            count          
          
      list   	      
            Number of Resources           
       1   
      Task Contention Mode           
       Contention Already Modeled   
   
   
   Call Signaling Mode                Direct Endpoint Call Signaling      Client Address         
   Auto Assigned   
   Cross Connect Groups               None      Cross-Connects Parameters         
      Not Configured   
   DHCPv6 Client Parameters         
      Disabled   
   DHCPv6 Server Parameters         
      Disabled   
   DSR Parameters               Default      DVMRP Parameters               Not Configured      GRP Parameters               Default      H323 Device Role            Terminal      IGMP Parameters               Default      IP Forwarding Table         
      Do Not Export   
   IP Gateway Function         
       Disabled   
   IP Host Parameters         
            count          
          
      list   	      
            Interface Information          
            count          
          
      list   	      
            MTU           
       WLAN   
      IPv6 Parameters          
      None   
      Layer 2 Mappings          
      None   
   
   
      Static Routing Table          
      None   
   
   
   IP Multicast Group-to-RP Table         
       Do Not Export   
   IP NAT Parameters               Not Configured      IP Processing Information         
            count          
          
      list   	      
            Datagram Forwarding Rate          
           Infinity   
   
   
   IP QoS Parameters         
      None   
   IP Slot Information         
      NOT USED   
   IPv6 Parameters               None      L2TP Control Channel Parameters               None      LACP System Priority          
       32768   
   LAN Supported Profiles         
      None   
   	LDP Based               None      MSDP Parameters               Not Configured      Mainframe Parameters         
      Not Configured   
   !Mainframe Workload Activity Table         
       Do Not Export   
   Max Number of Calls                 	Unlimited      Mobile IPv4 Parameters               Disabled      Mobile IPv6 Parameters               Not Configured      NHRP Parameters               None      OLSR Parameters               Default      PIM Parameters               Not Configured      %PIM-DVMRP Interoperability Parameters               Not Configured      PIM-SM Routing Table               Do Not Export      Pseudowire Classes               None      RSVP Protocol Parameters         
            count          
          
      list   	      
            Interface Information          
            count          
          
      list   	      
            Name          
   IF0   
   
      name          
   udp   
      process model          
   
rip_udp_v3   
      	icon name          
   	processor   
   
   
   
   Reporting End Time         └          Use Global Setting      Reporting Start Time         └          Use Global Setting      SIP Proxy Server Parameters                     count          
          
      list   	      
          
      SIP UAC Parameters                     count          
          
      list   	      
          
      Security Parameters         
      None   
   %Server: Advanced Server Configuration         
      GSun Ultra 10 333MHz:: 1 CPU, 1 Core(s) Per CPU, 333MHz, Solaris, System   
   Server: Modeling Method                 
Simple CPU      TCP Parameters         
      Default   
   
TIM source         
   ip   
   TORA/IMEP Parameters               Default      VRF Instances               None      	VRF Table         
      Do Not Export   
   Wireless LAN MAC Address          
       Auto Assigned   
   Wireless LAN Parameters         
      Default   
   altitude         
               
   altitude modeling            relative to subnet-platform      	condition         
          
   financial cost            0.00      ip.IGMP Parameters               Not Configured      ip.ip multicast information         
      Default   
   ip.ip router parameters         
            count          
          
      list   	      
            Interface Information          
            count          
          
      list   	      
            QoS Information          
            count          
          
      list   	      
          
   
   
   
      Loopback Interfaces          
            count          
          
      list   	      
            Name          
   Loopback   
   
   
      Static Routing Table          
            count          
          
      list   	      
          
   
   
   
   ip.manet_mgr.MANET Gateway                Disabled      ip.mpls_mgr.MPLS Parameters                     count          
          
      list   	      
          
      %mobile_ip.Mobile IP Router Parameters               Disabled      'mobile_ip.Mobile IPv6 Router Parameters               Not Configured      phase         
               
   priority          
           
   role                   user id          
           
              l   џ          
   udp   
       
   
rip_udp_v3   
          	processor                       ╚   ╚          
   ip_encap   
       
   ip_encap_v4   
          	processor                       ╚  $          
   arp   
       
   	ip_arp_v4   
          	processor                       ╚   џ          
   tcp   
       
   tcp_manager_v3   
          	processor                       ╚   l          
   tpal   
       
   tpal_v3   
          	processor                    
   ╚   >          
   application   
       
   gna_clsvr_mgr   
          	processor                       ╚  R          
   wireless_lan_mac   
       
   wlan_dispatch   
          	processor                      $   ╚          
   rsvp   
       
   rsvp   
          	processor                       ╚   Ш          
   ip   
       
   ip_dispatch   
          	processor                    J  $   >          
   CPU   
       
   
server_mgr   
          	processor                    L   l   >          
   manet_rte_mgr   
       
   manet_rte_mgr   
          	processor                    N   >   џ          
   	mobile_ip   
       
   mobile_ip_reg_mgr   
          	processor                    P      N          
   dhcp   
       
   dhcp_mgr   
          	processor                	   R   џ  ђ          
   wlan_port_rx_0_0   
       
            count          
          
      list   	      
            	data rate         
A.ёђ           
      packet formats         
   !unformatted,wlan_control,wlan_mac   
      	bandwidth         
@Н|            
      min frequency         
@б┬            
   
   
       
   dpsk   
       ?­                                          
   NONE   
       
   
wlan_power   
          dra_bkgnoise          
   wlan_inoise   
          dra_snr          
   wlan_ber   
       
   
wlan_error   
       
   wlan_ecc   
          ra_rx                       nd_radio_receiver         V   Ш  ђ          
   wlan_port_tx_0_0   
       
            count          
          
      list   	      
            	data rate         
A.ёђ           
      packet formats         
   wlan_control,wlan_mac   
      	bandwidth         
@Н|            
      min frequency         
@б┬            
      power         
?tzрG«{       
   
   
       
   dpsk   
       
   wlan_rxgroup   
       
   
wlan_txdel   
       
   dra_closure_range   
       
   wlan_chanmatch   
       
   NONE   
       
   wlan_propdel   
          ra_tx                       nd_radio_transmitter          X   >   Ш          
   hmipv6_managment   
       
   HMIPv6_MN_NEW   
          	processor                                     Й   ╔   g   ╔   g   а   
       
   	strm_15_2   
       
   src stream [2]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream                       m   д   m   к   ╗   к   
       
   	strm_16_2   
       
   src stream [0]   
       
   dest stream [2]   
                                              
@U         
                                        nd_packet_stream                      н   л   ж   л   ж   ы   н   ы   
       
   strm_8   
       
   src stream [0]   
       
   dest stream [0]   
                                              
@U         
                                        nd_packet_stream                      ╗   Ы   Д   Ы   Д   л   ╗   л   
       
   strm_9   
       
   src stream [0]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream             
         н   <   Т   <   Т   i   н   j   
       
   strm_190   
       
   src stream [0]   
       
   dest stream [1]   
                                              
@U         
                                        nd_packet_stream                
      ╗   d   Е   d   Е   >   ╗   =   
       
   strm_200   
       
   src stream [1]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream                      н   r   У   r   У   ћ   н   ћ   
       
   strm_221   
       
   src stream [0]   
       
   dest stream [1]   
                                              
@U         
                                        nd_packet_stream                      ╗   ќ   Е   ќ   Е   u   ╗   u   
       
   strm_222   
       
   src stream [1]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream          	            н   А   У   А   У   ┴   н   ┴   
       
   	strm_4104   
       
   src stream [0]   
       
   dest stream [1]   
                                              
@U         
                                        nd_packet_stream          
            ╗   ┴   е   ┴   е   а   ╗   а   
       
   	strm_4105   
       
   src stream [1]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream                       ╗   o   p   o   p   Ї   
       
   	strm_4107   
       
   src stream [3]   
       
   dest stream [2]   
                                              
@U         
                                        nd_packet_stream                       j   Ї   j   h   ╗   h   
       
   	strm_4108   
       
   src stream [2]   
       
   dest stream [3]   
                                              
@          
                                        nd_packet_stream                V      Л  P   Э  P   Э  {   
       
   tx   
       
   src stream [0]   
       
   dest stream [0]   
                                              
@U         
                                        nd_packet_stream             R         џ  s   Ў  p   Ў  S   Й  S   
       
   rx   
       
   src stream [0]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream                      ╗  G   е  G   е  +   ╗  +   
       
   	strm_4109   
       
   src stream [1]   
       
   dest stream [4]   
                                              
@          
                                        nd_packet_stream                      н  ,   Т  ,   Т  G   н  G   
       
   	strm_4110   
       
   src stream [4]   
       
   dest stream [1]   
                                              
@U         
                                        nd_packet_stream                      н   ╠  '   ╠  '   н   
       
   ip_encap_to_rsvp   
       
   src stream [6]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream                     "   н  "   к   н   к   
       
   rsvp_to_ip_encap   
       
   src stream [0]   
       
   dest stream [6]   
                                                                                                nd_packet_stream                 L      g   Ј   g   2   
       
   	strm_4111   
       
   src stream [1]   
       
   dest stream [0]   
                                              
@­.       
                                        nd_packet_stream             L          d   H   d   Ќ   
       
   	strm_4112   
       
   src stream [0]   
       
   dest stream [1]   
                                                                                                nd_packet_stream                 N      b   Ў   ?   Ў   ?   Ў   
       
   	strm_4116   
       
   src stream [3]   
       
   dest stream [0]   
                                              
@э8       
                                        nd_packet_stream             N          :   Б   :   Ю   l   Ю   
       
   	strm_4115   
       
   src stream [0]   
       
   dest stream [3]   
                                              
@щ       
                                        nd_packet_stream             P             H   i   Ј   
       
   dhcp_to_udp   
       
   src stream [0]   
       
   dest stream [4]   
                                              
@ ф        
                                        nd_packet_stream                 P         J   o   Љ   
       
   udp_to_dhcp   
       
   src stream [4]   
       
   dest stream [0]   
                                              
@          
                                        nd_packet_stream            R         ъ  x   ┬  T          
   rxstat   
       
   channel [0]   
       
   !radio receiver.received power (W)   
       
   
instat [0]   
                                              
           
       
           
                                           
               
       
=V<ї╚%јC       
       
@ф         
                                        nd_statistic_wire            V         №  x   ╦  T          
   txstat   
       
   channel [0]   
       
   radio transmitter.busy   
       
   
instat [1]   
                                              
           
                                                            н▓IГ%ћ├}              н▓IГ%ћ├}              
@ф         
                                        nd_statistic_wire          ,            л   Ч   §   ь   Щ  <   Л     
       
   	strm_4121   
       
   src stream [1]   
       
   dest stream [0]   
                                                                                                nd_packet_stream          .            Й     }  ?   ~   Ь   ╝   Э   
       
   	strm_4122   
       
   src stream [0]   
       
   dest stream [1]   
                                                                                                nd_packet_stream          0      X      ¤   ┐   I   Ь   
       
   	strm_4123   
       
   src stream [3]   
       
   dest stream [0]   
                                              J@          J                                        nd_packet_stream          2   X         9   ч   ╗   ╦   
       
   	strm_4124   
       
   src stream [0]   
       
   dest stream [3]   
                                                                                                nd_packet_stream      \   3  В   +ip.Broadcast Traffic Received (packets/sec)   (Broadcast Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   'ip.Broadcast Traffic Sent (packets/sec)   $Broadcast Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP   +ip.Multicast Traffic Received (packets/sec)   (Multicast Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   'ip.Multicast Traffic Sent (packets/sec)   $Multicast Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP    ip.Traffic Dropped (packets/sec)   Traffic Dropped (packets/sec)           IP   bucket/default total/sum_time   linear   IP   !ip.Traffic Received (packets/sec)   Traffic Received (packets/sec)           IP   bucket/default total/sum_time   linear   IP   ip.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           IP   bucket/default total/sum_time   linear   IP   "tcp.Congestion Window Size (bytes)   Congestion Window Size (bytes)           TCP Connection   sample/default total   linear   TCP Connection   tcp.Delay (sec)   Delay (sec)           TCP Connection    bucket/default total/sample mean   linear   TCP Connection   tcp.Load (bytes)   Load (bytes)           TCP Connection   bucket/default total/sum   linear   TCP Connection   tcp.Load (bytes/sec)   Load (bytes/sec)           TCP Connection   bucket/default total/sum_time   linear   TCP Connection   tcp.Load (packets)   Load (packets)           TCP Connection   bucket/default total/sum   linear   TCP Connection   tcp.Load (packets/sec)   Load (packets/sec)           TCP Connection   bucket/default total/sum_time   linear   TCP Connection   tcp.Received Segment Ack Number   Received Segment Ack Number           TCP Connection   sample/default total   linear   TCP Connection   $tcp.Received Segment Sequence Number    Received Segment Sequence Number           TCP Connection   sample/default total   linear   TCP Connection   &tcp.Remote Receive Window Size (bytes)   "Remote Receive Window Size (bytes)           TCP Connection   sample/default total   linear   TCP Connection   $tcp.Retransmission Timeout (seconds)    Retransmission Timeout (seconds)           TCP Connection   sample/default total   linear   TCP Connection   !tcp.Segment Round Trip Time (sec)   Segment Round Trip Time (sec)           TCP Connection    bucket/default total/sample mean   linear   TCP Connection   %tcp.Segment Round Trip Time Deviation   !Segment Round Trip Time Deviation           TCP Connection    bucket/default total/sample mean   linear   TCP Connection   tcp.Sent Segment Ack Number   Sent Segment Ack Number           TCP Connection   sample/default total   linear   TCP Connection    tcp.Sent Segment Sequence Number   Sent Segment Sequence Number           TCP Connection   sample/default total   linear   TCP Connection   tcp.Traffic Received (bytes)   Traffic Received (bytes)           TCP Connection   bucket/default total/sum   linear   TCP Connection    tcp.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           TCP Connection   bucket/default total/sum_time   linear   TCP Connection   tcp.Traffic Received (packets)   Traffic Received (packets)           TCP Connection   bucket/default total/sum   linear   TCP Connection   "tcp.Traffic Received (packets/sec)   Traffic Received (packets/sec)           TCP Connection   bucket/default total/sum_time   linear   TCP Connection   tcp.Connection Aborts   Connection Aborts           TCP   bucket/default total/sum   linear   TCP   tcp.Delay (sec)   Delay (sec)           TCP    bucket/default total/sample mean   linear   TCP   tcp.Load (bytes)   Load (bytes)           TCP   bucket/default total/sum   linear   TCP   tcp.Load (bytes/sec)   Load (bytes/sec)           TCP   bucket/default total/sum_time   linear   TCP   tcp.Load (packets)   Load (packets)           TCP   bucket/default total/sum   linear   TCP   tcp.Load (packets/sec)   Load (packets/sec)           TCP   bucket/default total/sum_time   linear   TCP   tcp.Traffic Received (bytes)   Traffic Received (bytes)           TCP   bucket/default total/sum   linear   TCP    tcp.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           TCP   bucket/default total/sum_time   linear   TCP   tcp.Traffic Received (packets)   Traffic Received (packets)           TCP   bucket/default total/sum   linear   TCP   "tcp.Traffic Received (packets/sec)   Traffic Received (packets/sec)           TCP   bucket/default total/sum_time   linear   TCP   ip.Processing Delay (sec)   Processing Delay (sec)           IP    bucket/default total/sample mean   linear   IP   "ip.Ping Replies Received (packets)   Ping Replies Received (packets)           IP   bucket/default total/count   square-wave   IP   ip.Ping Requests Sent (packets)   Ping Requests Sent (packets)           IP   bucket/default total/count   square-wave   IP   ip.Ping Response Time (sec)   Ping Response Time (sec)           IP    bucket/default total/sample mean   discrete   IP   %ip.Background Traffic Delay --> (sec)   "Background Traffic Delay --> (sec)           IP   normal   linear   IP   %ip.Background Traffic Delay <-- (sec)   "Background Traffic Delay <-- (sec)           IP   normal   linear   IP    wireless_lan_mac.Load (bits/sec)   Load (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   &wireless_lan_mac.Throughput (bits/sec)   Throughput (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   )wireless_lan_mac.Media Access Delay (sec)   Media Access Delay (sec)           Wireless Lan    bucket/default total/sample mean   linear   Wireless Lan   rsvp.Number of Path States   Number of Path States           RSVP   bucket/default total/sum_time   sample_hold   RSVP   rsvp.Number of Resv States   Number of Resv States           RSVP   bucket/default total/sum_time   sample_hold   RSVP   rsvp.Number of Blockade States   Number of Blockade States           RSVP   bucket/default total/sum_time   sample_hold   RSVP   "rsvp.Number of Successful Requests   Number of Successful Requests           RSVP   bucket/default total/sum_time   linear   RSVP    rsvp.Number of Rejected Requests   Number of Rejected Requests           RSVP   bucket/default total/sum_time   linear   RSVP   )rsvp.Path Messages Received (packets/sec)   $Path Messages Received (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   %rsvp.Path Messages Sent (packets/sec)    Path Messages Sent (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   )rsvp.Resv Messages Received (packets/sec)   $Resv Messages Received (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   %rsvp.Resv Messages Sent (packets/sec)    Resv Messages Sent (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   .rsvp.Resv Conf Messages Received (packets/sec)   )Resv Conf Messages Received (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   *rsvp.Resv Conf Messages Sent (packets/sec)   %Resv Conf Messages Sent (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   .rsvp.Total RSVP Traffic Received (packets/sec)   )Total RSVP Traffic Received (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   *rsvp.Total RSVP Traffic Sent (packets/sec)   %Total RSVP Traffic Sent (packets/sec)           RSVP   bucket/default total/sum_time   linear   RSVP   application.Response Time (sec)   Response Time (sec)           Client DB Entry    bucket/default total/sample mean   discrete   Client DB Entry   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Client DB Entry   bucket/default total/sum_time   linear   Client DB Entry   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Client DB Entry   bucket/default total/sum_time   linear   Client DB Entry   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client DB Entry   bucket/default total/sum_time   linear   Client DB Entry   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client DB Entry   bucket/default total/sum_time   linear   Client DB Entry   application.Response Time (sec)   Response Time (sec)           Client DB Query    bucket/default total/sample mean   discrete   Client DB Query   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Client DB Query   bucket/default total/sum_time   linear   Client DB Query   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Client DB Query   bucket/default total/sum_time   linear   Client DB Query   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client DB Query   bucket/default total/sum_time   linear   Client DB Query   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client DB Query   bucket/default total/sum_time   linear   Client DB Query   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           	Client DB   bucket/default total/sum_time   linear   	Client DB   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           	Client DB   bucket/default total/sum_time   linear   	Client DB   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           	Client DB   bucket/default total/sum_time   linear   	Client DB   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           	Client DB   bucket/default total/sum_time   linear   	Client DB   (application.Download Response Time (sec)   Download Response Time (sec)           Client Email    bucket/default total/sample mean   discrete   Client Email   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Client Email   bucket/default total/sum_time   linear   Client Email   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client Email   bucket/default total/sum_time   linear   Client Email   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Client Email   bucket/default total/sum_time   linear   Client Email   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client Email   bucket/default total/sum_time   linear   Client Email   &application.Download File Size (bytes)   Download File Size (bytes)           
Client Ftp    bucket/default total/sample mean   linear   
Client Ftp   (application.Download Response Time (sec)   Download Response Time (sec)           
Client Ftp    bucket/default total/sample mean   discrete   
Client Ftp   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           
Client Ftp   bucket/default total/sum_time   linear   
Client Ftp   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           
Client Ftp   bucket/default total/sum_time   linear   
Client Ftp   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           
Client Ftp   bucket/default total/sum_time   linear   
Client Ftp   $application.Upload File Size (bytes)   Upload File Size (bytes)           
Client Ftp    bucket/default total/sample mean   linear   
Client Ftp   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           
Client Ftp   bucket/default total/sum_time   linear   
Client Ftp   &application.Upload Response Time (sec)   Upload Response Time (sec)           
Client Ftp    bucket/default total/sample mean   discrete   
Client Ftp   *application.Object Response Time (seconds)   Object Response Time (seconds)           Client Http    bucket/default total/sample mean   discrete   Client Http   (application.Page Response Time (seconds)   Page Response Time (seconds)           Client Http    bucket/default total/sample mean   linear   Client Http   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Client Http   bucket/default total/sum_time   linear   Client Http   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Client Http   bucket/default total/sum_time   linear   Client Http   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client Http   bucket/default total/sum_time   linear   Client Http   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client Http   bucket/default total/sum_time   linear   Client Http   application.File Size (bytes)   File Size (bytes)           Client Print    bucket/default total/sample mean   linear   Client Print   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client Print   bucket/default total/sum_time   linear   Client Print   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client Print   bucket/default total/sum_time   linear   Client Print   application.Response Time (sec)   Response Time (sec)           Client Remote Login    bucket/default total/sample mean   discrete   Client Remote Login   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Client Remote Login   bucket/default total/sum_time   linear   Client Remote Login   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Client Remote Login   bucket/default total/sum_time   linear   Client Remote Login   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Client Remote Login   bucket/default total/sum_time   linear   Client Remote Login   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Client Remote Login   bucket/default total/sum_time   linear   Client Remote Login   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Video Calling Party    bucket/default total/sample mean   discrete   Video Calling Party   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Video Calling Party   bucket/default total/sum_time   linear   Video Calling Party   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Video Calling Party   bucket/default total/sum_time   linear   Video Calling Party   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Video Calling Party   bucket/default total/sum_time   linear   Video Calling Party   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Video Calling Party   bucket/default total/sum_time   linear   Video Calling Party   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Video Conferencing    bucket/default total/sample mean   discrete   Video Conferencing   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Video Conferencing   bucket/default total/sum_time   linear   Video Conferencing   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Video Conferencing   bucket/default total/sum_time   linear   Video Conferencing   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Video Conferencing   bucket/default total/sum_time   linear   Video Conferencing   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Video Conferencing   bucket/default total/sum_time   linear   Video Conferencing   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Voice Application    bucket/default total/sample mean   discrete   Voice Application   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Voice Application   bucket/default total/sum_time   linear   Voice Application   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Voice Application   bucket/default total/sum_time   linear   Voice Application   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Voice Application   bucket/default total/sum_time   linear   Voice Application   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Voice Application   bucket/default total/sum_time   linear   Voice Application   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Voice Calling Party    bucket/default total/sample mean   discrete   Voice Calling Party   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Voice Calling Party   bucket/default total/sum_time   linear   Voice Calling Party   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Voice Calling Party   bucket/default total/sum_time   linear   Voice Calling Party   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Voice Calling Party   bucket/default total/sum_time   linear   Voice Calling Party   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Voice Calling Party   bucket/default total/sum_time   linear   Voice Calling Party   $application.Transaction Size (bytes)   Transaction Size (bytes)           Client DB Entry    bucket/default total/sample mean   linear   Client DB Entry   $application.Transaction Size (bytes)   Transaction Size (bytes)           Client DB Query    bucket/default total/sample mean   linear   Client DB Query   application.Downloaded Objects   Downloaded Objects           Client Http   bucket/default total/count   linear   Client Http   application.Downloaded Pages   Downloaded Pages           Client Http   bucket/default total/count   linear   Client Http   &application.User Cancelled Connections   User Cancelled Connections           Client Http   bucket/default total/count   linear   Client Http   wireless_lan_mac.Delay (sec)   Delay (sec)           Wireless Lan    bucket/default total/sample mean   linear   Wireless Lan   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Video Called Party   bucket/default total/sum_time   linear   Video Called Party   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Video Called Party    bucket/default total/sample mean   discrete   Video Called Party   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Video Called Party   bucket/default total/sum_time   linear   Video Called Party   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Video Called Party   bucket/default total/sum_time   linear   Video Called Party   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Video Called Party   bucket/default total/sum_time   linear   Video Called Party   "application.Packet Delay Variation   Packet Delay Variation           Voice Application   sample/default total   discrete   Voice Application   "application.Packet Delay Variation   Packet Delay Variation           Voice Called Party   sample/default total   discrete   Voice Called Party   )application.Packet End-to-End Delay (sec)   Packet End-to-End Delay (sec)           Voice Called Party    bucket/default total/sample mean   discrete   Voice Called Party   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Voice Called Party   bucket/default total/sum_time   linear   Voice Called Party   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Voice Called Party   bucket/default total/sum_time   linear   Voice Called Party   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Voice Called Party   bucket/default total/sum_time   linear   Voice Called Party   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Voice Called Party   bucket/default total/sum_time   linear   Voice Called Party   "application.Packet Delay Variation   Packet Delay Variation           Voice Calling Party   sample/default total   discrete   Voice Calling Party   &ip.Forwarding Memory Free Size (bytes)   #Forwarding Memory Free Size (bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   ip.Forwarding Memory Overflows   Forwarding Memory Overflows           IP Processor   sample/default total   linear   IP Processor   'ip.Forwarding Memory Queue Size (bytes)   $Forwarding Memory Queue Size (bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   0ip.Forwarding Memory Queue Size (incoming bytes)   -Forwarding Memory Queue Size (incoming bytes)           IP Processor   !bucket/default total/time average   linear   IP Processor   2ip.Forwarding Memory Queue Size (incoming packets)   /Forwarding Memory Queue Size (incoming packets)           IP Processor   !bucket/default total/time average   linear   IP Processor   )ip.Forwarding Memory Queue Size (packets)   &Forwarding Memory Queue Size (packets)           IP Processor   !bucket/default total/time average   linear   IP Processor   "ip.Forwarding Memory Queuing Delay   Forwarding Memory Queuing Delay           IP Processor    bucket/default total/sample mean   discrete   IP Processor    udp.Traffic Received (Bytes/Sec)   Traffic Received (Bytes/Sec)           UDP   bucket/default total/sum_time   linear   UDP   "udp.Traffic Received (Packets/Sec)   Traffic Received (Packets/Sec)           UDP   bucket/default total/sum_time   linear   UDP   udp.Traffic Sent (Bytes/Sec)   Traffic Sent (Bytes/Sec)           UDP   bucket/default total/sum_time   linear   UDP   udp.Traffic Sent (Packets/Sec)   Traffic Sent (Packets/Sec)           UDP   bucket/default total/sum_time   linear   UDP   tcp.Flight Size (bytes)   Flight Size (bytes)           TCP Connection   sample/default total   square-wave   TCP Connection   "tcp.Selectively ACKed Data (bytes)   Selectively ACKed Data (bytes)           TCP Connection   bucket/default total/max value   square-wave   TCP Connection   tcp.Send Delay (CWND) (sec)   Send Delay (CWND) (sec)           TCP Connection   bucket/default total/max value   linear   TCP Connection   tcp.Send Delay (Nagle's) (sec)   Send Delay (Nagle's) (sec)           TCP Connection   bucket/default total/max value   linear   TCP Connection   tcp.Send Delay (RCV-WND) (sec)   Send Delay (RCV-WND) (sec)           TCP Connection   bucket/default total/max value   linear   TCP Connection   CPU.Utilization (%)   Utilization (%)           CPU   !bucket/default total/time average   linear   resource    ip.Queuing Delay Deviation (sec)   Queue Delay Variation (sec)           IP Interface   sample/default total/   linear   IP Interface   &ip.Background Traffic Flow Delay (sec)   #Background Traffic Flow Delay (sec)           IP    bucket/default total/sample mean   linear   IP   &application.Upload Response Time (sec)   Upload Response Time (sec)           Client Email    bucket/default total/sample mean   discrete   Client Email   "application.Packet Delay Variation   Packet Delay Variation           Video Calling Party   sample/default total   discrete   Video Calling Party   "application.Packet Delay Variation   Packet Delay Variation           Video Called Party   sample/default total   discrete   Video Called Party   "application.Packet Delay Variation   Packet Delay Variation           Video Conferencing   sample/default total   discrete   Video Conferencing   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           ACE   bucket/default total/sum_time   linear   ACE   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           ACE   bucket/default total/sum_time   linear   ACE   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           ACE   bucket/default total/sum_time   linear   ACE   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           ACE   bucket/default total/sum_time   linear   ACE   ip.Buffer Usage (bytes)   Buffer Usage (bytes)           IP Interface   !bucket/default total/time average   linear   IP Interface   ip.Buffer Usage (packets)   Buffer Usage (packets)           IP Interface   !bucket/default total/time average   linear   IP Interface   *ip.CAR Incoming Traffic Dropped (bits/sec)   'CAR Incoming Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   -ip.CAR Incoming Traffic Dropped (packets/sec)   *CAR Incoming Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   *ip.CAR Outgoing Traffic Dropped (bits/sec)   'CAR Outgoing Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   -ip.CAR Outgoing Traffic Dropped (packets/sec)   *CAR Outgoing Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Queuing Delay   Queuing Delay           IP Interface    bucket/default total/sample mean   linear   IP Interface   ip.RED Average Queue Size   RED Average Queue Size           IP Interface   !bucket/default total/time average   linear   IP Interface   ip.RSVP Allocated Bandwidth   RSVP Allocated Bandwidth           IP Interface   normal   sample-hold   IP Interface   ip.RSVP Allocated Buffer   RSVP Allocated Buffer           IP Interface   normal   sample-hold   IP Interface   ip.Traffic Dropped (bits/sec)   Traffic Dropped (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface    ip.Traffic Dropped (packets/sec)   Traffic Dropped (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Received (bits/sec)   Traffic Received (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   !ip.Traffic Received (packets/sec)   Traffic Received (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Sent (bits/sec)   Traffic Sent (bits/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   ip.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           IP Interface   bucket/default total/sum_time   linear   IP Interface   )CPU.CPU Job Queue Length by CPU Partition   %CPU Job Queue Length by CPU Partition           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.CPU Job Queue Length by Job   CPU Job Queue Length by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   (CPU.CPU Partition Utilization (%) by Job   $CPU Partition Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Segment Size by Job   CPU Segment Size by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.CPU Service Time by Job   CPU Service Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.CPU Total Utilization (%)   CPU Total Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   .CPU.CPU Total Utilization (%) by CPU Partition   *CPU Total Utilization (%) by CPU Partition           Server Jobs   !bucket/default total/time average   linear   Server Jobs   $CPU.CPU Total Utilization (%) by Job    CPU Total Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Utilization (%)   CPU Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Utilization (%) by Job   CPU Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.CPU Wait Time   CPU Wait Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.CPU Wait Time by Job   CPU Wait Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Disk Interface Bus Requests   Disk Interface Bus Requests           Server Jobs   bucket/default total/max value   linear   Server Jobs   &CPU.Disk Interface Bus Requests by Job   "Disk Interface Bus Requests by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   &CPU.Disk Interface Bus Utilization (%)   "Disk Interface Bus Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   -CPU.Disk Interface Bus Utilization (%) by Job   )Disk Interface Bus Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs    CPU.Disk Interface Bus Wait Time   Disk Interface Bus Wait Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   'CPU.Disk Interface Bus Wait Time by Job   #Disk Interface Bus Wait Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   'CPU.Disk Interface Channel Bus Requests   #Disk Interface Channel Bus Requests           Server Jobs   bucket/default total/max value   linear   Server Jobs   .CPU.Disk Interface Channel Bus Requests by Job   *Disk Interface Channel Bus Requests by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   .CPU.Disk Interface Channel Bus Utilization (%)   *Disk Interface Channel Bus Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   5CPU.Disk Interface Channel Bus Utilization (%) by Job   1Disk Interface Channel Bus Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs   +CPU.Disk Interface Channel Max Bus Requests   'Disk Interface Channel Max Bus Requests           Server Jobs   bucket/default total/max value   linear   Server Jobs   2CPU.Disk Interface Channel Max Bus Requests by Job   .Disk Interface Channel Max Bus Requests by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   #CPU.Disk Interface Max Bus Requests   Disk Interface Max Bus Requests           Server Jobs   bucket/default total/max value   linear   Server Jobs   *CPU.Disk Interface Max Bus Requests by Job   &Disk Interface Max Bus Requests by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Disk Max Queue Length   Disk Max Queue Length           Server Jobs   bucket/default total/max value   linear   Server Jobs    CPU.Disk Max Queue Length by Job   Disk Max Queue Length by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Disk Operations Per Second   Disk Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   %CPU.Disk Operations Per Second by Job   !Disk Operations Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Queue Length   Disk Queue Length           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Disk Queue Length by Job   Disk Queue Length by Job           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Disk Reads Per Second   Disk Reads Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs    CPU.Disk Reads Per Second by Job   Disk Reads Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Disk Utilization (%)   Disk Utilization (%)           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.Disk Utilization (%) by Job   Disk Utilization (%) by Job           Server Jobs   !bucket/default total/time average   linear   Server Jobs   CPU.Disk Writes Per Second   Disk Writes Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   !CPU.Disk Writes Per Second by Job   Disk Writes Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Active by Job   Jobs Active by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Jobs Completed by Job   Jobs Completed by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Created by Job   Jobs Created by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Memory Size by Job   Memory Size by Job (bytes)           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Paging Hard Faults by Job   Paging Hard Faults by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Paging Soft Faults by Job   Paging Soft Faults by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   1CPU.Prioritized Job Queue Length by CPU Partition   -Prioritized Job Queue Length by CPU Partition           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Resident Set Size by Job    Resident Set Size by Job (bytes)           Server Jobs   bucket/default total/max value   linear   Server Jobs   %CPU.Storage Partition Completion Time   !Storage Partition Completion Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   ,CPU.Storage Partition Completion Time by Job   (Storage Partition Completion Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   3CPU.Storage Partition Interface Bus Total Wait Time   /Storage Partition Interface Bus Total Wait Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   :CPU.Storage Partition Interface Bus Total Wait Time by Job   6Storage Partition Interface Bus Total Wait Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   +CPU.Storage Partition Operations Per Second   'Storage Partition Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   2CPU.Storage Partition Operations Per Second by Job   .Storage Partition Operations Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   'CPU.Storage Partition Operations by Job   #Storage Partition Operations by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   &CPU.Storage Partition Reads Per Second   "Storage Partition Reads Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   -CPU.Storage Partition Reads Per Second by Job   )Storage Partition Reads Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   "CPU.Storage Partition Reads by Job   Storage Partition Reads by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   "CPU.Storage Partition Service Time   Storage Partition Service Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   )CPU.Storage Partition Service Time by Job   %Storage Partition Service Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   1CPU.Storage Partition Total Operations Per Second   -Storage Partition Total Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   ,CPU.Storage Partition Total Reads Per Second   (Storage Partition Total Reads Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   -CPU.Storage Partition Total Writes Per Second   )Storage Partition Total Writes Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Storage Partition Wait Time   Storage Partition Wait Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   &CPU.Storage Partition Wait Time by Job   "Storage Partition Wait Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   'CPU.Storage Partition Writes Per Second   #Storage Partition Writes Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   .CPU.Storage Partition Writes Per Second by Job   *Storage Partition Writes Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   #CPU.Storage Partition Writes by Job   Storage Partition Writes by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Total Jobs Completed   Total Jobs Completed           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Jobs Created   Total Jobs Created           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Memory Size   Total Memory Size (bytes)           Server Jobs   bucket/default total/max value   linear   Server Jobs   CPU.Total Resident Set Size   Total Resident Set Size (bytes)           Server Jobs   bucket/default total/max value   linear   Server Jobs   4application.Active Custom Application Instance Count   (Active Custom Application Instance Count           Custom Application   bucket/default total/max value   discrete   Custom Application   #CPU.Replication Failures Per Second   Replication Failures Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   *CPU.Replication Failures Per Second by Job   &Replication Failures Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   %CPU.Replication Operations Per Second   !Replication Operations Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   ,CPU.Replication Operations Per Second by Job   (Replication Operations Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   &CPU.Replications Successful Per Second   "Replications Successful Per Second           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   -CPU.Replications Successful Per Second by Job   )Replications Successful Per Second by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Aborted by Job   Jobs Aborted by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Jobs Aborted   Total Jobs Aborted           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   #CPU.Storage Partition Response Time   Storage Partition Response Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   *CPU.Storage Partition Response Time by Job   &Storage Partition Response Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   $application.Read Requests Per Second   Read Requests Per Second           Remote Storage Server   bucket/default total/sum_time   linear   Remote Storage Server   )application.Requests Processed Per Second   Requests Processed Per Second           Remote Storage Server   bucket/default total/sum_time   linear   Remote Storage Server   (application.Requests Received Per Second   Requests Received Per Second           Remote Storage Server   bucket/default total/sum_time   linear   Remote Storage Server   %application.Write Requests Per Second   Write Requests Per Second           Remote Storage Server   bucket/default total/sum_time   linear   Remote Storage Server   !application.Connection Setup Time   Connection Setup Time           Remote Storage Client    bucket/default total/sample mean   linear   Remote Storage Client   #application.Disk IO Completion Time   Disk IO Completion Time           Remote Storage Client    bucket/default total/sample mean   linear   Remote Storage Client   ,application.Network delay (client -> server)    Network delay (client -> server)           Remote Storage Client    bucket/default total/sample mean   linear   Remote Storage Client   ,application.Network delay (server -> client)    Network delay (server -> client)           Remote Storage Client    bucket/default total/sample mean   linear   Remote Storage Client   application.Response Time   Response Time           Remote Storage Client    bucket/default total/sample mean   linear   Remote Storage Client   )application.Operations Aborted Per Second   Operations Aborted Per Second           Remote Storage Client   bucket/default total/sum_time   linear   Remote Storage Client   +application.Operations Completed Per Second   Operations Completed Per Second           Remote Storage Client   bucket/default total/sum_time   linear   Remote Storage Client   )application.Operations Started Per Second   Operations Started Per Second           Remote Storage Client   bucket/default total/sum_time   linear   Remote Storage Client   &application.Read Operations Per Second   Read Operations Per Second           Remote Storage Client   bucket/default total/sum_time   linear   Remote Storage Client   'application.Write Operations Per Second   Write Operations Per Second           Remote Storage Client   bucket/default total/sum_time   linear   Remote Storage Client   application.Active Calls   Active Calls           SIP UAC   normal   square-wave   SIP UAC   application.Call Duration (sec)   Call Duration (sec)           SIP UAC   normal   discrete   SIP UAC   !application.Call Setup Time (sec)   Call Setup Time (sec)           SIP UAC   normal   discrete   SIP UAC   application.Calls Connected   Calls Connected           SIP UAC   bucket/60 secs/sum   discrete   SIP UAC   application.Calls Initiated   Calls Initiated           SIP UAC   bucket/60 secs/sum   discrete   SIP UAC   application.Calls Rejected   Calls Rejected           SIP UAC   bucket/60 secs/sum   discrete   SIP UAC   application.Incoming Calls   Incoming Calls           SIP UAC   bucket/60 secs/sum   discrete   SIP UAC   tcp.Retransmission Count   Retransmission Count           TCP Connection   bucket/default total/sum   discrete   TCP Connection   tcp.Segment Delay (sec)   Segment Delay (sec)           TCP Connection    bucket/default total/sample mean   discrete   TCP Connection   tcp.Active Connection Count   Active Connection Count           TCP   !bucket/default total/sum/no reset   linear   TCP    tcp.Connection Aborts (RST Rcvd)   Connection Aborts (RST Rcvd)           TCP   bucket/default total/sum   linear   TCP    tcp.Connection Aborts (RST Sent)   Connection Aborts (RST Sent)           TCP   bucket/default total/sum   linear   TCP   tcp.Retransmission Count   Retransmission Count           TCP   bucket/default total/sum   discrete   TCP   tcp.Segment Delay (sec)   Segment Delay (sec)           TCP    bucket/default total/sample mean   discrete   TCP   $application.Task Response Time (sec)   Task Response Time (sec)           ACE   normal   discrete   ACE   ip.Maintenance Buffer Size   Maintenance Buffer Size           DSR   normal   discrete   DSR   ip.Number of Hops per Route   Number of Hops per Route           DSR    bucket/default total/sample mean   linear   DSR   ip.Request Table Size   Request Table Size           DSR   normal   discrete   DSR   ip.Route Cache Access Failure   Route Cache Access Failure           DSR   bucket/default total/sum   linear   DSR   ip.Route Cache Access Success   Route Cache Access Success           DSR   bucket/default total/sum   linear   DSR   ip.Route Cache Size   Route Cache Size           DSR   normal   discrete   DSR   ip.Route Discovery Time   Route Discovery Time           DSR    bucket/default total/sample mean   linear   DSR   &ip.Routing Traffic Received (bits/sec)   #Routing Traffic Received (bits/sec)           DSR   bucket/default total/sum_time   linear   DSR   &ip.Routing Traffic Received (pkts/sec)   #Routing Traffic Received (pkts/sec)           DSR   bucket/default total/sum_time   linear   DSR   "ip.Routing Traffic Sent (bits/sec)   Routing Traffic Sent (bits/sec)           DSR   bucket/default total/sum_time   linear   DSR   "ip.Routing Traffic Sent (pkts/sec)   Routing Traffic Sent (pkts/sec)           DSR   bucket/default total/sum_time   linear   DSR   ip.Send Buffer Size   Send Buffer Size           DSR   normal   discrete   DSR   $ip.Total Traffic Received (bits/sec)   !Total Traffic Received (bits/sec)           DSR   bucket/default total/sum_time   linear   DSR   $ip.Total Traffic Received (pkts/sec)   !Total Traffic Received (pkts/sec)           DSR   bucket/default total/sum_time   linear   DSR    ip.Total Traffic Sent (bits/sec)   Total Traffic Sent (bits/sec)           DSR   bucket/default total/sum_time   linear   DSR    ip.Total Traffic Sent (pkts/sec)   Total Traffic Sent (pkts/sec)           DSR   bucket/default total/sum_time   linear   DSR   &ip.Total Acknowledgement Requests Sent   #Total Acknowledgement Requests Sent           DSR   bucket/default total/sum   linear   DSR   ip.Total Acknowledgements Sent   Total Acknowledgements Sent           DSR   bucket/default total/sum   linear   DSR   ip.Total Cached Replies Sent   Total Cached Replies Sent           DSR   bucket/default total/sum   linear   DSR   &ip.Total Non Propagating Requests Sent   #Total Non Propagating Requests Sent           DSR   bucket/default total/sum   linear   DSR   ip.Total Packets Dropped   Total Packets Dropped           DSR   bucket/default total/sum   linear   DSR   ip.Total Packets Salvaged   Total Packets Salvaged           DSR   bucket/default total/sum   linear   DSR   "ip.Total Propagating Requests Sent   Total Propagating Requests Sent           DSR   bucket/default total/sum   linear   DSR   &ip.Total Replies Sent from Destination   #Total Replies Sent from Destination           DSR   bucket/default total/sum   linear   DSR   ip.Total Route Errors Sent   Total Route Errors Sent           DSR   bucket/default total/sum   linear   DSR   ip.Total Route Replies Sent   Total Route Replies Sent           DSR   bucket/default total/sum   linear   DSR   ip.Total Route Requests Sent   Total Route Requests Sent           DSR   bucket/default total/sum   linear   DSR    ip.Traffic Dropped (packets/sec)   Traffic Dropped (packets/sec)           IPv6   bucket/default total/sum_time   linear   IPv6   !ip.Traffic Received (packets/sec)   Traffic Received (packets/sec)           IPv6   bucket/default total/sum_time   linear   IPv6   ip.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           IPv6   bucket/default total/sum_time   linear   IPv6   +ip.Multicast Traffic Received (packets/sec)   (Multicast Traffic Received (packets/sec)           IPv6   bucket/default total/sum_time   linear   IPv6   'ip.Multicast Traffic Sent (packets/sec)   $Multicast Traffic Sent (packets/sec)           IPv6   bucket/default total/sum_time   linear   IPv6   *ip.Dropped Unroutable IP Packet (pkts/sec)   'Dropped Unroutable IP Packet (pkts/sec)           	TORA_IMEP   bucket/default total/sum_time   discrete   	TORA_IMEP   +ip.IMEP Control Traffic Received (bits/sec)   (IMEP Control Traffic Received (bits/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   +ip.IMEP Control Traffic Received (pkts/sec)   (IMEP Control Traffic Received (pkts/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   'ip.IMEP Control Traffic Sent (bits/sec)   $IMEP Control Traffic Sent (bits/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   'ip.IMEP Control Traffic Sent (pkts/sec)   $IMEP Control Traffic Sent (pkts/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   ip.IMEP Number of Neighbors   IMEP Number of Neighbors           	TORA_IMEP   normal       	TORA_IMEP   ip.IMEP Retransmissions   IMEP Retransmissions           	TORA_IMEP   bucket/default total/sum   discrete   	TORA_IMEP   .ip.IMEP ULP (TORA) Traffic Received (bits/sec)   +IMEP ULP (TORA) Traffic Received (bits/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   .ip.IMEP ULP (TORA) Traffic Received (pkts/sec)   +IMEP ULP (TORA) Traffic Received (pkts/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   *ip.IMEP ULP (TORA) Traffic Sent (bits/sec)   'IMEP ULP (TORA) Traffic Sent (bits/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   *ip.IMEP ULP (TORA) Traffic Sent (pkts/sec)   'IMEP ULP (TORA) Traffic Sent (pkts/sec)           	TORA_IMEP   bucket/default total/sum_time       	TORA_IMEP   ip.Route Discovery Delay   Route Discovery Delay           	TORA_IMEP   normal   discrete   	TORA_IMEP   "ip.Unroutable IP Packet Queue Size   Unroutable IP Packet Queue Size           	TORA_IMEP   bucket/default total/max value   discrete   	TORA_IMEP   )application.Phase Response Time (seconds)   Phase Response Time (seconds)           Custom Application    bucket/default total/sample mean   discrete   Custom Application   (application.Task Response Time (seconds)   Task Response Time (seconds)           Custom Application    bucket/default total/sample mean   discrete   Custom Application   /application.Application Response Time (seconds)   #Application Response Time (seconds)           Custom Application    bucket/default total/sample mean   discrete   Custom Application   !application.Response Size (bytes)   Response Size (bytes)           Responding Custom Application    bucket/default total/sample mean   linear   Responding Custom Application   -application.Request Processing Time (seconds)   !Request Processing Time (seconds)           Responding Custom Application    bucket/default total/sample mean   linear   Responding Custom Application   application.Load (requests/sec)   Load (requests/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   application.Load (sessions/sec)   Load (sessions/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Responding Custom Application   bucket/default total/sum_time   linear   Responding Custom Application   -application.Request Generation Time (seconds)   !Request Generation Time (seconds)           Requesting Custom Application    bucket/default total/sample mean   linear   Requesting Custom Application    application.Request Size (bytes)   Request Size (bytes)           Requesting Custom Application    bucket/default total/sample mean   linear   Requesting Custom Application   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Requesting Custom Application   bucket/default total/sum_time   linear   Requesting Custom Application   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Requesting Custom Application   bucket/default total/sum_time   linear   Requesting Custom Application   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Requesting Custom Application   bucket/default total/sum_time   linear   Requesting Custom Application   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Requesting Custom Application   bucket/default total/sum_time   linear   Requesting Custom Application   ip.Number of Hops per Route   Number of Hops per Route           AODV    bucket/default total/sample mean   linear   AODV   ip.Packet Queue Size   Packet Queue Size           AODV   normal   discrete   AODV   ip.Route Discovery Time   Route Discovery Time           AODV    bucket/default total/sample mean   linear   AODV   ip.Route Table Size   Route Table Size           AODV   normal   discrete   AODV   &ip.Routing Traffic Received (bits/sec)   #Routing Traffic Received (bits/sec)           AODV   bucket/default total/sum_time   linear   AODV   &ip.Routing Traffic Received (pkts/sec)   #Routing Traffic Received (pkts/sec)           AODV   bucket/default total/sum_time   linear   AODV   "ip.Routing Traffic Sent (bits/sec)   Routing Traffic Sent (bits/sec)           AODV   bucket/default total/sum_time   linear   AODV   "ip.Routing Traffic Sent (pkts/sec)   Routing Traffic Sent (pkts/sec)           AODV   bucket/default total/sum_time   linear   AODV   ip.Total Cached Replies Sent   Total Cached Replies Sent           AODV   bucket/default total/sum   linear   AODV   ip.Total Packets Dropped   Total Packets Dropped           AODV   bucket/default total/sum   linear   AODV   &ip.Total Replies Sent from Destination   #Total Replies Sent from Destination           AODV   bucket/default total/sum   linear   AODV   ip.Total Route Errors Sent   Total Route Errors Sent           AODV   bucket/default total/sum   linear   AODV   ip.Total Route Replies Sent   Total Route Replies Sent           AODV   bucket/default total/sum   linear   AODV   !ip.Total Route Requests Forwarded   Total Route Requests Forwarded           AODV   bucket/default total/max value   linear   AODV   ip.Total Route Requests Sent   Total Route Requests Sent           AODV   bucket/default total/sum   linear   AODV   manet_rte_mgr.MPR Status   
MPR Status           OLSR   normal   linear   OLSR   1manet_rte_mgr.Routing Traffic Received (bits/sec)   #Routing Traffic Received (bits/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   1manet_rte_mgr.Routing Traffic Received (pkts/sec)   #Routing Traffic Received (pkts/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   -manet_rte_mgr.Routing Traffic Sent (bits/sec)   Routing Traffic Sent (bits/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   -manet_rte_mgr.Routing Traffic Sent (pkts/sec)   Routing Traffic Sent (pkts/sec)           OLSR   bucket/default total/sum_time   linear   OLSR   'manet_rte_mgr.Total Hello Messages Sent   Total Hello Messages Sent           OLSR   bucket/default total/sum   linear   OLSR   )manet_rte_mgr.Total TC Messages Forwarded   Total TC Messages Forwarded           OLSR   bucket/default total/sum   linear   OLSR   $manet_rte_mgr.Total TC Messages Sent   Total TC Messages Sent           OLSR   bucket/default total/sum   linear   OLSR   .mobile_ip.Registration Traffic Received (bits)   $Registration Traffic Received (bits)           	Mobile IP   bucket/default total/sum   linear   	Mobile IP   1mobile_ip.Registration Traffic Received (packets)   'Registration Traffic Received (packets)           	Mobile IP   bucket/default total/sum   linear   	Mobile IP   *mobile_ip.Registration Traffic Sent (bits)    Registration Traffic Sent (bits)           	Mobile IP   bucket/default total/sum   linear   	Mobile IP   -mobile_ip.Registration Traffic Sent (packets)   #Registration Traffic Sent (packets)           	Mobile IP   bucket/default total/sum   linear   	Mobile IP   ip.Active Access Point   Active Access Point           Mobile IPv6   normal   bar   Mobile IPv6   ip.Binding Cache Table Size   Binding Cache Table Size           Mobile IPv6   normal   discrete   Mobile IPv6   ip.Binding Update List Size   Binding Update List Size           Mobile IPv6   normal   discrete   Mobile IPv6   &ip.Control Traffic Received (bits/sec)   #Control Traffic Received (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   &ip.Control Traffic Received (pkts/sec)   #Control Traffic Received (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   "ip.Control Traffic Sent (bits/sec)   Control Traffic Sent (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   "ip.Control Traffic Sent (pkts/sec)   Control Traffic Sent (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   !ip.Home Agent Binding Delay (sec)   Home Agent Binding Delay (sec)           Mobile IPv6    bucket/default total/sample mean   discrete   Mobile IPv6   "ip.Route Optimization Overhead (%)   Route Optimization Overhead (%)           Mobile IPv6   normal   discrete   Mobile IPv6   )ip.Route Optimization Overhead (bits/sec)   &Route Optimization Overhead (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   1ip.Route Optimization Traffic Received (bits/sec)   .Route Optimization Traffic Received (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   1ip.Route Optimization Traffic Received (pkts/sec)   .Route Optimization Traffic Received (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   -ip.Route Optimization Traffic Sent (bits/sec)   *Route Optimization Traffic Sent (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   -ip.Route Optimization Traffic Sent (pkts/sec)   *Route Optimization Traffic Sent (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   ip.Tunneled Traffic Delay (sec)   Tunneled Traffic Delay (sec)           Mobile IPv6   normal   discrete   Mobile IPv6    ip.Tunneled Traffic Overhead (%)   Tunneled Traffic Overhead (%)           Mobile IPv6   normal   discrete   Mobile IPv6   'ip.Tunneled Traffic Overhead (bits/sec)   $Tunneled Traffic Overhead (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   'ip.Tunneled Traffic Received (bits/sec)   $Tunneled Traffic Received (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   'ip.Tunneled Traffic Received (pkts/sec)   $Tunneled Traffic Received (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   #ip.Tunneled Traffic Sent (bits/sec)    Tunneled Traffic Sent (bits/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   #ip.Tunneled Traffic Sent (pkts/sec)    Tunneled Traffic Sent (pkts/sec)           Mobile IPv6   bucket/default total/sum_time   linear   Mobile IPv6   CPU.CPU Service Time   CPU Service Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   ip.Number of Hops -->   Number of Hops -->           IP    bucket/default total/sample mean   linear   IP   ip.Number of Hops <--   Number of Hops <--           IP    bucket/default total/sample mean   linear   IP   application.Jitter (sec)   Jitter (sec)           Voice Application    bucket/default total/sample mean   discrete   Voice Application   application.Jitter (sec)   Jitter (sec)           Voice Called Party    bucket/default total/sample mean   discrete   Voice Called Party   application.Jitter (sec)   Jitter (sec)           Voice Calling Party    bucket/default total/sample mean   discrete   Voice Calling Party   #application.Response Time (seconds)   Response Time (seconds)           Application Demand   normal   discrete   Application Demand   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           Application Demand   bucket/default total/sum_time   linear   Application Demand   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           Application Demand   bucket/default total/sum_time   linear   Application Demand   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           Application Demand   bucket/default total/sum_time   linear   Application Demand   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           Application Demand   bucket/default total/sum_time   linear   Application Demand   $CPU.Total Jobs Queued Before Startup    Total Jobs Queued Before Startup           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   %CPU.Jobs Queued Before Startup by Job   !Jobs Queued Before Startup by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Total Jobs Rejected   Total Jobs Rejected           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Jobs Rejected by Job   Jobs Rejected by Job           Server Jobs   bucket/default total/sum_time   linear   Server Jobs   CPU.Startup Queue Size by Job   Startup Queue Size by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Total Startup Wait Time   Total Startup Wait Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Startup Wait Time by Job   Startup Wait Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.Total Startup Queue Size   Total Startup Queue Size           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   $application.User Defined Stat (Mean)   User Defined Stat (Mean)           ACE Whiteboard    bucket/default total/sample mean   discrete   ACE Whiteboard   &application.User Defined Stat (Normal)   User Defined Stat (Normal)           ACE Whiteboard   normal   discrete   ACE Whiteboard   #application.User Defined Stat (Sum)   User Defined Stat (Sum)           ACE Whiteboard   bucket/default total/sum   discrete   ACE Whiteboard   (application.User Defined Stat (Sum/Time)   User Defined Stat (Sum/Time)           ACE Whiteboard   bucket/default total/sum_time   discrete   ACE Whiteboard   ,application.User Defined Stat (Time Average)    User Defined Stat (Time Average)           ACE Whiteboard   !bucket/default total/time average   discrete   ACE Whiteboard   (wireless_lan_mac.AC Queue Size (packets)   AC Queue Size (packets)           WLAN (Per HCF Access Category)   !bucket/default total/time average   linear   WLAN (Per HCF Access Category)   :wireless_lan_mac.Data Dropped (Buffer Overflow) (bits/sec)   )Data Dropped (Buffer Overflow) (bits/sec)           WLAN (Per HCF Access Category)   bucket/default total/sum_time   linear   WLAN (Per HCF Access Category)   Cwireless_lan_mac.Data Dropped (Retry Threshold Exceeded) (bits/sec)   2Data Dropped (Retry Threshold Exceeded) (bits/sec)           WLAN (Per HCF Access Category)   bucket/default total/sum_time   linear   WLAN (Per HCF Access Category)   wireless_lan_mac.Delay (sec)   Delay (sec)           WLAN (Per HCF Access Category)    bucket/default total/sample mean   linear   WLAN (Per HCF Access Category)    wireless_lan_mac.Load (bits/sec)   Load (bits/sec)           WLAN (Per HCF Access Category)   bucket/default total/sum_time   linear   WLAN (Per HCF Access Category)   #wireless_lan_mac.Load (packets/sec)   Load (packets/sec)           WLAN (Per HCF Access Category)   bucket/default total/sum_time   linear   WLAN (Per HCF Access Category)   )wireless_lan_mac.Media Access Delay (sec)   Media Access Delay (sec)           WLAN (Per HCF Access Category)    bucket/default total/sample mean   linear   WLAN (Per HCF Access Category)   &wireless_lan_mac.Throughput (bits/sec)   Throughput (bits/sec)           WLAN (Per HCF Access Category)   bucket/default total/sum_time   linear   WLAN (Per HCF Access Category)    wireless_lan_mac.AP Connectivity   AP Connectivity           Wireless Lan   normal   square-wave   Wireless Lan   %wireless_lan_mac.Queue Size (packets)   Queue Size (packets)           Wireless Lan   !bucket/default total/time average   linear   Wireless Lan   0wireless_lan_mac.Control Traffic Sent (bits/sec)   Control Traffic Sent (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   0wireless_lan_mac.Control Traffic Rcvd (bits/sec)   Control Traffic Rcvd (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   -wireless_lan_mac.Data Traffic Sent (bits/sec)   Data Traffic Sent (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   -wireless_lan_mac.Data Traffic Rcvd (bits/sec)   Data Traffic Rcvd (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   :wireless_lan_mac.Data Dropped (Buffer Overflow) (bits/sec)   )Data Dropped (Buffer Overflow) (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   Cwireless_lan_mac.Data Dropped (Retry Threshold Exceeded) (bits/sec)   2Data Dropped (Retry Threshold Exceeded) (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   3wireless_lan_mac.Management Traffic Sent (bits/sec)   "Management Traffic Sent (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   3wireless_lan_mac.Management Traffic Rcvd (bits/sec)   "Management Traffic Rcvd (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   6wireless_lan_mac.Management Traffic Dropped (bits/sec)   %Management Traffic Dropped (bits/sec)           Wireless Lan   bucket/default total/sum_time   linear   Wireless Lan   application.Delay (sec)   Delay (sec)           RTP    bucket/default total/sample mean   discrete   RTP    application.Delay Variance (sec)   Delay Variance (sec)           RTP    bucket/default total/sample mean   discrete   RTP   application.Jitter (sec)   Jitter (sec)           RTP    bucket/default total/sample mean   discrete   RTP   (application.Traffic Received (bytes/sec)   Traffic Received (bytes/sec)           RTP   bucket/default total/sum_time   linear   RTP   *application.Traffic Received (packets/sec)   Traffic Received (packets/sec)           RTP   bucket/default total/sum_time   linear   RTP   $application.Traffic Sent (bytes/sec)   Traffic Sent (bytes/sec)           RTP   bucket/default total/sum_time   linear   RTP   &application.Traffic Sent (packets/sec)   Traffic Sent (packets/sec)           RTP   bucket/default total/sum_time   linear   RTP   dhcp.Solicit Message Count   Solicit Message Count           DHCP   normal   discrete   DHCP   'dhcp.Rapid Commit Solicit Message Count   "Rapid Commit Solicit Message Count           DHCP   normal   discrete   DHCP   dhcp.Advertise Message Count   Advertise Message Count           DHCP   normal   discrete   DHCP   dhcp.Request Message Count   Request Message Count           DHCP   normal   discrete   DHCP   dhcp.Reply Message Count   Reply Message Count           DHCP   normal   discrete   DHCP   %dhcp.Rapid Commit Reply Message Count    Rapid Commit Reply Message Count           DHCP   normal   discrete   DHCP   dhcp.Renew Message Count   Renew Message Count           DHCP   normal   discrete   DHCP   dhcp.Rebind Message Count   Rebind Message Count           DHCP   normal   discrete   DHCP   dhcp.Retransmissions   Retransmissions           DHCP   normal   discrete   DHCP   dhcp.Prefixes Assigned   Prefixes Assigned           DHCP   normal   discrete   DHCP   dhcp.Prefix Assignment Renewals   Prefix Assignment Renewals           DHCP   normal   discrete   DHCP   dhcp.Addresses Assigned   Addresses Assigned           DHCP   normal   discrete   DHCP    dhcp.Address Assignment Renewals   Address Assignment Renewals           DHCP   normal   discrete   DHCP   dhcp.Transaction Delay   Transaction Delay           DHCP   normal   linear   DHCP   CPU.Total Response Time by Job   Total Response Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.CPU Response Time   CPU Response Time           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   CPU.CPU Response Time by Job   CPU Response Time by Job           Server Jobs    bucket/default total/sample mean   linear   Server Jobs   ip.End-to-end Delay (sec)   End-to-end Delay (sec)           IP    bucket/default total/sample mean   discrete   IP   #ip.End-to-end Delay Variation (sec)    End-to-end Delay Variation (sec)           IP    bucket/default total/sample mean   discrete   IP   3ip.Packets Dropped (Destination unknown) (bits/sec)   0Packets Dropped (Destination unknown) (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   5ip.Packets Dropped (No available neighbor) (bits/sec)   2Packets Dropped (No available neighbor) (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   *ip.Packets Dropped (TTL expiry) (bits/sec)   'Packets Dropped (TTL expiry) (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   %ip.Packets Dropped (Total) (bits/sec)   "Packets Dropped (Total) (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   &ip.Routing Traffic Received (bits/sec)   #Routing Traffic Received (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   &ip.Routing Traffic Received (pkts/sec)   #Routing Traffic Received (pkts/sec)           GRP   bucket/default total/sum_time   linear   GRP   "ip.Routing Traffic Sent (bits/sec)   Routing Traffic Sent (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   "ip.Routing Traffic Sent (pkts/sec)   Routing Traffic Sent (pkts/sec)           GRP   bucket/default total/sum_time   linear   GRP   ip.Total Number of Backtracks   Total Number of Backtracks           GRP   bucket/default total/sum   linear   GRP   #ip.Total Number of Quadrant Changes    Total Number of Quadrant Changes           GRP   bucket/default total/sum   linear   GRP   $ip.Total Traffic Received (bits/sec)   !Total Traffic Received (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP   $ip.Total Traffic Received (pkts/sec)   !Total Traffic Received (pkts/sec)           GRP   bucket/default total/sum_time   linear   GRP    ip.Total Traffic Sent (bits/sec)   Total Traffic Sent (bits/sec)           GRP   bucket/default total/sum_time   linear   GRP    ip.Total Traffic Sent (pkts/sec)   Total Traffic Sent (pkts/sec)           GRP   bucket/default total/sum_time   linear   GRP   application.MOS Dejitter Delay   MOS Dejitter Delay           Voice Application    bucket/default total/sample mean   discrete   Voice Application   "application.MOS Dejitter Loss Rate   MOS Dejitter Loss Rate           Voice Application    bucket/default total/sample mean   discrete   Voice Application   !application.MOS Network Loss Rate   MOS Network Loss Rate           Voice Application    bucket/default total/sample mean   discrete   Voice Application   application.MOS Value   	MOS Value           Voice Application    bucket/default total/sample mean   discrete   Voice Application   application.Active Calls   Active Calls           H323   normal   sample-hold   H323   application.Setup Time   
Setup Time           H323   !bucket/default total/time average   linear   H323   application.Total Calls   Total Calls           H323   normal   sample-hold   H323   application.Total Failed Calls   Total Failed Calls           H323   normal   sample-hold   H323   "application.Total Successful Calls   Total Successful Calls           H323   normal   sample-hold   H323          machine type       workstation   Model Attributes      14.5.A-January18-2008                 interface type       
IEEE802.11   interface class       ip      6IP Host Parameters.Interface Information [<n>].Address      
IP Address   :IP Host Parameters.Interface Information [<n>].Subnet Mask      IP Subnet Mask       wlan_port_tx_<n>_0   wlan_port_rx_<n>_0           