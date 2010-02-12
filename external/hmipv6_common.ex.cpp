/*
** Author: Brian Gianforcaro (b.gianfo@gmail.com)
** Description: Convenience functions for working with HMIPv6
**
** 
*/

#include <opnet.h>
#include <hmipv6_common.h>

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
 * Convert a std::string to a InetT_Address
 */
address_t stringToAddress( std::string dest_str ) {
  
  address_t address;

	FIN( stringToAddress( address ) );

  address = inet_address_create( dest_str.c_str(), InetC_Addr_Family_v6 );

  FRET( address );
}

/**
 * Convert a InetT_Address to a std::string
 */
std::string addressToString( address_t address ) {
  char buffer[100];

	FIN( addressToString( address ) );

  inet_address_print( buffer, address );

  std::string address_string( buffer );

  FRET( address_string );
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
 * Check if this packet was tunneled and this was the destination.
 */
bool tunneled( Packet* packet, address_t destination ) {
  
  IpT_Dgram_Fields* fields;

  FIN( tunneled( packet ) );

  /* Access field information. */
  op_pk_nfd_access( packet, "fields", &fields );

  if ( fields->encap_count > 0 && fields->protocol == IpC_Protocol_IPv6 ) {
    if ( inet_address_equal( destination, fields->dest_addr ) ) {
      FRET( true );
    }
  }
  FRET( false );
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
 * Encapsulates IPv6 in IPv6 packets to be transported by a HMIPv6 tunnel. 
 */
void tunnel_pkt( Packet** packet, address_t source, address_t dest ) {

  Packet* ip_packet;
  IpT_Dgram_Fields* newDG;
  IpT_Dgram_Fields* oldDG;

  FIN( tunnel_pkt( packet, source, dest_address ) );

  /* Access the old field information.            */
  op_pk_nfd_access( *packet, "fields", &oldDG );

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
  newDG = ip_dgram_fdstruct_copy( oldDG );

  /* Remove the extension headers if any. The outer packet  */
  /* of a MIPv6 tunnel must not carry any IPv6 extension    */
  /* headers, otherwise MIPv6 may process it as a MIPv6     */
  /* control message.                     */
  if ( ipv6_extension_header_exists( newDG ) ) {
    /* Remove the extension headers from the outer packet.  */
    ip_dgram_extension_headers_info_destroy( newDG );   
  }

  /* While copying the contents of the IPv6 header fields   */
  /* copies of the original source and destination IPv6     */
  /* addresses were allocated in memory. They must be     */
  /* destroyed since they will be replaced by the tunnels   */
  /* source and destination addresses.            */
  inet_address_destroy( newDG->src_addr );
  inet_address_destroy( newDG->dest_addr );
  
  /* Set the destination address for this IP datagram.    */
  newDG->src_addr = inet_address_copy( source );
  newDG->src_internal_addr = inet_rtab_addr_convert( source );

  /* Set the destination address for this IP datagram.    */
  newDG->dest_addr = inet_address_copy( dest );
  newDG->dest_internal_addr = inet_rtab_addr_convert( dest );
  
  /* The protocol fields  must indicate that there is an IPv6 */
  /* datagram encapsulated in this packet.          */
  newDG->protocol = IpC_Protocol_IPv6;
  
  /* Set the packet size-related fields of the IP datagram. */
  newDG->orig_len = op_pk_total_size_get( *packet ) / 8;
  newDG->frag_len = newDG->orig_len;
  newDG->original_size = 160 + newDG->orig_len * 8;

  /* Indicate that the packet is not yet fragmented.      */
  newDG->frag = 0;

  /* Set the encapsulation count for sim efficiency.      */
  newDG->encap_count++;

  newDG->dest_internal_addr = IPC_FAST_ADDR_INVALID;
  newDG->src_internal_addr  = IPC_FAST_ADDR_INVALID;

  /*  Set the fields structure inside the ip datagram.    */
  op_pk_nfd_set( ip_packet, "fields", newDG, 
      ip_dgram_fdstruct_copy, ip_dgram_fdstruct_destroy, sizeof( IpT_Dgram_Fields ));

  /* Set the original IP packet in the data field of the new  IP datagram. */
  op_pk_nfd_set( ip_packet, "data", *packet );

  /* Return the outer packet. */
  *packet = ip_packet;
  
  FOUT;
}

