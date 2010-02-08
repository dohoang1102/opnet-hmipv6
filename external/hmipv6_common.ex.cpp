#include <opnet.h>
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
#include <string>

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
