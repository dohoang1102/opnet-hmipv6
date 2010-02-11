/* 
** File: hmipv6_support.h
**
** Description: Support file for Hierarchal Mobile IPv6 (HMIPv6)
**              Data structures and macro's for implementation.
**
** Author: Brian Gianforcaro (b.gianfo@gmail.com)
**
** Terminology:
**  HA - Home Agent
**  CN - Corespondent Node
**  MN - Mobile Node
**  BU - Binding Update
**  MAP - Mobility Anchor Point
**
**  address_t - Just a InetT_Address typedef
*/

#include <opnet.h>
#include <hmipv6_defs.h>
#include <hmipv6_support.h>
#include <mipv6_support.h>
#include <string>

/**
 * Make sure the given packet is the correct format
 */
bool correct_packet_fmt( Packet* packet );
/**
 * Convert C++ string to InetT_Address
 */
address_t stringToAddress( std::string dest_str );
	
/**
 * Convert InetT_Address to C++ string.
 */
std::string addressToString( address_t address );

/**
 * Obtain the destination address from the packet 
 */
address_t dest_address( Packet* packet );

/**
 * Obtain the source address from the packet 
 */
address_t src_address( Packet* packet ); 

/**
 * Check if this packet was tunneled and this was the source.
 */
bool tunneled( Packet* packet, address_t destination );

/**
 * This function removes and IPv6 in IPv6 encapsulated packet.
 * It is used at the end point of a HMIPv6 tunnel. 
 */ 
void decapsulate_pkt( Packet** packet ); 

/** 
 * Encapsulates IPv6 in IPv6 packets to be transported by a HMIPv6 tunnel. 
 */
void tunnel_pkt( Packet** packet, address_t source, address_t dest );
