/* hmipv6_defs.h: Header file with HMIPv6 definitions.  */

/* 
 * File: hmipv6_support.h
 *
 * Modified MIPv6 for use with HMIPv6:
 *
 * Description: Support file for Hierarchal Mobile IPv6 (HMIPv6)
 *              Data structures and macro's for implementation.
 *
 * Author: Brian Gianforcaro (b.gianfo@gmail.com)
 *
 * Terminology:
 *  HA - Home Agent
 *  CN - Corespondent Node
 *  MN - Mobile Node
 *  BU - Binding Update
 *  MAP - Mobility Anchor Point
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
	
address_t stringToAddress( std::string dest_str );
 

std::string addressToString( address_t address );

/**
 * Obtain the destination address from the packet 
 */
address_t dest_address( Packet* packet );

/**
 * Obtain the source address from the packet 
 */
address_t src_address( Packet* packet ); 
