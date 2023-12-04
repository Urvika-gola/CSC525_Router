#ifndef ROUTER_UTILITIES
#define ROUTER_UTILITIES

#include "pwospf_protocol.h"
#include "network_topology_manager.h"
// Define a structure to represent the ICMP header
struct IcmpHeader
{
    uint8_t type;       // Type of the ICMP message
    uint8_t code;       // Code for the ICMP message
    uint16_t checksum;  // Checksum to verify data integrity
    uint32_t data;      // Additional data for the ICMP message
    // Note: The payload is not included in this structure
} __attribute__ ((packed));  // Ensure that the compiler does not add any padding between fields

// Define constants for ICMP types to improve readability
#ifndef ICMP_TYPE_REQUEST
#define ICMP_TYPE_REQUEST       8  // ICMP Echo Request
#endif

#ifndef ICMP_TYPE_REPLY
#define ICMP_TYPE_REPLY         0  // ICMP Echo Reply
#endif

// FUNCTION DECLARATIONS

/**
 * @brief Calculate the Internet Checksum for generic packets.
 * 
 * This function calculates the checksum for generic packets, which is used to detect errors 
 * in transmitted packets. The checksum is calculated by summing 16-bit words and 
 * handling the carry bits accordingly.
 * 
 * @param buffer Pointer to the data for which the checksum is to be calculated.
 * @param wordCount The number of 16-bit words in the data.
 * @return u_short The calculated checksum.
 */
u_short calculateChecksum(u_short *buffer, int wordCount);

/**
 * @brief Calculate the Internet Checksum for ICMP packets.
 * 
 * This function calculates the checksum for ICMP packets, which is used to detect errors 
 * in transmitted packets. The checksum is calculated by summing 16-bit words and 
 * folding the carry bits into the sum.
 * 
 * @param dataPointer Pointer to the data for which the checksum is to be calculated.
 * @param byteCount The number of bytes in the data.
 * @return uint16_t The calculated checksum.
 */
uint16_t calculateIcmpChecksum(uint16_t* dataPointer, int byteCount);

#endif  // End of the ROUTER_UTILITIES inclusion guard
