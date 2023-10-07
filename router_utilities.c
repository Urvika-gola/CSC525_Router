
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "IP_Mac_Mapping.h"
#include "IP_Mac_Mapping_Buffer.h"
#include "sr_router.h"
#include "router_utilities.h"

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
uint16_t calculateIcmpChecksum(uint16_t* dataPointer, int byteCount)
{
    register uint32_t sum = 0;
    // Loop through all 16-bit words in the data, summing them up
    for(; byteCount > 1; byteCount -= 2) {
        sum += *dataPointer++;
    }
    // If there's a leftover byte, add it to the sum
    if (byteCount > 0)
        sum += *((uint8_t*)dataPointer);
    // Add back any carry out from the top 16 bits to the low 16 bits
    for(; sum >> 16;)
        sum = (sum & 0xffff) + (sum >> 16);
    // Return the one's complement of the sum
    return (~sum);
}

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
u_short calculateChecksum(u_short *buffer, int wordCount)
{
    register u_long sum = 0;
    // Loop through all 16-bit words in the data, summing them up
    for(; wordCount--;)
    {
        sum += *buffer++;
        // If a carry from the lower bits to the upper bits occurred, handle it
        if (sum & 0xFFFF0000)
        {
            // Wrap around the carry by adding it to the sum
            sum &= 0xFFFF;
            sum++;
        }
    }
    // Return the one's complement of the sum
    return ~(sum & 0xFFFF);
}
