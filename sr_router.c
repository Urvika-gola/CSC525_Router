/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #1693354266
 * 
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "IP_Mac_Mapping.h"
#include "IP_Mac_Mapping_Buffer.h"
#include "router_utilities.h"
#include "sr_pwospf.h"

void process_icmp_packet_packet(struct sr_instance* sr,
uint8_t * packet,
unsigned int len,
char* interface);
void process_ip_packet(struct sr_instance* sr,
uint8_t * packet,
unsigned int len,
char* interface);
void process_arp_packet(struct sr_instance* sr,
uint8_t * packet,
unsigned int len,
char* interface);
void transfer_arp_packet(struct sr_instance* sr,
uint8_t * orig_packet,
char* interface,
uint32_t dest_ip);


IP_Mac_Mapping arp_head;
IP_Mac_Mapping_Buffer buf_head;

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr)
{
/* REQUIRES */
assert(sr);

arp_head.next = NULL;
buf_head.next = NULL;
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
uint8_t * packet/* lent */,
unsigned int len,
char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) packet;
    if(htons(eth->ether_type) == ETHERTYPE_ARP) {
    process_arp_packet(sr, packet, len, interface);
    } else if(htons(eth->ether_type) == ETHERTYPE_IP) {
    process_ip_packet(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */

/**
 * transfer_arp_packet - Function to send ARP requests.
 *
 * This function constructs and sends an ARP request packet, either to a specific
 * IP address or to the IP address extracted from an original packet.
 *
 * @param sr: A pointer to the router instance.
 * @param orig_packet: A pointer to the original packet that prompted the ARP request.
 * @param interface: The name of the interface on which to send the ARP request.
 * @param dest_ip: The IP address to which the ARP request should be sent. If 0, the IP address is extracted from orig_packet.
 */
void transfer_arp_packet(struct sr_instance* sr,
                 uint8_t * orig_packet,
                 char* interface,
                 uint32_t dest_ip)
{
    // Allocate memory for the ARP request packet.
    uint8_t packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)];
    memset(&packet, 0, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

    // Pointers to the Ethernet and ARP headers of the packet.
    struct sr_ethernet_hdr *ethernetHeader = (struct sr_ethernet_hdr*) packet;
    struct sr_arphdr *arpHeader = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));

    // Set Ethernet header fields.
    memset(ethernetHeader->ether_dhost, 0xFF, ETHER_ADDR_LEN);  // Broadcast address.
    ethernetHeader->ether_type = htons(ETHERTYPE_ARP);

    // Set ARP header fields.
    arpHeader->ar_hrd = htons(ARPHDR_ETHER);
    arpHeader->ar_pro = htons(ETHERTYPE_IP);
    arpHeader->ar_hln = 6;
    arpHeader->ar_pln = 4;
    arpHeader->ar_op = htons(ARP_REQUEST);

    // Find the interface to use for sending the ARP request.
    struct sr_if* interfaceWalker = sr->if_list;
    while(interfaceWalker)
    {
        if(strncmp(interface, interfaceWalker->name, sizeof(interfaceWalker->name)) == 0)
            break;
        interfaceWalker = interfaceWalker->next;
    }

    // Set source MAC and IP addresses in the ARP header.
    memcpy(ethernetHeader->ether_shost, interfaceWalker->addr, sizeof(ethernetHeader->ether_shost));
    arpHeader->ar_sip = interfaceWalker->ip;
    memcpy(arpHeader->ar_sha, ethernetHeader->ether_shost, sizeof(arpHeader->ar_sha));

    // Set target IP address in the ARP header.
    if(dest_ip == 0) {
        arpHeader->ar_tip = ((struct ip*)(orig_packet + sizeof(struct sr_ethernet_hdr)))->ip_dst.s_addr;
    } else {
        arpHeader->ar_tip = dest_ip;
    }

    // Set target MAC address in the ARP header to 0s (unknown).
    memset(arpHeader->ar_tha, 0, sizeof(arpHeader->ar_tha));

    // Send the ARP request packet.
    int rc = sr_send_packet(sr, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), interface);
    assert(rc == 0);
}

/**
 * process_arp_packet - Function to handle ARP packets.
 *
 * This function processes incoming ARP packets, responding to ARP requests
 * and caching information from ARP replies.
 *
 * @param sr: A pointer to the router instance.
 * @param packet: A pointer to the incoming packet data.
 * @param len: The length of the incoming packet data.
 * @param interface: The name of the interface on which the packet was received.
 */
void process_arp_packet(struct sr_instance* sr,
                  uint8_t * packet,
                  unsigned int len,
                  char* interface)
{
    struct sr_ethernet_hdr *ethernetHeader = (struct sr_ethernet_hdr*) packet;
    struct sr_arphdr *arpHeader = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));

    // Handle ARP request.
    if(arpHeader->ar_op == ntohs(1)) {
        // Ensure the interface list is not empty.
        if(sr->if_list == 0)
        {
            printf(" Interface list empty \n");
            return;
        }

        // Find the interface that matches the target IP of the ARP request.
        struct sr_if* interfaceWalker;
        for(interfaceWalker = sr->if_list; interfaceWalker != NULL; interfaceWalker = interfaceWalker->next)
        {
            // If interface found, prepare ARP reply.
            if(interfaceWalker->ip == arpHeader->ar_tip) {
                arpHeader->ar_op = ntohs(2);
                memcpy(arpHeader->ar_tha, arpHeader->ar_sha, sizeof(arpHeader->ar_tha));
                memcpy(arpHeader->ar_sha, interfaceWalker->addr, sizeof(arpHeader->ar_sha));
                uint32_t temp = arpHeader->ar_tip;
                arpHeader->ar_tip = arpHeader->ar_sip;
                arpHeader->ar_sip = temp;
                memcpy(ethernetHeader->ether_dhost, ethernetHeader->ether_shost, sizeof(ethernetHeader->ether_dhost));
                memcpy(ethernetHeader->ether_shost, arpHeader->ar_sha, sizeof(arpHeader->ar_sha));
                int rc = sr_send_packet(sr, packet, len, interface);
                assert(rc == 0);
                break;
            }
        }

        if(interfaceWalker == NULL) {
            printf("No matching interface found for ARP request.\n");
        }
    } 
    // Handle ARP reply.
    else if (arpHeader->ar_op == ntohs(2)) {
        // Find buffer entry for the source IP of the ARP reply.
        IP_Mac_Mapping_Buffer *currentBuffer = find_buffer_by_ip(&buf_head, arpHeader->ar_sip);

        // If no buffer entry found, ignore the ARP reply.
        if(currentBuffer == NULL)
            return;

        // Add the sender's IP and MAC address to the ARP cache.
        addMapping(&arp_head, arpHeader->ar_sip, arpHeader->ar_sha);

        // Process buffered packets waiting for this ARP reply.
        unsigned int bufferedPacketLen = 0;
        uint8_t *bufferedPacket = dequeue_packet(currentBuffer, &bufferedPacketLen);
        while(bufferedPacket != NULL) {
            struct ip *ipHeader = (struct ip*) (bufferedPacket + sizeof(struct sr_ethernet_hdr));
            sr_handlepacket(sr, bufferedPacket, bufferedPacketLen, interface);

            free(bufferedPacket);
            bufferedPacket = dequeue_packet(currentBuffer, &bufferedPacketLen);
        }
    }
}

/**
 * @brief Handles ICMP packets.
 * 
 * This function processes ICMP packets, ensuring they are ICMP requests, 
 * and if so, modifies them to be ICMP replies and sends them back.
 * 
 * @param sr        Pointer to the router instance, used to send out packets.
 * @param packet    Pointer to the received packet data.
 * @param len       Length of the received packet data.
 * @param interface Name of the interface on which the packet was received.
 */
void process_icmp_packet_packet(
    struct sr_instance* sr,
    uint8_t * packet_data,
    unsigned int packet_length,
    char* interface_name
) {
    // Extract Ethernet and IP headers from the packet data.
    struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr*) packet_data;
    struct ip *ip_header = (struct ip*) (packet_data + sizeof(struct sr_ethernet_hdr));

    // Ensure the packet is an ICMP packet, otherwise ignore it.
    if(ip_header->ip_p != IPPROTO_ICMP) {
        return;
    }

    // Extract ICMP header from the packet data.
    struct IcmpHeader *icmp_header = (struct IcmpHeader*) (
        packet_data + 
        sizeof(struct sr_ethernet_hdr) + 
        sizeof(struct ip)
    );

    // Ensure the packet is an ICMP request, otherwise ignore it.
    if(icmp_header->type != ICMP_TYPE_REQUEST || icmp_header->code != 0) {
        return;
    }

    // Store the original checksum and then reset it in the header for recalculation.
    uint16_t original_checksum = icmp_header->checksum;
    icmp_header->checksum = 0;
    icmp_header->checksum = calculateIcmpChecksum(
        (uint16_t *) icmp_header, 
        packet_length - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)
    );

    // If the recalculated checksum doesn't match the original, ignore the packet.
    if(original_checksum != icmp_header->checksum) {
        printf("Failed checksum, %d vs %d\n", original_checksum, icmp_header->checksum);
        return;
    }

    // Swap the source and destination IP addresses to send a reply back.
    uint32_t temporary_ip = ip_header->ip_src.s_addr;
    ip_header->ip_src.s_addr = ip_header->ip_dst.s_addr;
    ip_header->ip_dst.s_addr = temporary_ip;

    // Modify the ICMP type to be a reply.
    icmp_header->type = ICMP_TYPE_REPLY;

    // Recalculate the checksum for the modified ICMP packet.
    icmp_header->checksum = 0;
    icmp_header->checksum = calculateIcmpChecksum(
        (uint16_t *) icmp_header, 
        packet_length - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip)
    );

    // Send out the modified packet.
    sr_handlepacket(sr, packet_data, packet_length, interface_name);
}
/**
 * @brief Handle IP packets.
 * 
 * This function processes IP packets, performing various checks and 
 * potentially forwarding them based on the routing table or sending 
 * ICMP replies.
 * 
 * @param sr        Pointer to the router instance.
 * @param packet    Pointer to the received packet data.
 * @param len       Length of the received packet data.
 * @param interface Name of the interface on which the packet was received.
 */
void process_ip_packet(
    struct sr_instance* sr,
    uint8_t * packet_data,
    unsigned int packet_length,
    char* interface_name
) {
    // Extract Ethernet and IP headers from the packet data.
    struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr*) packet_data;
    struct ip *ip_header = (struct ip*) (packet_data + sizeof(struct sr_ethernet_hdr));
    uint32_t destination_ip = ip_header->ip_dst.s_addr;
    char use_default_route = 0;

    // Ensure the packet is IPv4, otherwise ignore it.
    if(ip_header->ip_v != 4) {
        return;
    }

    // Validate the IP checksum.
    u_short checksum = calculateChecksum((void *)ip_header, ip_header->ip_hl * 4 / 2);
    if(checksum != 0) {
        return;
    }

    // If TTL is 1, ignore the packet to prevent looping.
    if(ip_header->ip_ttl == 1) {
        return;
    }

    // Check if the destination IP matches any of the router's interfaces.
    struct sr_if* interface_iterator = 0;
    interface_iterator = sr->if_list;
    while(interface_iterator) {
	//DebugMAC(interface_iterator->addr);
        if(interface_iterator->ip == destination_ip) {
            process_icmp_packet_packet(sr, packet_data, packet_length, interface_name);
            return;
        }
        interface_iterator = interface_iterator->next;
    }

    // Find a route for the destination IP.
    struct sr_rt* routing_iterator = NULL, *default_route = NULL, *match = NULL;
    if(sr->routing_table == 0) {
        printf(" *warning* Routing table empty \n");
        return;
    }

    routing_iterator = sr->routing_table;
    while(routing_iterator) {
        if(routing_iterator->dest.s_addr == 0) {
            default_route = routing_iterator;
        } else if((destination_ip & routing_iterator->mask.s_addr) == 
                  (routing_iterator->dest.s_addr & routing_iterator->mask.s_addr)) {
           if(match == NULL || routing_iterator->mask.s_addr > match->mask.s_addr) {
			   match = routing_iterator;
			   }
        }
        routing_iterator = routing_iterator->next;
    }

    // Use the default route if no specific route is found.
    if(match == NULL && default_route != NULL) {
        match = default_route;
        destination_ip = match->gw.s_addr;
        use_default_route = 1;
    }
    else if(match == NULL) {
    	return;
    } else if(match->gw.s_addr != 0) {
	    destination_ip = match->gw.s_addr;
    }

    // Check ARP cache for MAC address.
    IP_Mac_Mapping *arp_cache_iterator = &arp_head;
    while(arp_cache_iterator != NULL) {
        unsigned char *mac_address = findMacAddress(arp_cache_iterator, destination_ip);
        if(mac_address != NULL) {
            --ip_header->ip_ttl;

            // Recalculate IP checksum.
            ip_header->ip_sum = 0;
            checksum = calculateChecksum((void *)ip_header, ip_header->ip_hl * 4 / 2);
            ip_header->ip_sum = checksum;

            // Ensure the checksum is valid.
            checksum = calculateChecksum((void *)ip_header, ip_header->ip_hl * 4 / 2);
            if(checksum != 0) {
                return;
            }

            // Update Ethernet header and send the packet.
            struct sr_if* interface_info = sr_get_interface(sr, match->interface);
            memcpy(ethernet_header->ether_shost, interface_info->addr, sizeof(ethernet_header->ether_shost));
            memcpy(ethernet_header->ether_dhost, mac_address, sizeof(ethernet_header->ether_dhost));

            int send_status = sr_send_packet(sr, packet_data, packet_length, match->interface);
            assert(send_status == 0);
            return;
        }
        arp_cache_iterator = arp_cache_iterator->next;
    }

    // If MAC address is not in ARP cache, buffer the packet and send an ARP request.
    if(arp_cache_iterator == NULL) {
        IP_Mac_Mapping_Buffer *buffer_check = find_buffer_by_ip(&buf_head, destination_ip);

        if(buffer_check == NULL) {
            buffer_check = insert_new_buffer_entry(&buf_head, destination_ip);
            enqueue_packet(buffer_check, packet_data, packet_length);
            if(use_default_route || match->gw.s_addr != 0) {
                transfer_arp_packet(sr, packet_data, match->interface, destination_ip);
            } else {
                transfer_arp_packet(sr, packet_data, match->interface, 0);
            }
        } else {
            enqueue_packet(buffer_check, packet_data, packet_length);
        }
    }
}
