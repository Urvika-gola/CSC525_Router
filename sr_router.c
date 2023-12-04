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

#include "network_topology_manager.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "IP_Mac_Mapping.h"
#include "IP_Mac_Mapping_Buffer.h"
#include "router_utilities.h"
#include "sr_pwospf.h"

/**
 * Handles PWOSPF (Project-Wide OSPF) protocol packets, processing both OSPF Hello and LSU packets.
 *
 * @param sr Pointer to the simple router instance.
 * @param packet Pointer to the packet data.
 * @param len Length of the packet.
 * @param interface Name of the interface through which the packet was received.
 */
void handle_pwospf(struct sr_instance* sr,
                   uint8_t * packet,
                   unsigned int len,
                   char* interface) {    

    // Extract OSPF header from the packet
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    // Process OSPF Hello or LSU packets
    if(ospf_hdr->type == OSPF_TYPE_HELLO) {
        (sr->ospf_subsys); // Locking OSPF subsystem
        handle_pwospf_hello(sr, packet, len, interface); // Handle OSPF Hello
        release_pwospf_lock(sr->ospf_subsys); // Unlocking OSPF subsystem
    }
    else if(ospf_hdr->type == OSPF_TYPE_LSU) {
        (sr->ospf_subsys); // Locking OSPF subsystem
        // Handle OSPF LSU and send updates if topology changes
        if(handle_pwospf_lsu(sr, packet, len, interface)) {
            broadcast_topology_updates(sr); // Send topology update
        }
        release_pwospf_lock(sr->ospf_subsys); // Unlocking OSPF subsystem
    }
}

/**
 * Processes PWOSPF LSU (Link State Update) packets.
 *
 * @param sr Pointer to the simple router instance.
 * @param packet Pointer to the packet data.
 * @param len Length of the packet.
 * @param interface Name of the interface through which the packet was received.
 * @return char Flag indicating if the routing table was updated.
 */
char handle_pwospf_lsu(struct sr_instance* sr,
                       uint8_t * packet,
                       unsigned int len,
                       char* interface) {

    // Extract Ethernet and IP headers
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr*) packet;
    struct ip *ip = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

    // LSU specific headers extraction
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr*) ((uint8_t *) ospf_hdr + sizeof(struct ospfv2_hdr));
    struct ospfv2_lsu *lsu_ad = (struct ospfv2_lsu*) ((uint8_t *) lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    // Check for incomplete ARP resolution
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; ++i) {
        if(eth->ether_dhost[i] != 0)
            break;
    }
    if(i == ETHER_ADDR_LEN) { // ARP resolution required
        // Resolve MAC address using ARP cache
        IP_Mac_Mapping *cache_temp = &(sr->arp_head);
        unsigned char *haddr = findMacAddress(cache_temp, ip->ip_dst.s_addr);
        if(haddr != NULL) {
            memcpy(eth->ether_dhost, haddr, sizeof(eth->ether_dhost));
            int rc = sr_send_packet(sr, packet, len, interface);
            assert(rc == 0);
        } else {
            struct in_addr ip_dest;
            ip_dest.s_addr = ip->ip_dst.s_addr;
            printf("NO ARP CACHE ENTRY EXISTS FOR IP %s, SHOULD NOT HAPPEN.\n", inet_ntoa(ip_dest));
        }
        return 0;
    }

    // Normal processing of OSPF LSU packet
    Router *router = findRouterById(&(sr->ospf_subsys->head_router), ospf_hdr->rid);
    char flag = 0;

    // Skip processing if packet is from the router itself
    if(sr_get_interface(sr, "eth0")->ip == ospf_hdr->rid) {
        return flag;
    }

    // Add router if it doesn't exist in the OSPF subsystem
    if(router == NULL) {
        router = addRouter(&(sr->ospf_subsys->head_router), ospf_hdr->rid);
        struct sr_if *iface = sr_get_interface(sr, interface);
        iface->neighbor_ip = ip->ip_src.s_addr;
        iface->neighbor_rid = ospf_hdr->rid;
        iface->up = 1;

        // Update next hops in routing table
        struct sr_rt* rt_walker = sr->routing_table;
        while(rt_walker) {
            if(strcmp(rt_walker->interface, iface->name) == 0)
                rt_walker->gw.s_addr = iface->neighbor_ip;
            rt_walker = rt_walker->next;
        }
        flag = 1;
    }

    // Skip outdated LSU packets
    if(lsu_hdr->seq <= router->seq) {
        return flag;
    }

    // Clear existing links and add new links from LSU
    clearAllLinksFromRouter(router);
    for(i = 0; i < lsu_hdr->num_adv; ++i) {       
        if(lsu_ad->rid == 0)
            appendLinkToRouter(router, lsu_ad->subnet, lsu_ad->mask, ospf_hdr->rid);
        else
            appendLinkToRouter(router, lsu_ad->subnet, lsu_ad->mask, lsu_ad->rid);

        lsu_ad = (struct ospfv2_lsu *) ((uint8_t *) lsu_ad + sizeof(struct ospfv2_lsu));
    }
  
    // Recalculate routing table if required
    recalculate_routing_table(sr);

    return flag;
}

/**
 * Handles the reception of an OSPF Hello packet.
 * This function is responsible for processing Hello packets in the OSPF protocol, 
 * updating the router information, and sending updates if there's a change in the topology.
 *
 * @param sr Pointer to the simple router instance.
 * @param packet Pointer to the packet data.
 * @param len Length of the packet.
 * @param interface Name of the interface through which the packet was received.
 */
void handle_pwospf_hello(struct sr_instance* sr,
                         uint8_t * packet,
                         unsigned int len,
                         char* interface)
{
    // Extract IP and OSPF headers from the packet
    struct ip *ip = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    // printf("Hello received from router: %u\n", ospf_hdr->rid);

    // Find the router by ID in the OSPF subsystem
    Router *router = findRouterById(&(sr->ospf_subsys->head_router), ospf_hdr->rid);

    // If a new router is discovered
    if(router == NULL) {
        // Add the new router to the OSPF subsystem
        router = addRouter(&(sr->ospf_subsys->head_router), ospf_hdr->rid);

        // Update interface information with neighbor details
        struct sr_if *iface = sr_get_interface(sr, interface);
        iface->neighbor_ip = ip->ip_src.s_addr;
        iface->neighbor_rid = ospf_hdr->rid;
        iface->up = 1;
        // printf("Hello received from router: %u\n", iface->neighbor_ip);

        // Update the next hop in the routing table if necessary
        struct sr_rt* rt_walker = sr->routing_table;
        while(rt_walker) {
            if(strcmp(rt_walker->interface, iface->name) == 0) {
                rt_walker->gw.s_addr = iface->neighbor_ip;
            }
            rt_walker = rt_walker->next;
        }
        // Send updates due to topology change
        broadcast_topology_updates(sr);
    } else {
        // Update the timestamp of the existing router
        updateTime(router);
    }
}
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

    sr->arp_head.next = NULL;
    sr->buf_head.next = NULL;
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
    memset(ethernetHeader->ether_dhost, 0xFF, ETHER_ADDR_LEN); 
    ethernetHeader->ether_type = htons(ETHERTYPE_ARP);
    // Set ARP header fields.
    arpHeader->ar_hrd = htons(ARPHDR_ETHER);
    arpHeader->ar_pro = htons(ETHERTYPE_IP);
    arpHeader->ar_hln = 6;
    arpHeader->ar_pln = 4;
    arpHeader->ar_op = htons(ARP_REQUEST);

    // Find the interface to use for sending the ARP request.
    struct sr_if* if_walker = sr->if_list;
    while(if_walker)
    {
        if(strncmp(interface, if_walker->name, sizeof(if_walker->name)) == 0)
            break;
        if_walker = if_walker->next;
    }

    // Set source MAC and IP addresses in the ARP header.
    memcpy(ethernetHeader->ether_shost, if_walker->addr, sizeof(ethernetHeader->ether_shost));
    arpHeader->ar_sip = if_walker->ip;
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
         struct sr_if* if_walker = 0;
        // Ensure the interface list is not empty.
        if(sr->if_list == 0)
        {
            printf(" Interface list empty \n");
            return;
        }

        // Find the interface that matches the target IP of the ARP request.
        if_walker = sr->if_list;
        while(if_walker != NULL)
        {
            // If interface found, prepare ARP reply.
            if(if_walker->ip == arpHeader->ar_tip) {
                arpHeader->ar_op = ntohs(2);
                memcpy(arpHeader->ar_tha, arpHeader->ar_sha, sizeof(arpHeader->ar_tha));
                memcpy(arpHeader->ar_sha, if_walker->addr, sizeof(arpHeader->ar_sha));
                uint32_t temp = arpHeader->ar_tip;
                arpHeader->ar_tip = arpHeader->ar_sip;
                arpHeader->ar_sip = temp;
                memcpy(ethernetHeader->ether_dhost, ethernetHeader->ether_shost, sizeof(ethernetHeader->ether_dhost));
                memcpy(ethernetHeader->ether_shost, arpHeader->ar_sha, sizeof(arpHeader->ar_sha));
                int rc = sr_send_packet(sr, packet, len, interface);
                assert(rc == 0);
                break;
            }
            if_walker = if_walker->next;
        }

        if(if_walker->next == NULL) {
            struct in_addr temp;
            temp.s_addr = arpHeader->ar_sip;
            temp.s_addr = arpHeader->ar_tip;
        }
    } 
    // Handle ARP reply.
    else if (arpHeader->ar_op == ntohs(2)) {
        // Find buffer entry for the source IP of the ARP reply.
        IP_Mac_Mapping_Buffer *currentBuffer = find_buffer_by_ip(&(sr->buf_head), arpHeader->ar_sip);

        // If no buffer entry found, ignore the ARP reply.
        if(currentBuffer == NULL)
            return;

        // Add the sender's IP and MAC address to the ARP cache.
        addMapping(&(sr->arp_head), arpHeader->ar_sip, arpHeader->ar_sha);

        // Process buffered packets waiting for this ARP reply.
        unsigned int bufferedPacketLen = 0;
        uint8_t *bufferedPacket = dequeue_packet(currentBuffer, &bufferedPacketLen);
        while(bufferedPacket != NULL) {
            //struct ip *ipHeader = (struct ip*) (bufferedPacket + sizeof(struct sr_ethernet_hdr));
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

    if(ip_header->ip_p == IPROTO_OSPF) {
        handle_pwospf(sr, packet_data, packet_length, interface_name); 
        return;
    }

    // Check if the destination IP matches any of the router's interfaces.
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;
    while(if_walker) {
	//DebugMAC(interface_iterator->addr);
        if(if_walker->ip == destination_ip) {
            process_icmp_packet_packet(sr, packet_data, packet_length, interface_name);
            return;
        }
        if_walker = if_walker->next;
    }

    (sr->ospf_subsys);
    struct sr_rt* rt_walker = NULL, *default_route = NULL, *match = NULL;
    if(sr->routing_table == 0) {
        release_pwospf_lock(sr->ospf_subsys);
        return;
    }

    rt_walker = sr->routing_table;
    while(rt_walker) {
        if(rt_walker->dest.s_addr == 0) {
            default_route = rt_walker;
        } else if((destination_ip & rt_walker->mask.s_addr) == 
                  (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
           if(match == NULL || rt_walker->mask.s_addr > match->mask.s_addr) {
			   match = rt_walker;
			   }
        }
        rt_walker = rt_walker->next;
    }
    release_pwospf_lock(sr->ospf_subsys);

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
    IP_Mac_Mapping *arp_cache_iterator =&(sr->arp_head);
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
        IP_Mac_Mapping_Buffer *buffer_check = find_buffer_by_ip(&(sr->buf_head), destination_ip);

        if(buffer_check == NULL) {
            buffer_check = insert_new_buffer_entry(&(sr->buf_head), destination_ip);
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
