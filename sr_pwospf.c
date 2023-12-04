/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "router_utilities.h"
#include "sr_router.h"


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

/**
 * Checks for router timeouts in the PWOSPF subsystem and updates the routing table and interfaces accordingly.
 *
 * @param sr Pointer to the simple router instance.
 * @return char Flag indicating if any router has timed out (1 if timed out, 0 otherwise).
 */
char check_for_router_timeout(struct sr_instance* sr) {
    char flag = 0; // Flag to indicate if any router has timed out
    Router *curr_router = &(sr->ospf_subsys->head_router);
    time_t curr_time = time(0); // Current time for timeout calculation


    // Iterate through all routers in the PWOSPF subsystem
    while(curr_router->next != NULL) {
        // Check if the router has timed out (10 seconds in this case)
        if(curr_time - curr_router->next->time >= 10) {
            // Get the corresponding interface for the timed-out router
            struct sr_if *iface = sr_get_interface_neighbor_rid(sr, curr_router->next->rid);
            iface->up = 0; // Mark interface as down
            iface->neighbor_ip = 0; // Reset neighbor IP
            iface->neighbor_rid = 0; // Reset neighbor router ID


            // Remove relevant entries from the routing table
            struct sr_rt *curr_rt = sr->routing_table, *temp = NULL;
            while(strcmp(curr_rt->interface, iface->name) == 0 && !(curr_rt->static_flag)) {
                temp = curr_rt;
                sr->routing_table = temp->next; // Remove the routing table entry
                curr_rt = sr->routing_table;
                flag = 1; // Set flag as a router has timed out
                free(temp); // Free the removed routing table entry
            }


            // Continue removing entries from the routing table
            while(curr_rt->next != NULL) {
                if(strcmp(curr_rt->next->interface, iface->name) == 0 && !(curr_rt->next->static_flag)) {
                    temp = curr_rt->next;
                    curr_rt->next = temp->next; // Remove the next routing table entry
                    free(temp); // Free the removed entry
                    flag = 1; // Set flag as a router has timed out
                } else {
                    curr_rt = curr_rt->next;
                }
            }


            // Remove the router from the PWOSPF subsystem
            removeRouterById(&(sr->ospf_subsys->head_router), curr_router->next->rid);
        } else {
            // Move to the next router if no timeout
            curr_router = curr_router->next;
        }
    }
    return flag; // Return the flag indicating if any router has timed out
}

/**
 * Recalculates the routing table based on the current state of the network interfaces and OSPF information.
 *
 * @param sr Pointer to the simple router instance.
 */
void recalculate_routing_table(struct sr_instance* sr) {
    struct sr_if* if_walker = sr->if_list; // Walker for the list of interfaces
    struct sr_rt* rt_walker = sr->routing_table; // Walker for the routing table

    // Iterate over all network interfaces
    while(if_walker != NULL) {
        // Skip the interface if it's down
        if(!(if_walker->up)) {
            if_walker = if_walker->next;
            continue;
        }

        // Check if the interface's network is already in the routing table
        rt_walker = sr->routing_table;
        while(rt_walker != NULL) {
            if((if_walker->mask & if_walker->ip) == (rt_walker->mask.s_addr & rt_walker->dest.s_addr) && if_walker->mask > 0) {
                break;
            }
            rt_walker = rt_walker->next;
        }

        // Add a new routing table entry if the network is not present
        if(rt_walker == NULL) {
            struct in_addr dest, gw, mask;
            dest.s_addr = if_walker->ip;
            gw.s_addr = if_walker->neighbor_ip;
            mask.s_addr = if_walker->mask;
            sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
        }

        if_walker = if_walker->next;
    }

    // Iterate over the interfaces again for OSPF related updates
    if_walker = sr->if_list;
    while(if_walker != NULL) {
        // Skip interfaces without an OSPF neighbor
        if(if_walker->neighbor_rid == 0) {
            if_walker = if_walker->next;
            continue;
        }

        // Find the corresponding router in the OSPF subsystem
        Router *router = findRouterById(&(sr->ospf_subsys->head_router), if_walker->neighbor_rid);
        if(router == NULL) {
            if_walker = if_walker->next;
            continue;
        }

        // Iterate over the links of the router
        Link *curr_link = router->head.next;
        while(curr_link != NULL) {
            // Skip the link if it corresponds to the router's own interface
            if(curr_link->rid == sr_get_interface(sr, "eth0")->ip) {
                curr_link = curr_link->next;
                continue;
            }

            // Check if the link's network is already in the routing table
            rt_walker = sr->routing_table;
            while(rt_walker != NULL) {
                if((curr_link->mask & curr_link->ip) == (rt_walker->mask.s_addr & rt_walker->dest.s_addr)) {
                    // Update the routing table entry if necessary
                    struct sr_if *temp_iface = sr_get_interface(sr, rt_walker->interface);
                    if(curr_link->rid == temp_iface->neighbor_rid) {
                        break;
                    }

                    // Skip static entries and entries without a gateway
                    if(rt_walker->gw.s_addr == 0 || rt_walker->static_flag) {
                        break;
                    }

                    // Locate the link in the router
                    Link *temp_link = locateLinkInRouter(&(sr->ospf_subsys->head_router), temp_iface->neighbor_rid, rt_walker->dest.s_addr, rt_walker->mask.s_addr);
                    if(temp_link != NULL && temp_link->rid == curr_link->rid) {
                        // Update the routing table entry
                        rt_walker->dest.s_addr = curr_link->ip;
                        rt_walker->mask.s_addr = curr_link->mask;
                        rt_walker->gw.s_addr = if_walker->neighbor_ip;
                        memcpy(rt_walker->interface, if_walker->name, sizeof(char) * SR_IFACE_NAMELEN);
                    }
                    break;
                }
                rt_walker = rt_walker->next;
            }

            // Add a new entry to the routing table if necessary
            if(rt_walker == NULL) {
                struct in_addr dest, gw, mask;
                dest.s_addr = curr_link->ip;
                gw.s_addr = if_walker->neighbor_ip;
                mask.s_addr = curr_link->mask;
                sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
            }
            curr_link = curr_link->next;
        }

        if_walker = if_walker->next;
    }
}

/**
 * Broadcasts topology updates to all neighboring routers in the OSPF network.
 * 
 * @param sr Pointer to the simple router instance.
 */
void broadcast_topology_updates(struct sr_instance *sr) {
    struct sr_if* if_walker = sr->if_list; // Interface list walker
    struct sr_rt* rt_walker = sr->routing_table; // Routing table walker
    int ad_count = 0; // Count of advertisements

    // Count the number of routing table entries
    while(rt_walker != NULL) {
        ad_count++;
        rt_walker = rt_walker->next;
    }

    // Calculate length of LSU (Link State Update) packet
    uint32_t lsu_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + (ad_count * sizeof(struct ospfv2_lsu));
    uint8_t *lsu_packet = (uint8_t *) calloc(lsu_len, sizeof(uint8_t)); // Allocate memory for LSU packet

    // Construct Ethernet header
    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) lsu_packet;
    eth->ether_type = ntohs(ETHERTYPE_IP);

    // Construct IP header
    struct ip *ip = (struct ip*) (lsu_packet + sizeof(struct sr_ethernet_hdr));
    ip->ip_v = 4; // IPv4
    ip->ip_hl = 5; // Header length
    ip->ip_tos = 0; // Type of service
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu));
    ip->ip_id = 0; // ID field
    ip->ip_off = 0; // Fragment offset
    ip->ip_ttl = 255; // Time to live
    ip->ip_p = IPROTO_OSPF; // OSPF protocol

    // Construct OSPF header
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *) ((uint8_t *) ip + sizeof(struct ip));
    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = OSPF_TYPE_LSU;
    ospf_hdr->len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu);
    ospf_hdr->rid = sr_get_interface(sr, "eth0")->ip; // Router ID
    ospf_hdr->aid = 0; // Area ID
    ospf_hdr->autype = 0; // Authentication type
    ospf_hdr->audata = 0; // Authentication data

    // Construct OSPF LSU header
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *) ((uint8_t *) ospf_hdr + sizeof(struct ospfv2_hdr));
    lsu_hdr->seq = sr->ospf_subsys->curr_seq; // Sequence number
    sr->ospf_subsys->curr_seq++; // Increment sequence number
    lsu_hdr->ttl = 255; // TTL for LSU
    lsu_hdr->num_adv = ad_count; // Number of advertisements

    // Populate LSU advertisements
    struct ospfv2_lsu *lsu_ad = (struct ospfv2_lsu *) ((uint8_t *) lsu_hdr + sizeof(struct ospfv2_lsu_hdr));
    rt_walker = sr->routing_table;
    while(rt_walker) {
        lsu_ad->subnet = rt_walker->dest.s_addr;
        lsu_ad->mask = rt_walker->mask.s_addr;
        lsu_ad->rid = sr_get_interface(sr, rt_walker->interface)->neighbor_rid;
        lsu_ad = (uint8_t *) lsu_ad + sizeof(struct ospfv2_lsu);
        rt_walker = rt_walker->next;
    }

    // Broadcast LSU packet to all neighbors
    if_walker = sr->if_list;
    while(if_walker) {
        if(if_walker->neighbor_ip == 0) {
            if_walker = if_walker->next;
            continue;
        }

        // Set source and destination MAC addresses
        memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));
        uint32_t dest_ip = if_walker->neighbor_ip;
        ip->ip_src.s_addr = if_walker->ip;
        ip->ip_dst.s_addr = dest_ip;

        // Calculate checksums for IP and OSPF headers
        ip->ip_sum = 0;
        ip->ip_sum = calculateChecksum((void *) ip, ip->ip_hl * 4 / 2);
        ospf_hdr->csum = 0;
        ospf_hdr->csum = calculateChecksum((void *) ospf_hdr, (sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + ad_count * sizeof(struct ospfv2_lsu)) / 2);

        // Check ARP cache and send packet
        IP_Mac_Mapping *cache_temp = &(sr->arp_head);
        while(cache_temp != NULL) {
            unsigned char *haddr = findMacAddress(cache_temp, dest_ip);
            if(haddr != NULL) {
                memcpy(eth->ether_dhost, haddr, sizeof(eth->ether_dhost));
                memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));
                int rc = sr_send_packet(sr, lsu_packet, lsu_len, if_walker->name);
                assert(rc == 0);
            }
            cache_temp = cache_temp->next;
        }

        // Handle ARP buffer if necessary
        if(cache_temp == NULL) {
            IP_Mac_Mapping_Buffer *check_buf = find_buffer_by_ip(&(sr->buf_head), dest_ip);
            if(check_buf == NULL) {
                check_buf = insert_new_buffer_entry(&(sr->buf_head), dest_ip);
                enqueue_packet(check_buf, lsu_packet, lsu_len);
                transfer_arp_packet(sr, lsu_packet, if_walker->name, dest_ip);
            } else {
                enqueue_packet(check_buf, lsu_packet, lsu_len);
            }
        }

        if_walker = if_walker->next;
    } 

    // Free allocated packet memory
    free(lsu_packet);
}



/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    uint32_t hello_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
    uint8_t hello_packet[hello_len];

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) hello_packet;
    // make destination MAC bits all 1
    for(int i = 0; i < ETHER_ADDR_LEN; ++i)
        eth->ether_dhost[i] = ~(eth->ether_dhost[i] & 0);
    eth->ether_type = ntohs(ETHERTYPE_IP);

    // INITIALIZE IP HEADER START **********
    struct ip *ip = (struct ip*) (hello_packet + sizeof(struct sr_ethernet_hdr));
    ip->ip_v = 4;
    ip->ip_hl=5;
    ip->ip_tos=0; //normal
    ip->ip_len=htons(sizeof(struct ip)+ sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    ip->ip_id=0;
    ip->ip_off=0;
    ip->ip_ttl=255;// max ttl put here
    ip->ip_p = IPROTO_OSPF;
    ip->ip_dst.s_addr = htonl(OSPF_AllSPFRouters); //244.0.0.5
    // INITIALIZE IP HEADER END   **********


    // INITIALIZE OSPF HEADER START ********
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *) ((uint8_t *) ip + sizeof(struct ip));
    //(hello_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    ospf_hdr->version = (OSPF_V2);
    ospf_hdr->type = OSPF_TYPE_HELLO;
    ospf_hdr->len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
    ospf_hdr->rid = sr_get_interface(sr, "eth0")->ip; 
    ospf_hdr->aid = 0;
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0; 

    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *) ((uint8_t *) ospf_hdr + sizeof(struct ospfv2_hdr));
    //(ospf_hdr + sizeof(struct ospfv2_hdr));
    hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;
    // INITIALIZE OSPF HEADER END   ********

    int hello_cnt = 0, update_cnt = 0;
    char need_update = 0;
    while(1) {
        need_update = 0;
        (sr->ospf_subsys);
        need_update = check_for_router_timeout(sr);

        if(hello_cnt % OSPF_DEFAULT_HELLOINT == 0) {
            hello_cnt = 0;
            send_hello_to_neighbors(sr, hello_packet, hello_len);
        }
        if(update_cnt % OSPF_DEFAULT_LSUINT == 0 || need_update) {
            broadcast_topology_updates(sr);
            update_cnt = 0;
        }

        //printf("Done checking timeout.\n");
        if(need_update)
            recalculate_routing_table(sr);

        release_pwospf_lock(sr->ospf_subsys);
        sleep(1);
        hello_cnt++;
        update_cnt++;

    };

    free(hello_packet);

    return NULL;
} /* -- run_ospf_thread -- */



void send_hello_to_neighbors(struct sr_instance *sr, uint8_t *packet, uint32_t len) {
    //going through the interface list,
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *) packet;
    struct ip *ip = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *) ((uint8_t *) ip + sizeof(struct ip));
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *) ((uint8_t *) ospf_hdr + sizeof(struct ospfv2_hdr));


    while(if_walker) {
        memcpy(eth->ether_shost, if_walker->addr, sizeof(eth->ether_shost));
        ip->ip_src.s_addr = if_walker->ip; 
        ip->ip_sum = 0;
        ip->ip_sum = calculateChecksum((void *) ip, ip->ip_hl * 4 / 2); //put it as blank for now

        hello_hdr->nmask = if_walker->mask; // set when sending hello
        ospf_hdr->csum = 0;
        ospf_hdr->csum = calculateChecksum((void *) ospf_hdr, (sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr)) / 2); //need to figure out how to calculate this, likely happens before send
        int rc = sr_send_packet(sr, packet, len, if_walker->name);
        assert(rc == 0);
        if_walker = if_walker->next; 
    }  
}





int pwospf_init(struct sr_instance* sr) {
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);


    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->head_router.next = NULL;
    sr->ospf_subsys->head_router.head.next = NULL;
    sr->ospf_subsys->curr_seq = 1;

    // initialize routing table
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    // need to set static to 0
    struct sr_rt *rt_walker = sr->routing_table;
    while(rt_walker != NULL) {
        rt_walker->static_flag = 1;
        rt_walker = rt_walker->next;
    } 

    struct in_addr dest, gw, mask;
    while(if_walker) {
        dest.s_addr = if_walker->ip;
        gw.s_addr = 0;
        mask.s_addr = if_walker->mask;
        if(!interface_exists(sr, if_walker->name)) {
            sr_add_rt_entry(sr, dest, gw, mask, if_walker->name);
        }
        if_walker = if_walker->next; 
    }  


    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


void acquire_pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
    //printf("Locking.\n");
} /* -- pwospf_subsys -- */


void release_pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
    //printf("Unlocking.\n");
} /* -- pwospf_subsys -- */