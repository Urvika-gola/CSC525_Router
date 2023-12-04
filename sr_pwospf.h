/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>

#include "network_topology_manager.h"

#ifndef IPROTO_OSPF 
#define IPROTO_OSPF 89
#endif

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */
    Router head_router;
    uint32_t curr_seq;

    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);

/**
 * Acquires the lock for the PWOSPF subsystem to ensure thread safety.
 *
 * @param subsys Pointer to the PWOSPF subsystem.
 */
void acquire_pwospf_lock(struct pwospf_subsys* subsys);

/**
 * Releases the lock for the PWOSPF subsystem.
 *
 * @param subsys Pointer to the PWOSPF subsystem.
 */
void release_pwospf_lock(struct pwospf_subsys* subsys);

/**
 * Sends topology updates to neighboring routers.
 *
 * @param sr Pointer to the simple router instance.
 */
void broadcast_topology_updates(struct sr_instance* sr);

/**
 * Sends OSPF Hello packets to all neighbors.
 *
 * @param sr Pointer to the simple router instance.
 * @param packet Pointer to the OSPF packet.
 * @param len Length of the OSPF packet.
 */
void send_hello_to_neighbors(struct sr_instance* sr, uint8_t *packet, uint32_t len);

/**
 * Checks for router timeouts and updates PWOSPF subsystem accordingly.
 *
 * @param sr Pointer to the simple router instance.
 * @return char Status indicating if a timeout occurred.
 */
char check_for_router_timeout(struct sr_instance* sr);

/**
 * Recalculates the routing table for the router instance.
 *
 * @param sr Pointer to the simple router instance.
 */
void recalculate_routing_table(struct sr_instance* sr);

#endif /* SR_PWOSPF_H */





