#ifndef NETWORK_TOPOLOGY_MANAGER
#define NETWORK_TOPOLOGY_MANAGER

#include <time.h>
#include <stdint.h>

// Structure representing a network link
typedef struct Link {    
    uint32_t ip;          // IP address of the link
    uint32_t mask;        // Network mask of the link
    uint32_t rid;         // Router ID in the adjacency list
    struct Link *next;    // Pointer to the next link in the list
} Link;

// Structure representing a router in the network
typedef struct Router {
    time_t time;          // Timestamp for the router
    uint32_t rid;         // Router ID
    Link head;            // Head of the linked list of links
    uint16_t seq;         // Sequence number (used for tracking updates)
    char traversed;       // Flag to mark if the router has been traversed
    struct Router *next;  // Pointer to the next router in the list
} Router;

// Function Prototypes

/**
 * Checks if a router with the given ID exists in the network.
 * @param head Pointer to the head of the router list.
 * @param rid The router ID to search for.
 * @return Pointer to the found router, or NULL if not found.
 */
Router *findRouterById(Router *head, uint32_t rid);

/**
 * Deletes a router with the specified ID from the network.
 * @param head Pointer to the head of the router list.
 * @param rid The router ID of the router to be deleted.
 */
void removeRouterById(Router *head, uint32_t rid);

/**
 * Inserts a new router with the specified ID into the network.
 * @param head Pointer to the head of the router list.
 * @param rid The router ID of the new router.
 * @return Pointer to the newly inserted router.
 */
Router *addRouter(Router *head, uint32_t rid);
/**
 * Updates the timestamp of a given router.
 * @param spot Pointer to the router whose timestamp is to be updated.
 */
void updateTime(Router *spot);

/**
 * Adds a new link to a specified router in the network.
 * @param spot Pointer to the router to which the link is to be added.
 * @param ip IP address of the new link.
 * @param mask Network mask of the new link.
 * @param rid Router ID associated with the new link.
 */
void appendLinkToRouter(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);

/**
 * Removes a specified link from a router in the network.
 * @param spot Pointer to the router from which the link is to be removed.
 * @param ip IP address of the link to be removed.
 * @param mask Network mask of the link to be removed.
 * @param rid Router ID associated with the link to be removed.
 */
void detachLinkFromRouter(Router *spot, uint32_t ip, uint32_t mask, uint32_t rid);
/**
 * Removes all links from a specified router in the network.
 * @param spot Pointer to the router from which all links are to be removed.
 */
void clearAllLinksFromRouter(Router *spot);
/**
 * Finds a specific link associated with a given router in the network.
 * @param head Pointer to the head of the router list.
 * @param rid Router ID to search for the link.
 * @param ip IP address of the link.
 * @param mask Network mask of the link.
 * @return Pointer to the found link, or NULL if not found.
 */
Link *locateLinkInRouter(Router *head, uint32_t rid, uint32_t ip, uint32_t mask);

#endif // NETWORK_TOPOLOGY_MANAGER
