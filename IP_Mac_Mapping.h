/**
 * @file IP_Mac_Mapping.h
 * @brief Provides functionality for managing IP to MAC address mappings.
 */

#ifndef IP_MAC_MAPPING
#define IP_MAC_MAPPING

/**
 * @struct IP_Mac_Mapping
 * @brief A structure to hold mappings from IP addresses to MAC addresses.
 *
 * This structure represents a node in a linked list where each node
 * contains an IP address, a corresponding MAC address, and a pointer
 * to the next node in the list.
 */
typedef struct IP_Mac_Mapping {
    uint32_t ip;  ///< The IP address.
    unsigned char addr[6];  ///< The MAC address.
    struct IP_Mac_Mapping *next;  ///< Pointer to the next mapping in the list.
} IP_Mac_Mapping;

/**
 * @brief Adds a new IP to MAC address mapping to the list.
 *
 * This function creates a new IP_Mac_Mapping node, sets its IP and MAC address
 * to the provided values, and inserts it at the beginning of the linked list.
 *
 * @param listHead Pointer to the head of the linked list.
 * @param ipAddress The IP address to be added.
 * @param macAddress The MAC address to be added.
 */
void addMapping(IP_Mac_Mapping *listHead, uint32_t ipAddress, unsigned char* macAddress);

/**
 * @brief Finds the MAC address corresponding to an IP address in the list.
 *
 * This function traverses the linked list to find a node containing the
 * provided IP address and returns the corresponding MAC address.
 *
 * @param listHead Pointer to the head of the linked list.
 * @param ipAddress The IP address to find.
 * @return Pointer to the MAC address, or NULL if the IP address was not found.
 */
unsigned char* findMacAddress(IP_Mac_Mapping *listHead, uint32_t ipAddress);
#endif
