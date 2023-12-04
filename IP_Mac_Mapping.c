#include<stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "sr_router.h"
#include "IP_Mac_Mapping.h"

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
void addMapping(IP_Mac_Mapping *listHead, uint32_t ipAddress, unsigned char* macAddress) {
    // Allocate memory for the new mapping node
    IP_Mac_Mapping *newMapping = (IP_Mac_Mapping *)malloc(sizeof(IP_Mac_Mapping));

    // Initialize the new mapping with the provided IP and MAC address
    newMapping->ip = ipAddress;
    memcpy(newMapping->addr, macAddress, sizeof(newMapping->addr));
    
    // Insert the new mapping node at the beginning of the linked list
    IP_Mac_Mapping *temporary = listHead->next;
    listHead->next = newMapping;
    newMapping->next = temporary;
}

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
unsigned char* findMacAddress(IP_Mac_Mapping *listHead, uint32_t ipAddress) {
    IP_Mac_Mapping *currentMapping;
    // Traverse the linked list to find the node with the specified IP address
    for(currentMapping = listHead;
        currentMapping->next != NULL && (currentMapping->next)->ip != ipAddress;
        currentMapping = currentMapping->next);
    
    // If the IP address is found, return the corresponding MAC address
    if(currentMapping->next != NULL) {
        return currentMapping->next->addr;
    }
    
    // If not found, return NULL
    return NULL;
}
