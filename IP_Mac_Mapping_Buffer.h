#ifndef IP_MAC_MAPPING_BUFFER
#define IP_MAC_MAPPING_BUFFER
#include <stdint.h>

// Define a structure to represent a waiting list node.
typedef struct Waiting_List {
    uint8_t *packet;          // Pointer to the packet data.
    unsigned int len;         // Length of the packet data.
    struct Waiting_List *next; // Pointer to the next node in the waiting list.
} Waiting_List;

// Define a structure to represent an ARP buffer node.
typedef struct IP_Mac_Mapping_Buffer {
    uint32_t ip;              // IP address associated with this buffer node.
    Waiting_List head;        // Head of the waiting list associated with this buffer node.
    struct IP_Mac_Mapping_Buffer *next;  // Pointer to the next buffer node in the linked list.
} IP_Mac_Mapping_Buffer;

/**
 * @brief Find a buffer node by IP address in a linked list.
 * 
 * @param buffer_head Pointer to the head of the ARP buffer linked list.
 * @param target_ip The IP address to search for in the linked list.
 * @return IP_Mac_Mapping_Buffer* Returns a pointer to the found buffer node, or NULL if not found.
 */
IP_Mac_Mapping_Buffer *find_buffer_by_ip(IP_Mac_Mapping_Buffer *buffer_head, uint32_t target_ip);

/**
 * @brief Insert a new buffer entry at the beginning of the linked list.
 * 
 * @param buffer_head Pointer to the head of the ARP buffer linked list.
 * @param ip_address The IP address to be stored in the new buffer node.
 * @return IP_Mac_Mapping_Buffer* Returns a pointer to the newly created buffer node.
 */
IP_Mac_Mapping_Buffer *insert_new_buffer_entry(IP_Mac_Mapping_Buffer *buffer_head, uint32_t ip_address);

/**
 * @brief Dequeue a packet from the waiting list of a given ARP buffer.
 * 
 * @param target_buffer Pointer to the ARP buffer from which the packet should be dequeued.
 * @param packet_length Pointer to a variable where the length of the dequeued packet will be stored.
 * @return uint8_t* Returns a pointer to the dequeued packet data, or NULL if the waiting list is empty.
 */
uint8_t *dequeue_packet(IP_Mac_Mapping_Buffer *target_buffer, unsigned int *packet_length);

/**
 * @brief Enqueue a packet into the waiting list of a given ARP buffer.
 * 
 * @param target_buffer Pointer to the ARP buffer where the packet should be enqueued.
 * @param packet Pointer to the packet data to be enqueued.
 * @param packet_length Length of the packet data.
 */
void enqueue_packet(IP_Mac_Mapping_Buffer *target_buffer, uint8_t *packet, unsigned int packet_length);

#endif // IP_Mac_Mapping_Buffer_H





