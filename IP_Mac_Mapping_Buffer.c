#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "IP_Mac_Mapping_Buffer.h"



/**
 * @brief Find a buffer node by IP address in a linked list.
 * 
 * @param buffer_head Pointer to the head of the ARP buffer linked list.
 * @param target_ip The IP address to search for in the linked list.
 * @return IP_Mac_Mapping_Buffer* Returns a pointer to the found buffer node, or NULL if not found.
 */
IP_Mac_Mapping_Buffer *find_buffer_by_ip(IP_Mac_Mapping_Buffer *buffer_head, uint32_t target_ip) {
    IP_Mac_Mapping_Buffer *current_buffer = buffer_head;
    // Get the current buffer
    while(current_buffer->next != NULL && (current_buffer->next)->ip != target_ip) {
        // Moving the current pointer to next if the target IP nott found
        current_buffer = current_buffer->next;
    }
    if(current_buffer->next != NULL) {
	//We have successfully found the buffer
        return current_buffer->next; 
    }
    return NULL;//Buffer not found
}

/**
 * @brief Insert a new buffer entry at the beginning of the linked list.
 * 
 * @param buffer_head Pointer to the head of the ARP buffer linked list.
 * @param ip_address The IP address to be stored in the new buffer node.
 * @return IP_Mac_Mapping_Buffer* Returns a pointer to the newly created buffer node.
 * @note This function dynamically allocates memory for the new buffer node using malloc. 
 */

IP_Mac_Mapping_Buffer *insert_new_buffer_entry(IP_Mac_Mapping_Buffer *buffer_head, uint32_t ip_address) {
    IP_Mac_Mapping_Buffer *new_buffer = (IP_Mac_Mapping_Buffer *) malloc(sizeof(IP_Mac_Mapping_Buffer));
    new_buffer->ip = ip_address;
    new_buffer->head.next = NULL;
    IP_Mac_Mapping_Buffer *next_buffer = buffer_head->next;
    buffer_head->next = new_buffer;
    new_buffer->next = next_buffer;
    return new_buffer;
}

/**
 * @brief Dequeue a packet from the waiting list of a given ARP buffer.
 * 
 * @param target_buffer Pointer to the ARP buffer from which the packet should be dequeued.
 * @param packet_length Pointer to a variable where the length of the dequeued packet will be stored.
 * @return uint8_t* Returns a pointer to the dequeued packet data, or NULL if the waiting list is empty.
 */
uint8_t *dequeue_packet(IP_Mac_Mapping_Buffer *target_buffer, unsigned int *packet_length) {
    Waiting_List *next_waiting_entry = target_buffer->head.next;
    if(next_waiting_entry == NULL) {
        return NULL;
    }
    uint8_t *packet = next_waiting_entry->packet;
    *packet_length = next_waiting_entry->len;
    target_buffer->head.next = next_waiting_entry->next;
    free(next_waiting_entry);
    return packet;
}

/**
 * @brief Enqueue a packet into the waiting list of a given ARP buffer.
 * 
 * @param target_buffer Pointer to the ARP buffer where the packet should be enqueued.
 * @param packet Pointer to the packet data to be enqueued.
 * @param packet_length Length of the packet data.
 * @note This function dynamically allocates memory to store the packet data.
 */

void enqueue_packet(IP_Mac_Mapping_Buffer *target_buffer, uint8_t *packet, unsigned int packet_length) {
    Waiting_List *new_waiting_entry = (Waiting_List *) malloc(sizeof(Waiting_List));
    new_waiting_entry->packet = (uint8_t *) malloc(packet_length);
    memcpy(new_waiting_entry->packet, packet, packet_length);
    new_waiting_entry->len = packet_length;
    Waiting_List *next_waiting_entry = target_buffer->head.next;
    target_buffer->head.next = new_waiting_entry;
    new_waiting_entry->next = next_waiting_entry;
}
