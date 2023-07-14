#include "lib.h"
#include "protocols.h"
#include "queue.h"

#include <string.h>
#include <arpa/inet.h>

#define MAX_PACKET_LEN 1600
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define INTERFACE_COUNT 4

struct message
{
  char *buf;
  size_t len;
  int interface;
};

// queue for messages
struct queue *queue_arp_waiting;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* arp table */
struct arp_entry *arp_table;
int arp_table_len;

// This function is defined here because it is used in other functions
int check_and_solve_packet(char *buf, size_t len, int interface);

int compare_rtable_entries(const void *a, const void *b)
{
  if ((*(struct route_table_entry *)a).prefix < (*(struct route_table_entry *)b).prefix)
    return -1;
  else if ((*(struct route_table_entry *)a).prefix > (*(struct route_table_entry *)b).prefix)
    return 1;
  else if ((*(struct route_table_entry *)a).prefix == (*(struct route_table_entry *)b).prefix)
  {
    if ((*(struct route_table_entry *)a).mask < (*(struct route_table_entry *)b).mask)
    {
      return -1;
    }
    else
      return 1;
  }
  return 0;
}

// quicksort sort ascending the route table entries by (prefix & mask
void sort_rtable(struct route_table_entry *rtable, int rtable_len)
{
  qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entries);
}

int find_addr_index_in_rtable(uint32_t destination, struct route_table_entry *rtable, int rtable_len)
{
  // use binary search to find the index of the longest prefix match
  int left = 0;
  int right = rtable_len - 1;
  int max_prefix_index = -1;

  uint32_t max_mask = htonl(0xFFFFFF00);

  while (left <= right)
  {
    int mid = (left + right) / 2;
    // Used the maximum mask to find the longest prefix match
    // Because the route table is sorted by prefix & mask and at a step
    // We could get on a small mask and the prefix would be wrong
    if ((destination & rtable[mid].mask) == rtable[mid].prefix ||
        (destination & max_mask) == rtable[mid].prefix)
    {
      max_prefix_index = mid;
      for (int i = mid; i < rtable_len; i++)
      {
        if (rtable[i].mask > rtable[max_prefix_index].mask &&
            (destination & rtable[i].mask) == rtable[i].prefix)
        {
          max_prefix_index = i;
        }
      }
      break;
    }
    else
    {
      // if ((destination & rtable[mid].mask) > rtable[mid].prefix)
      if ((destination & max_mask) > rtable[mid].prefix)
      {
        left = mid + 1;
      }
      else
      {
        right = mid - 1;
      }
    }
  }

  return max_prefix_index;
}

// Get the index of the mac address in the arp table
int find_mac_index_in_table(uint32_t ip, struct arp_entry *arp_table, int arp_table_len)
{
  int i;

  for (i = 0; i < arp_table_len; i++)
  {

    if (ip == arp_table[i].ip)
    {

      return i;
    }
  }
  return -1;
}

// Check if the IP & mask of a packet are already in the arp table
int check_if_ip_in_arp_table(uint32_t ip, struct arp_entry *arp_table, int arp_table_len)
{
  int i;

  for (i = 0; i < arp_table_len; i++)
  {
    if (ip == arp_table[i].ip)
    {
      return 1;
    }
  }
  return 0;
}

void add_to_queue(char *buf, size_t len, int interface)
{
  struct message *msg = (struct message *)calloc(1, sizeof(struct message));
  msg->buf = (char *)calloc(len, sizeof(char));
  memcpy(msg->buf, buf, len);
  msg->len = len;
  msg->interface = interface;
  queue_enq(queue_arp_waiting, msg);
}

// Add the sender of a packet to the arp table
void add_sender_arp_ip(char *buf, size_t len, int interface)
{
  struct ether_header *eth_hdr = (struct ether_header *)buf;
  struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

  // Check if the sender is already in the arp table
  if (check_if_ip_in_arp_table(ip_hdr->saddr, arp_table, arp_table_len) == 1)
  {
    // printf("Sender already in arp table?!");
    return;
  }

  // Add the sender to the arp table
  struct arp_entry *arp_entry = (struct arp_entry *)calloc(1, sizeof(struct arp_entry));
  arp_entry->ip = ip_hdr->saddr;
  memcpy(arp_entry->mac, eth_hdr->ether_shost, 6);
  arp_table[arp_table_len] = *arp_entry;
  arp_table_len++;
}

// Add the sender of an ARP request to the arp table
void add_sender_arp_by_request(char *buf, size_t len, int interface)
{
  struct ether_header *eth_hdr = (struct ether_header *)buf;
  struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

  // Check if the sender is already in the arp table
  if (check_if_ip_in_arp_table(arp_hdr->spa, arp_table, arp_table_len) == 1)
  {
    // printf("Sender already in arp table?!");
    return;
  }

  // Add the sender to the arp table
  struct arp_entry *arp_entry = (struct arp_entry *)calloc(1, sizeof(struct arp_entry));
  arp_entry->ip = arp_hdr->spa;
  memcpy(arp_entry->mac, eth_hdr->ether_shost, 6);
  arp_table[arp_table_len] = *arp_entry;
  arp_table_len++;
}

// Solve the arp reply by adding the received mac to the arp table
void solve_arp_reply(char *buf, size_t len, int interface)
{
  struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
  struct arp_entry *arp_entry = (struct arp_entry *)calloc(1, sizeof(struct arp_entry));

  if (check_if_ip_in_arp_table(arp_hdr->spa, arp_table, arp_table_len) == 1)
  {
    return;
  }

  // Create the arp entry
  arp_entry->ip = arp_hdr->spa;
  memcpy(arp_entry->mac, arp_hdr->sha, 6);

  // Add the arp entry to the arp table
  arp_table[arp_table_len] = *arp_entry;
  arp_table_len++;

  // Send the packets from the queue
  if (queue_empty(queue_arp_waiting))
    return;

  struct message *msg = queue_deq(queue_arp_waiting);

  // Must check (again) if the packet is an arp request or an ip packet
  check_and_solve_packet(msg->buf, msg->len, msg->interface);
}

// Solve the arp request by sending an arp reply
void create_and_send_arp_reply(char *buf, size_t len, int interface)
{
  // Add the sender of the packet to ARP table if it's not already there
  add_sender_arp_by_request(buf, len, interface);

  // Create the arp request
  char *arp_reply = (char *)calloc(MAX_PACKET_LEN, sizeof(char));

  // Create the ethernet header of the arp reply
  struct ether_header *eth_hdr = (struct ether_header *)arp_reply;
  eth_hdr->ether_type = htons(ETHERTYPE_ARP);

  // Set the destination mac address using the source mac address of the arp request
  struct ether_header *eth_hdr_req = (struct ether_header *)buf;
  memcpy(eth_hdr->ether_dhost, eth_hdr_req->ether_shost, 6);

  // Get the mac address of the interface
  uint8_t *interface_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
  get_interface_mac(interface, interface_mac);

  // Set the source mac address
  memcpy(eth_hdr->ether_shost, interface_mac, 6);

  // Set the parameters of the arp header
  struct arp_header *arp_hdr = (struct arp_header *)(arp_reply + sizeof(struct ether_header));
  arp_hdr->htype = htons(1);
  arp_hdr->ptype = htons(0x0800);
  arp_hdr->hlen = 6;
  arp_hdr->plen = 4;
  arp_hdr->op = htons(2); // ARP reply

  // Set the source ip address
  uint32_t interface_ip = inet_addr(get_interface_ip(interface));
  arp_hdr->spa = interface_ip;

  // Set the target ip address
  struct arp_header *arp_hdr_req = (struct arp_header *)(buf + sizeof(struct ether_header));
  arp_hdr->tpa = arp_hdr_req->spa;

  // Set the sender and target mac (hardware) addresses
  memcpy(arp_hdr->sha, interface_mac, 6);
  memcpy(arp_hdr->tha, arp_hdr_req->sha, 6);

  // Send the arp request
  size_t arp_reply_len = sizeof(struct ether_header) + sizeof(struct arp_header);

  send_to_link(interface, arp_reply, arp_reply_len);
}

// Solve the arp request by sending an arp reply
void create_and_send_arp_request(uint32_t next_hop_ip, int next_hop_interface, char *buf, size_t len, int interface)
{
  // Add the sender of the packet to ARP table if it's not already there
  add_sender_arp_ip(buf, len, interface);

  // Add the packet to the queue
  add_to_queue(buf, len, interface);

  // Create the arp request
  char *arp_request = (char *)calloc(MAX_PACKET_LEN, sizeof(char));

  // Create the ethernet header of the arp request
  struct ether_header *eth_hdr = (struct ether_header *)arp_request;
  eth_hdr->ether_type = htons(ETHERTYPE_ARP);
  memset(eth_hdr->ether_dhost, 0xFF, 6);

  uint8_t *interface_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
  get_interface_mac(next_hop_interface, interface_mac);
  memcpy(eth_hdr->ether_shost, interface_mac, 6);

  // Set the parameters of the arp header
  struct arp_header *arp_hdr = (struct arp_header *)(arp_request + sizeof(struct ether_header));
  arp_hdr->htype = htons(1);
  arp_hdr->ptype = htons(0x0800);
  arp_hdr->hlen = 6;
  arp_hdr->plen = 4;
  arp_hdr->op = htons(1);

  // Set the sender and target mac (hardware) addresses
  memcpy(arp_hdr->sha, interface_mac, 6);
  memset(arp_hdr->tha, 0, 6);

  // Set the source ip address and target ip address
  uint32_t interface_ip = inet_addr(get_interface_ip(next_hop_interface));
  arp_hdr->spa = interface_ip;
  arp_hdr->tpa = next_hop_ip;

  // free(interface_mac);

  // Send the arp request
  size_t arp_request_len = sizeof(struct ether_header) + sizeof(struct arp_header);
  send_to_link(next_hop_interface, arp_request, arp_request_len);

  /* Normaly should send on all interfaces, but in this case we know the interface*/
}

/* **************************** SEND FUNCTION **************************** */

int check_and_solve_packet(char *buf, size_t len, int interface)
{
  struct ether_header *eth_hdr = NULL;
  eth_hdr = (struct ether_header *)buf;

  struct iphdr *ip_hdr = NULL;
  ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

  // Check if the packet is ARP and if it's a request or a reply
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
  {
    if (ntohs(((struct arp_header *)(buf + sizeof(struct ether_header)))->op) == 1)
    {

      create_and_send_arp_reply(buf, len, interface);
      return -2;
    }
    else if (ntohs(((struct arp_header *)(buf + sizeof(struct ether_header)))->op) == 2)
    {
      solve_arp_reply(buf, len, interface);
      return 0;
    }
  }

  // Check if the router is the destination of the packet (An ICMP type 8 packet)
  uint8_t *receive_interface_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
  get_interface_mac(interface, receive_interface_mac);
  uint32_t interface_ip = inet_addr(get_interface_ip(interface));
  if (memcmp(eth_hdr->ether_dhost, receive_interface_mac, 6) == 0 &&
      interface_ip == ip_hdr->daddr &&
      ip_hdr->protocol == IPPROTO_ICMP && // check if the packet is ICMP
      ((struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr)))->type == 8 &&
      ((struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr)))->code == 0)
  {
    // printf("Packet is for me!\n");
    return 8;
  }

  // Check if the packet is of type IP
  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
  {
    // printf("The packet is not of type IP\n");
    return -10;
  }

  // Check the checksum for only the IP header
  u_int16_t old_checksum = ntohs(ip_hdr->check);
  ip_hdr->check = 0;
  u_int16_t new_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
  if (old_checksum != new_check)
  {
    return -10;
  }

  // Check the TTL
  if (ip_hdr->ttl <= 1)
  {
    // printf("The TTL is not correct\n");
    return 11;
  }

  // Decrement the TTL
  ip_hdr->ttl--;

  // Find the line of the address in the table
  // and the next hop
  int next_hop_index = find_addr_index_in_rtable(ip_hdr->daddr, rtable, rtable_len);
  if (next_hop_index == -1)
  {
    // The destination is not found in the routing table and the packet is dropped
    // Send an ICMP type 3 code 0
    return 3;
  }
  struct route_table_entry next_hop_table_line = rtable[next_hop_index];

  int next_hop_interface = next_hop_table_line.interface;
  uint32_t next_hop_ip = next_hop_table_line.next_hop;

  int next_hop_mac_index = find_mac_index_in_table(next_hop_ip, arp_table, arp_table_len);
  if (next_hop_mac_index == -1)
  {
    // reset the TTL and checksum with the old values
    ip_hdr->ttl++;
    ip_hdr->check = ntohs(old_checksum);
    create_and_send_arp_request(next_hop_ip, next_hop_interface, buf, len, interface);
    return -1; // The next hop is not found in the ARP table
  }

  struct arp_entry next_hop_arp_entry = arp_table[next_hop_mac_index];

  uint8_t *send_interface_mac = (uint8_t *)calloc(6, sizeof(uint8_t));
  get_interface_mac(next_hop_interface, send_interface_mac);

  // Set the source and destination mac addresses
  memmove(eth_hdr->ether_shost, send_interface_mac, 6 * sizeof(uint8_t));
  memmove(eth_hdr->ether_dhost, next_hop_arp_entry.mac, 6 * sizeof(uint8_t));

  // Recalculate the checksum
  ip_hdr->check = 0;
  u_int16_t new_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
  ip_hdr->check = ntohs(new_checksum);

  // Send the packet to the next hop
  int ret = send_to_link(next_hop_interface, buf, len);
  if (ret < 0)
  {
    // perror("Error sending packet to link");
    return -10;
  }

  // Should try to free the memory first
  // free(send_interface_mac);
  // free(eth_hdr);
  // free(ip_hdr);

  return 1; // The packet was sent to the next hop
}

/* **************************** SEND FUNCTION **************************** */

void send_icmp_message(char *buf, size_t len, int interface, int icmp_type)
{
  char *send_buf = (char *)calloc(MAX_PACKET_LEN, sizeof(char));

  // Old headers
  struct ether_header *eth_hdr = (struct ether_header *)buf;
  struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
  struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

  // New headers
  struct ether_header *icmp_eth_hdr = (struct ether_header *)send_buf;
  struct iphdr *icmp_ip_hdr = (struct iphdr *)(send_buf + sizeof(struct ether_header));
  struct icmphdr *icmp_icmp_hdr = (struct icmphdr *)(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

  // struct iphdr *ip_hdr_old = (struct iphdr *)calloc(1, sizeof(struct iphdr));
  char *old_payload = (char *)calloc(8, sizeof(char));
  memcpy(old_payload, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8 * sizeof(char));

  // Set the Ethernet header for the ICMP message
  // icmp_eth_hdr->ether_type = eth_hdr->ether_type;
  memcpy(icmp_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
  memcpy(icmp_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6 * sizeof(uint8_t));
  icmp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

  // Set the IP header for the ICMP message
  icmp_ip_hdr->version = 4;
  icmp_ip_hdr->ihl = 5;
  icmp_ip_hdr->tos = 0;
  if (icmp_type == 8)
    icmp_ip_hdr->tot_len = ip_hdr->tot_len;
  else
    icmp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

  // icmp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
  icmp_ip_hdr->id = htons(1);
  icmp_ip_hdr->frag_off = 0;
  icmp_ip_hdr->ttl = 64;
  icmp_ip_hdr->protocol = IPPROTO_ICMP;
  icmp_ip_hdr->check = 0;

  // Update the IP destination address and source address
  uint32_t ip_interface = inet_addr(get_interface_ip(interface));
  icmp_ip_hdr->saddr = ip_interface;
  icmp_ip_hdr->daddr = ip_hdr->saddr;

  // Set the IP checksum for the ICMP message
  icmp_ip_hdr->check = 0;
  u_int16_t ip_new_checksum = checksum((uint16_t *)icmp_ip_hdr, sizeof(struct iphdr));
  icmp_ip_hdr->check = htons(ip_new_checksum);

  size_t send_len = 0;
  // Set the new ICMP header
  if (icmp_type == 8)
  {
    icmp_icmp_hdr->type = 0;
    icmp_icmp_hdr->code = 0;
    icmp_icmp_hdr->un.echo.id = icmp_hdr->un.echo.id;
    icmp_icmp_hdr->un.echo.sequence = icmp_hdr->un.echo.sequence;
    send_len = len;
    memcpy(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
           buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr),
           send_len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr));
    icmp_icmp_hdr->checksum = 0;
    u_int16_t icmp_new_checksum = checksum((uint16_t *)icmp_icmp_hdr, send_len - sizeof(struct ether_header) - sizeof(struct iphdr));
    icmp_icmp_hdr->checksum = htons(icmp_new_checksum);
  }
  else
  {
    icmp_icmp_hdr->type = icmp_type;
    icmp_icmp_hdr->code = 0;
    icmp_icmp_hdr->un.echo.id = 0;
    icmp_icmp_hdr->un.echo.sequence = 0;

    // Copy the old IP header and payload to the ICMP message
    int icmp_offset = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    memcpy(send_buf + icmp_offset, ip_hdr, sizeof(struct iphdr));
    memcpy(send_buf + icmp_offset + sizeof(struct iphdr), old_payload, 8 * sizeof(char));
    // Set the ICMP checksum for the ICMP message
    icmp_icmp_hdr->checksum = 0;
    u_int16_t icmp_new_checksum = checksum((uint16_t *)icmp_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
    icmp_icmp_hdr->checksum = htons(icmp_new_checksum);

    // Copy info to the send buffer
    send_len = sizeof(struct ether_header) +
               sizeof(struct iphdr) +
               sizeof(struct icmphdr) +
               sizeof(struct iphdr) +
               8 * sizeof(char);
  }

  // Send the packet to the destination
  int ret = send_to_link(interface, send_buf, send_len);
  if (ret == -1)
  {
    perror("Error sending ICMP message:");
  }
  // free(aux_mac);
}

int main(int argc, char *argv[])
{
  char buf[MAX_PACKET_LEN];

  // Do not modify this line
  init(argc - 2, argv + 2);

  /* Code to allocate the route and ARP tables */
  rtable = malloc(sizeof(struct route_table_entry) * 100000);
  /* DIE is a macro for sanity checks */
  DIE(rtable == NULL, "memory");

  arp_table = malloc(sizeof(struct arp_header) * 100000);
  DIE(arp_table == NULL, "memory");

  /* Read the static routing table and the MAC table */
  rtable_len = read_rtable(argv[1], rtable);

  /* // For static ARP table
   arp_table_len = parse_arp_table("arp_table.txt", arp_table);
  */

  // For dynamic ARP table
  arp_table_len = 0;

  // sort the route table entries by ip prefix
  sort_rtable(rtable, rtable_len);

  // Initialize the the arp wating queue
  queue_arp_waiting = queue_create();

  while (1)
  {
    int interface;
    size_t len;

    interface = recv_from_any_link(buf, &len);
    DIE(interface < 0, "recv_from_any_links");

    int result = check_and_solve_packet(buf, len, interface);
    // Check if must send an type 11 / 3 ICMP message
    switch (result)
    {
    case 3: // ICMP type 3 - Destination Unreachable
      send_icmp_message(buf, len, interface, 3);
      continue;
      break;
    case 8: // ICMP type 8 - Echo Request
      send_icmp_message(buf, len, interface, 8);
      continue;
      break;
    case 11: // ICMP type 11 - Time Exceeded
      send_icmp_message(buf, len, interface, 11);
      continue;
      break;
    case 1: // Packet was sent
      // printf("Packet was sent!\n");
      continue;
    case 0: // Packet was ARP reply
      // printf("Packet was ARP reply!\n");
      continue;
      break;
    case -1: // The packet requires an ARP request
      // printf("Packet requires an ARP request!\n");
      continue;
      break;
    case -2: // The packet was an ARP request
      // printf("Packet was an ARP request!\n");
      continue;
      break;
    default: // code -10
      continue;
      // printf("Packet was wrong or/and was not sent!\n");
    }
  }
}
