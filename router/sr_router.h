/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include "sr_nat.h"

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define MTU 1514

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;

    int nat_flag;
    struct sr_nat nat;/* NAT */
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
/*void sr_init(struct sr_instance* );*/
void sr_init(struct sr_instance* sr, int nat, int icmp_timeout_int, int tcp_idle_timeout, int transitory_idle_timeout);
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
int sr_handleIPpacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
int sr_handleARPpacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
struct sr_if* checkDestIsIface(uint32_t ip, struct sr_instance* sr);
int sendICMPmessage(struct sr_instance* sr, uint8_t icmp_type, uint8_t icmp_code, char* iface, uint8_t * ori_packet);
int send_echo_reply(struct sr_instance* sr, char* iface, uint8_t * ori_packet, unsigned int len, struct sr_arpentry* arpentry);
struct sr_rt *longest_prefix_match(struct sr_instance* sr, uint32_t ip);
struct sr_rt* longest_prefix_match1(struct sr_instance* sr, uint32_t ip);
int sr_nat_handleIPpacket(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface);
uint32_t icmp_cksum (sr_icmp_t3_hdr_t  *icmpHdr, int len); 
/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );
struct sr_rt* sr_rt_entry(struct sr_instance* sr, char* dest,
char* gw, char* mask,char* if_name);
struct sr_rt* longest_prefix_match_internal(struct sr_instance* sr, uint32_t ip);

#endif /* SR_ROUTER_H */
