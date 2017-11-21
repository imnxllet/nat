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
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

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

    printf("Through iface -> %s\n", interface);

    /* Sanity check
       can only check length of ethernet packet for now.*/
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength || len > MTU){
        return;
    }

    /* Print ethenet packet header. */
    print_hdrs(packet, len);

    /* Check packet type */
    uint16_t ethtype = ethertype(packet);

    /* IP Packet */
    if (ethtype == ethertype_ip) {
        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) {
            fprintf(stderr, "Failed to process IP packet, insufficient length\n");
            return;
        }

        printf("This is a IP packet...\n");
        sr_handleIPpacket(sr, packet, len, interface); 
        return;

    /* ARP Packet*/
    }else if (ethtype == ethertype_arp) {
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength){
            fprintf(stderr, "Failed to process ARP packet, insufficient length\n");
            return;
        }
        printf("This is a ARP packet...\n");
        sr_handleARPpacket(sr, packet, len, interface);
        return;   

    /* Unrecognized type, drop it.*/
    }else{
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
        return;
    }
}/* end sr_handlepacket */


/* Handle IP Packet */
int sr_handleIPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the IP packet.. */
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

    /* TO-DO: Essentially we need to check if this packet is ipv4*/

    /* See if this packet is for me or not. */
    struct sr_if *target_if = (struct sr_if*) checkDestIsIface(ip_packet->ip_dst, sr);

    /* This packet is for one of the interfaces */
    if(target_if != NULL){
        /* Check if it's ICMP or TCP/UDP */
        uint8_t ip_proto = ip_protocol((uint8_t *) ip_packet);

        if (ip_proto == ip_protocol_icmp) { /* ICMP, send echo reply */
            printf("This packet is for me(Echo Req), Initialize ARP req..\n");
            
            struct sr_arpcache *cache = &(sr->cache);
            struct sr_rt* matching_entry = longest_prefix_match(sr, ip_packet->ip_src);
            struct sr_arpentry* arpentry = sr_arpcache_lookup(cache, (uint32_t)((matching_entry->gw).s_addr));
            
            if(arpentry != NULL){/* Find ARP cache matching the echo req src*/
                return send_echo_reply(sr, interface, packet, len, arpentry);
            }else{/* Send ARP req to find the echo req src MAC addr*/
                sr_arpcache_queuereq(&(sr->cache),(uint32_t)((matching_entry->gw).s_addr),packet,len,interface);
                return 0;
            }

        /* TCP/UDP, Send ICMP Port Unreachable */
        }else if(ip_proto == 0x0006 || ip_proto == 0x11){ 
          printf("This packet is for me(TCP/UDP), send port unreachable back...\n");
          return sendICMPmessage(sr, 3, 3, interface, packet);
        
        /* Unknow IP packet type */
        }else{
          printf("This packet is for me, but type not recognized, drop it...\n");
          return -1;
        }

    /* Packet should be forwarded. */
    }else{
        /* Check if TTL is 0 or 1, send Time out accordingly. */
        if(ip_packet->ip_ttl == 1 || ip_packet->ip_ttl == 0){
            printf("TTL too short, send ICMP\n");
            /* Check arp cache before send back...*/
            return sendICMPmessage(sr, 11, 0, interface, packet);
        }
        printf("This packet should be forwarded..\n");
        
        /* Check if Routing Table has entry for targeted ip addr */
        /* use lpm */
        struct sr_rt* matching_entry = longest_prefix_match(sr, ip_packet->ip_dst);
        
        /* Found destination in routing table*/
        if(matching_entry != NULL){

            /* Adjust TTL and checksum */
            ip_packet->ip_ttl --;
            ip_packet->ip_sum = 0;
            ip_packet->ip_sum = cksum((uint8_t *) ip_packet, sizeof(sr_ip_hdr_t));
            printf("Found entry in routing table.\n");
            /* Check ARP cache, see hit or miss, like can we find the MAC addr.. */
            struct sr_arpcache *cache = &(sr->cache);
            struct sr_arpentry* arpentry = sr_arpcache_lookup(cache, (uint32_t)((matching_entry->gw).s_addr));

            /* Miss ARP */
            if (arpentry == NULL){
                printf("Miss in ARP cache table..\n");
                /* Send ARP request for 5 times. 
                 If no response, send ICMP host Unreachable.*/

                /* Add ARP req to quene*/
                sr_arpcache_queuereq(&(sr->cache),(uint32_t)((matching_entry->gw).s_addr),packet,           /* borrowed */
                                             len,/*matching_entry->interface*/interface);

                return 0;

            }else{/* Hit */
                printf("Hit in ARP cahce table...\n");

                /* Adjust ethernet packet and forward to next-hop */
                memcpy(((sr_ethernet_hdr_t *)packet)->ether_dhost, (uint8_t *) arpentry->mac, ETHER_ADDR_LEN);
                struct sr_if* forward_src_iface = sr_get_interface(sr, matching_entry->interface);
                memcpy(((sr_ethernet_hdr_t *)packet)->ether_shost, forward_src_iface->addr, ETHER_ADDR_LEN);
                free(arpentry);
              
                return sr_send_packet(sr,packet, len, matching_entry->interface);
            }

        }else{/* No match in routing table */
          printf("Did not find target ip in rtable..\n");
          return sendICMPmessage(sr, 3, 0, interface, packet);
        }
    }
    return 0;
}

/* Handle ARP Packet, Find MAC addr for a new IP addr*/
int sr_handleARPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the ARP packet.. */
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Get the dest ip and see which interface it is.. */
    struct sr_if *target_if = (struct sr_if*) checkDestIsIface(arp_packet->ar_tip, sr);

    /* Error check */
    if(target_if == 0){
        fprintf(stderr, "This ARP packet is not for this router.., can't be handled\n");
        return -1;
    }
    /* Check if this is reply or request */
    if(arp_packet->ar_op == htons(arp_op_request)){/* Req. Construct reply with MAC addr*/
        printf("This is an ARP request, preparing ARP reply...\n"); 
        len = (unsigned int) sizeof(sr_ethernet_hdr_t) +  sizeof(sr_arp_hdr_t);
  
        uint8_t *eth_packet = malloc(len);
        memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
        /* Source MAC is current Interface*/
        memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_shost, target_if->addr, ETHER_ADDR_LEN);
        ((sr_ethernet_hdr_t *)eth_packet)->ether_type = htons(ethertype_arp);

        /* Create IP packet */
        sr_arp_hdr_t *arp_reply = (sr_arp_hdr_t*) (eth_packet + sizeof(sr_ethernet_hdr_t));

        arp_reply->ar_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
        arp_reply->ar_pro = htons(0x0800);             /* format of protocol address   */
        arp_reply->ar_hln = 6;             /* length of hardware address   */
        arp_reply->ar_pln = 4;             /* length of protocol address   */
        arp_reply->ar_op = htons(arp_op_reply);              /* ARP opcode (command)         */
        memcpy(arp_reply->ar_sha, target_if->addr,ETHER_ADDR_LEN);/* sender hardware address      */
        arp_reply->ar_sip = target_if->ip;             /* sender IP address            */
        memcpy(arp_reply->ar_tha, arp_packet->ar_sha,ETHER_ADDR_LEN);/* target hardware address      */
        arp_reply->ar_tip = arp_packet->ar_sip;

        printf("Sending back ARP reply...Detail below:\n");  
        print_hdrs(eth_packet, len);         
        
        return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, interface);
   

    }else if(arp_packet->ar_op == htons(arp_op_reply)){
        printf("This is an ARP reply...\n"); 

        /* cache it */
        printf("Caching the ip->mac entry \n");
        struct sr_arpcache *cache = &(sr->cache);
        struct sr_arpreq *cached_req = sr_arpcache_insert(cache, arp_packet->ar_sha, arp_packet->ar_sip);
        
        /* send outstanding packts */
        struct sr_packet *pkt, *nxt;
        for (pkt = cached_req->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf){
                sr_ethernet_hdr_t * pack = (sr_ethernet_hdr_t *) (pkt->buf);
                
                sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (pkt->buf + sizeof(sr_ethernet_hdr_t));
                uint8_t ip_proto = ip_protocol((uint8_t *) ip_packet);
                sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t *) ((pkt->buf) + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
                
                /* Handle echo req */
                if (ip_proto == ip_protocol_icmp) { 
                    if(icmp_packet->icmp_type == 8){

                        uint32_t temp_ip_src = ip_packet->ip_src;
                        ip_packet->ip_src = ip_packet->ip_dst;
                        ip_packet->ip_dst = temp_ip_src;
                        ip_packet->ip_sum = 0;
                        ip_packet->ip_sum = cksum((uint8_t *) ip_packet, sizeof(sr_ip_hdr_t));
                        icmp_packet->icmp_type = 0;
                        icmp_packet->icmp_sum = 0;
                        icmp_packet->icmp_sum = cksum(icmp_packet, ntohs(ip_packet->ip_len) - (ip_packet->ip_hl * 4));

                        memcpy(pack->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
                        memcpy(pack->ether_shost, arp_packet->ar_tha, ETHER_ADDR_LEN);
                        printf("Sending outstanding packet.. \n");
                        sr_send_packet(sr, pkt->buf, pkt->len, interface);
                        continue;
                    }
                }
                /* Forward packet that is not a echo request */
                memcpy(pack->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
                memcpy(pack->ether_shost, arp_packet->ar_tha, ETHER_ADDR_LEN);
                printf("Sending outstanding packet.. \n");
                sr_send_packet(sr, pkt->buf, pkt->len, interface);
                           
          }
      }
      sr_arpreq_destroy(cache, cached_req);
      return 0;

    }else{
      fprintf(stderr, "This ARP packet is of unknown type.\n");
      return -1;
    }

    return 0;
}


/* Check an IP addr is one of the interfaces' IP */
struct sr_if* checkDestIsIface(uint32_t ip, struct sr_instance* sr){

    printf("Checking if this is for me...\n");
    printf("Current IP: ");
    print_addr_ip_int(ip);
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    while(if_walker){   
        printf("\nIface Ip:");
        print_addr_ip_int(if_walker->ip);
        if(ip == if_walker->ip){
            return if_walker;
        }
     
        if_walker = if_walker->next;
    }

    return NULL;
}


/* Send Echo Reply back */
int send_echo_reply(struct sr_instance* sr,char* iface, uint8_t * ori_packet, unsigned int len,struct sr_arpentry* arpentry){

    uint8_t *temp_dhost = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(temp_dhost, ((sr_ethernet_hdr_t *)ori_packet)->ether_dhost, ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t *)ori_packet)->ether_dhost, (uint8_t *) arpentry->mac, ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t *)ori_packet)->ether_shost, temp_dhost, ETHER_ADDR_LEN);
    free(temp_dhost);

    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (ori_packet + sizeof(sr_ethernet_hdr_t));

    /* Modify IP addr */

    uint32_t temp_ip_src = ip_packet->ip_src;
    ip_packet->ip_src = ip_packet->ip_dst;
    ip_packet->ip_dst = temp_ip_src;
    ip_packet->ip_sum = 0;
    ip_packet->ip_sum = cksum((uint8_t *) ip_packet, sizeof(sr_ip_hdr_t));

    sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t *) (ori_packet + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
    icmp_packet->icmp_type = 0;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_sum = 0;
    /*icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));*/
    /*copy...*/
    icmp_packet->icmp_sum = cksum(icmp_packet, ntohs(ip_packet->ip_len) - (ip_packet->ip_hl * 4));

    printf("Echo reply as folllow: \n");
    print_hdrs(ori_packet, len);


    return sr_send_packet(sr,ori_packet, /*uint8_t*/ /*unsigned int*/ len, iface);

}

/* Send ICMP message */
int sendICMPmessage(struct sr_instance* sr, uint8_t icmp_type, 
    uint8_t icmp_code, char* iface, uint8_t * ori_packet){

    printf("Creating ICMP message..\n");

    sr_ip_hdr_t *ori_ip_packet = (sr_ip_hdr_t*) (ori_packet + sizeof(sr_ethernet_hdr_t));
    unsigned int len = 0;

    printf("Creating unreachable reply..\n");
    len = (unsigned int) sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    
    uint8_t *eth_packet = malloc(len);
    memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_dhost, ((sr_ethernet_hdr_t *)ori_packet)->ether_shost, ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_shost, ((sr_ethernet_hdr_t *)ori_packet)->ether_dhost, ETHER_ADDR_LEN);
    ((sr_ethernet_hdr_t *)eth_packet)->ether_type = htons(ethertype_ip);

    /* Create IP packet */
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (eth_packet + sizeof(sr_ethernet_hdr_t));
    ip_packet->ip_hl = 5;
    ip_packet->ip_v = 4;
    ip_packet->ip_tos = 0;
    ip_packet->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    ip_packet->ip_id = htons(1);
    ip_packet->ip_off = htons(IP_DF);
    ip_packet->ip_ttl = 64;
    ip_packet->ip_p = ip_protocol_icmp;

    /* Unknow for now?? lpm??*/
    /*ip_packet->ip_src = ori_ip_packet->ip_dst;*/
    struct sr_if *ethx = sr_get_interface(sr, iface);

    ip_packet->ip_src = ethx->ip;
    if(icmp_code == 3){
      ip_packet->ip_src = ori_ip_packet->ip_dst;
    }
    
    ip_packet->ip_dst = ori_ip_packet->ip_src;

    /* Create ICMP Type 0 header*/
    ip_packet->ip_sum = 0;
    

    /* Take the original ip packet back */
    sr_icmp_t3_hdr_t *icmp_packet = (sr_icmp_t3_hdr_t *) (eth_packet + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
    memcpy(icmp_packet->data, ori_ip_packet, ICMP_DATA_SIZE);
    
    icmp_packet->icmp_type = icmp_type;
    icmp_packet->icmp_code = icmp_code;
    icmp_packet->icmp_sum = 0;
    icmp_packet->icmp_sum = cksum(icmp_packet, ntohs(ip_packet->ip_len) - (ip_packet->ip_hl * 4));
    ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

    printf("Eth pakcet prepared, ready to send...\n");
    print_hdrs(eth_packet, len);
    printf("--------------------------\n");
    return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, iface);


}


/* Find LPM in routing table */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip){

    struct sr_rt *rtable = sr->routing_table;
    struct sr_rt *match = NULL;
    unsigned long length = 0;
    while (rtable){
        /* Check which entry has the same ip addr as given one */
        if (((rtable->dest).s_addr & (rtable->mask).s_addr) == (ip & (rtable->mask).s_addr)){
            /* Check if it's longer based on the mask */
          if (length == 0 || length < (rtable->mask).s_addr){
            length = (rtable->mask).s_addr;
            match = rtable;
          }         
        }
        rtable = rtable->next;
    }
    
    /* Check if we find a matching entry */
    if(length == 0){
      return NULL;
    }

    return match;
}
