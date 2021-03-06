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
 *tar -czvf pa2.tar.gz ./ *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_nat.h"
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

void sr_init(struct sr_instance* sr, int nat, int icmp_timeout_int, int tcp_idle_timeout, int transitory_idle_timeout)
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
    sr->nat_flag = nat;

    /**/
    if (nat){
        sr_nat_init(&(sr->nat));
        (sr->nat).icmp_timeout_int = icmp_timeout_int;
        (sr->nat).tcp_idle_timeout = tcp_idle_timeout;
        (sr->nat).transitory_idle_timeout = transitory_idle_timeout;
        /* Do I need this tho...*/
        (sr->nat).sr = sr;
    }
    
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
    /*print_hdrs(packet, len);*/

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

        if(sr->nat_flag){
            printf("Handling packet in nat mode..\n");
            sr_nat_handleIPpacket(sr, packet, len, interface);
            return;
        }
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

/* HANDLE IP packet when NAT mode enabled. */
int sr_nat_handleIPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the IP packet.. */
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

    /*need delete*/
   
    /* TO-DO: Essentially we need to check if this packet is ipv4*/

    /* See if this packet is for me or not. */
    struct sr_if *target_if = (struct sr_if*) checkDestIsIface(ip_packet->ip_dst, sr);
    uint8_t ip_proto = ip_protocol((uint8_t *) ip_packet);
    
    /* This packet is for one of the interfaces */
    if(target_if != NULL){
        /* Check if it's ICMP or TCP/UDP */
        /*uint8_t ip_proto = ip_protocol((uint8_t *) ip_packet);*/

        /* PING from client to router throgh eth1. */
        if(is_nat_internal_iface(interface)){
            printf("PING from client to router throgh eth1.\n");
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

        /* Packet targeted to router, but it's from EXTERNAL. Need to do NAT...*/
        /* Packet comes from server1/2 to router.... translate NAT addr to internal ..*/
        /* check type of IP: icmp, tcp????*/
        }else{
            printf("[NAT] Packet targeted INternal HOST from server\n");

            if (ip_proto == ip_protocol_icmp) { 
                printf("[NAT ICMP] \n");

                /* Locate icmp header.. */
                sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Look up external addr/port pair given internal info */
                struct sr_nat_mapping *nat_entry = sr_nat_lookup_external(&(sr->nat), icmp_hdr->identifier, nat_mapping_icmp);

                /* No mapping found.. */
                if (nat_entry != NULL) {
                    printf("[NAT ICMP: found mapping in table, good] \n");
                    ip_packet->ip_dst = nat_entry->ip_int;
                    /*int diff = (int)icmp_hdr->identifier - (int)nat_entry->aux_int;*/
                    icmp_hdr->identifier = nat_entry->aux_int;
                    nat_entry->last_updated = time(NULL);
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                   
                    /*int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);*/
                    
                    /*icmp_hdr->icmp_sum = (uint16_t) ((int) icmp_hdr->icmp_sum - diff);*/

                }else{
                    printf("[NAT ICMP] didn't found entry..shit\n");
                    return sendICMPmessage(sr, 3, 0, interface, packet);
                }
                

            /* TCP */
            }else if(ip_proto == 0x0006){
                printf("[NAT TCP] Packet from SERVER to INTERNAL HOST\n");
                sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                


                struct sr_nat_mapping *nat_lookup = sr_nat_lookup_external(&(sr->nat), tcp_hdr->dst_port, nat_mapping_tcp);
                if (nat_lookup != NULL) {
                    printf("[NAT TCP] Found mapping in table, good.\n");
                    ip_packet->ip_dst = nat_lookup->ip_int;
                  tcp_hdr->dst_port = nat_lookup->aux_int;

                  /*ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));
                  tcp_hdr->sum = tcp_cksum(ipHdr, tcp_hdr, len);*/
                  tcp_hdr->checksum = 0;
                  tcp_hdr->checksum = cksum(tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                  

                  /* Critical section, make sure you lock, careful modifying code under critical section. */
                  pthread_mutex_lock(&((sr->nat).lock));

                  struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_lookup, ip_packet->ip_src);
                  if (tcp_con == NULL) {
                    printf("[NAT TCP] New conn, inserting..\n");
                    tcp_con = sr_nat_insert_tcp_con(nat_lookup, ip_packet->ip_src);
                    /*
                    TCPEndpointIndependentFiltering [MAX_POINTS = 1]: Client sends a TCP SYN packet to one of the external host(exho1). Get a new mapping (internal port#, internal IP)<=>(external port#, external IP) (Let’s call the external pair Pext). After that, another external host(exho2) sends a TCP SYN packet using Pext as destination (port#, IP) pair. 
Check : a TCP packet should be sent out via NAT internal interface with correct destination port#.*/
                    /*printf("[NAT TCP] Existing conn, start modify..\n");
                    if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack){
                        if(ntohs(tcp_hdr->dst_port) >= 1024){

                            printf("[NAT TCP] ICMP port unreachable\n");
                            sleep(6);
                            return sendICMPmessage(sr, 3, 3, interface, packet);
                        }else{
                            printf("[NAT TCP] port < 1024, no need to drop...\n");
                            return sendICMPmessage(sr, 3, 3, interface, packet);
                        }
                    }*/
                  }
                  tcp_con->last_updated = time(NULL);


                  switch (tcp_con->tcp_state) {
                    /* Receive SYN packet from client, respond..*/
                    /*--2)SYN-ACK*/
                    case SYN_SENT:
                      if ((ntohl(tcp_hdr->ack_num) == ntohl(tcp_con->client_isn) + 1) && tcp_hdr->syn && tcp_hdr->ack) {
                        /*tcp_con->server_isn = ntohl(tcp_hdr->seq);*/
                        printf("[NAT TCP] 2-SYN-ACK \n");
                        tcp_con->server_isn = tcp_hdr->seq;
                        tcp_con->tcp_state = SYN_RCVD;
                        break;
                      
                      /* Simultaneous open */
                      } else if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack) {
                        printf("[NAT TCP] 1)SYN SERVER->INTERNAL: Simultaneous Open\n");
                        tcp_con->server_isn = tcp_hdr->seq;
                        tcp_con->tcp_state = SYN_RCVD;
                        break;
                      /*}else if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack){
                        if(ntohs(nat_lookup->aux_ext) >= 1024){

                            printf("[NAT TCP] ICMP port unreachable\n");
                            sleep(6);
                            return sendICMPmessage(sr, 3, 3, interface, packet);
                        }else{
                            printf("[NAT TCP] port < 1024, no need to drop...\n");
                        }*/

                      }else{
                        printf("[NAT TCP] 2-SYN-ACK:fucked up;; \n");
                        /*tcp_con->tcp_state = CLOSED;
                        return -1;*/
                        return sendICMPmessage(sr, 3, 3, interface, packet);
                        
                      }
                    case SYN_RCVD:
                        if (tcp_hdr->syn && tcp_hdr->ack) {
                            printf("[NAT TCP: 3)ACK-Client to server, ok to send, established]\n");
                        
                            tcp_con->tcp_state = ESTABLISHED;
                        }

                    case ESTABLISHED:
                        printf("[NAT TCP] SERVER->ROUNTER.. ESTABLISHED.. http \n");
                        break;

                    default: 
                        /*if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack){
                            if(ntohs(nat_lookup->aux_ext) >= 1024){

                                printf("[NAT TCP] ICMP port unreachable\n");
                                sleep(6);
                                return sendICMPmessage(sr, 3, 3, interface, packet);
                            }else{
                                printf("[NAT TCP] port < 1024, no need to drop...\n");

                            }
                        }*/

                      printf("[NAT TCP] SERVER->ROUNTER.. DEFAULT.. why \n");
                      print_hdrs(packet, len);
                     /* return sendICMPmessage(sr, 3, 3, interface, packet);*/

                      break;
                  }

                  pthread_mutex_unlock(&((sr->nat).lock));
                  /* End of critical section. */

                  

                }else{
                    printf("No matching nat entry found in table.. shit\n");
                    /*TCPUnsolicitedSyn [MAX_POINTS = 1]: Send unsolicited SYN from one of
                     the external hosts to the NAT external interface. It should generate an 
                     ICMP port unreachable after 6s ONLY if the destination port to which the 
                     packet is sent to is >= 1024.
                     TCPUnsolicitedSyn2 [MAX_POINTS = 1]: TCPUnsolicitedSyn to 
                     restricted external port#(22), It should generate an ICMP port unreachable 
                        message too.
                     */
                    if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack){
                        if(ntohs(tcp_hdr->dst_port) >= 1024){

                            printf("[NAT TCP] ICMP port unreachable\n");
                            sleep(6);
                            return sendICMPmessage(sr, 3, 3, interface, packet);
                        }else{
                            printf("[NAT TCP] port < 1024, no need to drop...\n");
                            return sendICMPmessage(sr, 3, 3, interface, packet);
                        }
                    }
                    return sendICMPmessage(sr, 3, 3, interface, packet);

                }
            }else{
                printf("This is a UDP or other types of pakcet.. drop it.. \n");
                return 0;
            }
            /* Check if Routing Table has entry for targeted ip addr */
            /* use lpm */

            /*struct sr_rt* matching_entry = longest_prefix_match(sr, ip_packet->ip_dst);*/
            struct sr_rt* matching_entry = longest_prefix_match(sr, ip_packet->ip_dst);
           /*struct sr_rt* matching_entry = sr_rt_entry(sr, "10.0.1.100", "10.0.1.100", "255.255.255.255", "eth1");*/
            /* Found destination in routing table*/
            if(matching_entry != NULL){

                printf("Prepare to forward the packet back..\n");
                printf("Found entry in routing table.\n");
                /* Locate the icmp header.. */
                /*sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

                /* Adjust TTL and checksum */
                ip_packet->ip_ttl --;
                ip_packet->ip_sum = 0;
                ip_packet->ip_sum = cksum((uint8_t *) ip_packet, sizeof(sr_ip_hdr_t));
                
                
                /* Check ARP cache, see hit or miss, like can we find the MAC addr.. */
                struct sr_arpcache *cache = &(sr->cache);
                /*struct in_addr gw;
                inet_aton("10.0.1.100 ",&gw);
                matching_entry->gw = gw;*/
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
                    /*struct sr_if* forward_src_iface = sr_get_interface(sr, matching_entry->interface);*/
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

    /* Packets targeted to Server1/2... Turn the internal addr to NAT addr... */
    /* Packet should be forwarded. Do NAT before forward.*/
    }else{
        /* Check if TTL is 0 or 1, send Time out accordingly. */
        if(ip_packet->ip_ttl == 1 || ip_packet->ip_ttl == 0){
            printf("TTL too short, send ICMP\n");
            /* Check arp cache before send back...*/
            return sendICMPmessage(sr, 11, 0, interface, packet);
        }
        printf("[NAT] Packet from INTERNAL to SERVER\n");
        struct sr_rt* matching_entry = longest_prefix_match(sr, ip_packet->ip_dst);

        if(matching_entry == NULL){/* No match in routing table */
          printf("Did not find target ip in rtable..\n");
          return sendICMPmessage(sr, 3, 0, interface, packet);
        }

       /* DO NAT */

        /* ICMP*/
        struct sr_if* forward_src_iface = sr_get_interface(sr, matching_entry->interface);
        if (ip_proto == ip_protocol_icmp) { 
            printf("[NAT icmp]\n");

            /* Locate icmp header.. */
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* Look up external addr/port pair given internal info */
            struct sr_nat_mapping *nat_entry = sr_nat_lookup_internal(&(sr->nat), ip_packet->ip_src, icmp_hdr->identifier, nat_mapping_icmp);

            /* No mapping found.. */
            if (nat_entry == NULL) {
                printf("[NAT ICMP] making entry\n");
                /* Insert mapping entry with internal source ip and icmp id */
                nat_entry = sr_nat_insert_mapping(&(sr->nat), ip_packet->ip_src, icmp_hdr->identifier, nat_mapping_icmp);

                /* Add external ip(eth2) and port to mapping entry */
                nat_entry->ip_ext = forward_src_iface->ip;
                printf("eth2 ip is...\n");
                print_addr_ip_int(forward_src_iface->ip);
                /* Generate a random port for the entry for external info */
                nat_entry->aux_ext = htons((uint16_t) generate_unique_port(&(sr->nat)));
            }else{
                printf("[NAT icmp]Found a matching entry..\n");
            }
            /* Update this entry */
            nat_entry->last_updated = time(NULL);
            /* Update the packet info to external addr and port */
            /*int diff = (int)icmp_hdr->identifier - (int)nat_entry->aux_ext;*/
            icmp_hdr->identifier = nat_entry->aux_ext;
            ip_packet->ip_src = nat_entry->ip_ext;
            printf("eth2 ip is...\n");
            print_addr_ip_int(ntohl(ip_packet->ip_src));
            /*printf("After NAT... headers like this\n");
            print_hdrs(packet,len);*/
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

           /* int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);*/
            
            /*icmp_hdr->icmp_sum = (uint16_t) ((int) icmp_hdr->icmp_sum - diff);*/

            

        /* TCP */
        }else if(ip_proto == 0x0006){
            printf("[NAT TCP: from internal to server]\n");

            sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            if(ntohs(tcp_hdr->dst_port) == 22){
                return sendICMPmessage(sr, 3, 3, interface, packet);
            }

            struct sr_nat_mapping *nat_entry = sr_nat_lookup_internal(&(sr->nat), ip_packet->ip_src, tcp_hdr->src_port, nat_mapping_tcp);

            if (nat_entry == NULL) {
                printf("[NAT TCP: Didn't find mapping, make one]\n");
              nat_entry  = sr_nat_insert_mapping(&(sr->nat), ip_packet->ip_src, tcp_hdr->src_port, nat_mapping_tcp);
              /* Add external ip(eth2) and port to mapping entry */
                nat_entry->ip_ext = forward_src_iface->ip;
                printf("eth2 ip is...\n");
                print_addr_ip_int(ntohl(forward_src_iface->ip));
                /* Generate a random port for the entry for external info */
                nat_entry->aux_ext = htons((uint16_t) generate_unique_port(&(sr->nat)));
            }else{
                printf("[NAT TCP: Found a entry]\n");
            }
            nat_entry->last_updated = time(NULL);

            /* Critical section, make sure you lock, careful modifying code under critical section. */
            pthread_mutex_lock(&((sr->nat).lock));

            /* Look up tcp connection for this mapping */
            struct sr_nat_connection *tcp_con = sr_nat_lookup_tcp_con(nat_entry, ip_packet->ip_dst);
            if (tcp_con == NULL) {
                /* Insert the connection .. */
                printf("[NAT TCP: NO conn found, insert this]\n");
                tcp_con = sr_nat_insert_tcp_con(nat_entry, ip_packet->ip_dst);
            }else{
                printf("[NAT TCP: found Existing COnn]\n");
            }
            tcp_con->last_updated = time(NULL);

            switch (tcp_con->tcp_state) {
              case CLOSED:
                /*1）---SYN----*/
                if (ntohl(tcp_hdr->ack_num) == 0 && tcp_hdr->syn && !tcp_hdr->ack) {
                    printf("[NAT TCP: (1)SYN-Opening the handshake.]\n");
                  /*tcp_con->client_isn = ntohl(tcp_hdr->seq_num);*/
                  tcp_con->client_isn = tcp_hdr->seq;
                  tcp_con->tcp_state = SYN_SENT;
                }else{
                    printf("[NAT TCP CLOSED: fuck up]\n");
                }
                break;
              /* 3) ACK*/  
              case SYN_RCVD:
                if ((ntohl(tcp_hdr->seq) == ntohl(tcp_con->client_isn) + 1) && (ntohl(tcp_hdr->ack_num) == ntohl(tcp_con->server_isn) + 1) && !tcp_hdr->syn && tcp_hdr->ack) {
                  printf("[NAT TCP: 3)ACK-Client to server, ok to send, established]\n");
                  tcp_con->client_isn = tcp_hdr->seq;
                  tcp_con->tcp_state = ESTABLISHED;
                }else if (tcp_hdr->syn && tcp_hdr->ack) {
                        /*tcp_con->server_isn = ntohl(tcp_hdr->seq);*/
                        printf("[NAT TCP] INTERNAL->SERVER>. 2-SYN-ACK : Simultaneous open \n");
                        tcp_con->client_isn = tcp_hdr->seq;
                        tcp_con->tcp_state = SYN_RCVD;
                        break;


                /* Unsolicited syn... drop it..*/
                }else if((ntohl(tcp_hdr->ack_num) == 0) && tcp_hdr->syn && !tcp_hdr->ack){
                    printf("[NAT] Unsolicited SYN packet.. \n");
                    double diff_t;
                    diff_t = difftime(time(NULL), tcp_con->last_updated );
                    if((int)diff_t < 6){
                        printf("[NAT] Unsolicited SYN packet.. drop it.. <6\n");
                        return -1;

                    }else{
                        printf("[NAT] Unsolicited SYN packet.. drop it anyways....\n");
                        return -1;
                    }

                }else{
                    printf("[NAT TCP: I am fucked up here!!!\n");
                    printf("(ntohl(tcp_hdr->seq_num) == ntohl(tcp_con->client_isn) + 1): ->%d\n", (ntohl(tcp_hdr->seq) == ntohl(tcp_con->client_isn) + 1));
                    printf("(ntohl(tcp_hdr->ack_num) == ntohl(tcp_con->server_isn) + 1): ->%d\n", (ntohl(tcp_hdr->ack_num) == ntohl(tcp_con->server_isn) + 1));
                    printf("!tcp_hdr->syn: ->%d\n", !tcp_hdr->syn);
                    printf("tcp_hdr->ack: ->%d\n", tcp_hdr->ack);
                }
                break;

              case ESTABLISHED:
                if (tcp_hdr->fin && tcp_hdr->ack) {
                    printf("[NAT TCP: Client to Server: closing connection]\n");
                  tcp_con->client_isn = tcp_hdr->seq;
                  tcp_con->tcp_state = CLOSED;
                }else{
                    printf("[NAT TCP ESTABLISHED: HTTP\n");
    

                }
                break;

              default:
              printf("[NAT TCP] INTERNAL -> SERVER: DEFAULT...\n");
              print_hdrs(packet, len);
                break;
            }

            pthread_mutex_unlock(&((sr->nat).lock));
            /* End of critical section. */

            ip_packet->ip_src = nat_entry->ip_ext;
            tcp_hdr->src_port = nat_entry->aux_ext;

            /*ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));*/
            tcp_hdr->checksum = 0;
            tcp_hdr->checksum= cksum(tcp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            
        }
        
        /* Check if Routing Table has entry for targeted ip addr */
        /* use lpm */
        
        
        /* Found destination in routing table*/
        if(matching_entry != NULL){
            printf("[NAT] Forwarding the modified packet to destination\n");
                /* Locate the icmp header.. */
                /*sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

                /* Adjust TTL and checksum */
                ip_packet->ip_ttl --;
                ip_packet->ip_sum = 0;
                ip_packet->ip_sum = cksum((uint8_t *) ip_packet, sizeof(sr_ip_hdr_t));
                
                
                printf("[NAT}Found entry in routing table.\n");
                /* Check ARP cache, see hit or miss, like can we find the MAC addr.. */
                struct sr_arpcache *cache = &(sr->cache);
                struct sr_arpentry* arpentry = sr_arpcache_lookup(cache, (uint32_t)((matching_entry->gw).s_addr));
         

            /* Miss ARP */
            if (arpentry == NULL){
                printf("[NAT}Miss in ARP cache table..\n");
                /* Send ARP request for 5 times. 
                 If no response, send ICMP host Unreachable.*/

                /* Add ARP req to quene*/
                sr_arpcache_queuereq(&(sr->cache),(uint32_t)((matching_entry->gw).s_addr),packet,           /* borrowed */
                                             len,/*matching_entry->interface*/interface);

                return 0;

            }else{/* Hit */
                printf("[NAT]Hit in ARP cahce table...\n");

                /* Adjust ethernet packet and forward to next-hop */
                memcpy(((sr_ethernet_hdr_t *)packet)->ether_dhost, (uint8_t *) arpentry->mac, ETHER_ADDR_LEN);
                struct sr_if* forward_src_iface = sr_get_interface(sr, matching_entry->interface);
                memcpy(((sr_ethernet_hdr_t *)packet)->ether_shost, forward_src_iface->addr, ETHER_ADDR_LEN);
                free(arpentry);
              
                return sr_send_packet(sr,packet, len, matching_entry->interface);
            }

        }
    }
    return 0;
}


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
            struct sr_rt* matching_entry = longest_prefix_match1(sr, ip_packet->ip_src);
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
        struct sr_rt* matching_entry = longest_prefix_match1(sr, ip_packet->ip_dst);
        
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
        /*print_hdrs(eth_packet, len);  */       
        
        return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, interface);
   

    }else if(arp_packet->ar_op == htons(arp_op_reply)){
        printf("This is an ARP reply...\n"); 
        
        /*print_hdrs(arp_packet, len);*/

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
                        /* Check if this packet is sent to external host..*/
                        struct sr_if* is_router = checkDestIsIface(ip_packet->ip_dst, sr);
                        if(is_router == NULL){
                            memcpy(pack->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
                            memcpy(pack->ether_shost, arp_packet->ar_tha, ETHER_ADDR_LEN);
                            printf("Sending outstanding packet.. (nat out )\n");
                            print_hdrs(pkt->buf, pkt->len);
                            sr_send_packet(sr, pkt->buf, pkt->len, interface);
                            continue;
                        }

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
                        printf("Sending outstanding packet.. (echo req...)\n");
                        
                        sr_send_packet(sr, pkt->buf, pkt->len, interface);
                        continue;
                    }
                }
                /* Forward packet that is not a echo request */
                memcpy(pack->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
                memcpy(pack->ether_shost, arp_packet->ar_tha, ETHER_ADDR_LEN);
                printf("Sending outstanding packet.. (forward it..)\n");
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
    /*print_hdrs(ori_packet, len);*/


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
    /*print_hdrs(eth_packet, len);*/
    printf("--------------------------\n");
    return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, iface);


}

struct sr_rt* longest_prefix_match1(struct sr_instance* sr, uint32_t ip){

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

/* Find   in routing table */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t ip){

    struct sr_rt *rtable = sr->routing_table;
    struct sr_rt *match = NULL;
    struct sr_rt *default_eth1 = NULL;
    unsigned long length = 0;

    while (rtable){
        /* Check which entry has the same ip addr as given one */
        if (((uint32_t) (rtable->dest).s_addr & (uint32_t)(rtable->mask).s_addr) == ((uint32_t)ip & (uint32_t)(rtable->mask).s_addr)){
            /* Check if it's longer based on the mask */
          if (length == 0 || length < ntohs((rtable->mask).s_addr)){
            length = ntohs((rtable->mask).s_addr);
            match = rtable;
          }         
        }
        if(strcmp(rtable->interface, "eth1") == 0){
            default_eth1 = rtable;
           /* match = rtable;*/
        }
        rtable = rtable->next;
    }
    
    /* Check if we find a matching entry */
    if(length == 0){
      
       return default_eth1;
      /*return NULL;*/
    }

    return match;
}


struct sr_rt* longest_prefix_match_internal(struct sr_instance* sr, uint32_t ip){

    struct sr_rt *rtable = sr->routing_table;
    struct sr_rt *match = NULL;
    struct sr_rt *default_eth1 = NULL;
    unsigned long length = 0;


    while (rtable){
        /* Check which entry has the same ip addr as given one */
        /*if (( (rtable->gw).s_addr  == ip) && (strcmp(rtable->interface, "eth1") == 0)){
            match = rtable;
            length = 1;
        }*/
        if(strcmp(rtable->interface, "eth1") == 0){
 
            default_eth1 = rtable;
            
        }
        rtable = rtable->next;
    }
    
    /* Check if we find a matching entry */
   /* if(length == 0){*/


      
       return default_eth1;
      /*return NULL;*/
   /* }*/

    /*return match;*/
}

uint32_t icmp_cksum (sr_icmp_t3_hdr_t *icmpHdr, int len) {
    uint16_t currChksum, calcChksum;

    currChksum = icmpHdr->icmp_sum; 
    icmpHdr->icmp_sum = 0;
    calcChksum = cksum(icmpHdr, len);
    icmpHdr->icmp_sum = currChksum;

    return calcChksum;
}



struct sr_rt* sr_rt_entry(struct sr_instance* sr, char* dest, char* gw, char* mask,char* if_name)
{
    struct sr_rt* rt_walker = 0;
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    if(inet_aton(dest,&dest_addr) == 0)
    { 
        fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                dest);
        return NULL; 
    }
    if(inet_aton(gw,&gw_addr) == 0)
    { 
        fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                gw);
        return NULL; 
    }
    if(inet_aton(mask,&mask_addr) == 0)
    { 
        fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                mask);
        return NULL; 
    }




    rt_walker = (struct sr_rt*)malloc(sizeof(struct sr_rt));
  
    rt_walker->next = 0;
    rt_walker->dest = dest_addr;
    rt_walker->gw   = gw_addr;
    rt_walker->mask = mask_addr;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);

    return rt_walker;

} 
