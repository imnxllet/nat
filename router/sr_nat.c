#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  memset(nat->ports, 0, TOTAL_PORTS);
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */


  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  /**/
  struct sr_nat_mapping *current = NULL;
  struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping));
  current = nat->mappings;

  while (current != NULL) {
    if (current->type == type && current->aux_ext == aux_ext) {
      memcpy(copy, current, sizeof(sr_nat_mapping));
      break;
    }
    current = current->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *current = NULL;
  struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping));
  current = nat->mappings;

  while (current != NULL) {
    if (current->type == type && current>aux_ext == aux_ext && current->ip_int == ip_int) {
      memcpy(copy, current, sizeof(sr_nat_mapping));
      break;
    }
    current = current->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  /*struct sr_nat_mapping *mapping = NULL;*/
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping)); 

  mapping->type = type;
  mapping->last_updated = time(NULL);
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->conns = NULL;

  struct sr_nat_mapping *head_mapping = nat->mappings;
  nat->mappings = mapping;
  mapping->next = head_mapping;


  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/* Check if packer incoming interface is eth1 */
int is_nat_internal_iface(char *iface) {
  return strcmp(iface, NAT_INTERNAL_INTERFACE) == 0 ? 1 : 0;
}

/* Check if packer incoming interface is eth2 */
int is_nat_external_iface(char *iface) {
  return strcmp(iface, NAT_EXTERNAL_INTERFACE) == 0 ? 1 : 0;
}

/* Generate a port for external mapping */
int generate_unique_port(struct sr_nat *nat) {

  pthread_mutex_lock(&(nat->lock));

  uint16_t *available_ports = nat->ports;
  int i;

  for (i = MIN_PORT; i <= TOTAL_PORTS; i++) {
    if (available_ports[i] == 0) {
      available_ports[i] = 1;
      printf("Allocated port: %d\n", i);

      pthread_mutex_unlock(&(nat->lock));
      return i;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return -1;
}