#ifndef CRED_STORE_H
#define CRED_STORE_H
/*
 * Credential table.  The private keys live in the secure element; this table
 * (public data only) maps an opaque credential id + relying party to the chip
 * slot that holds the key, so a credential id is useless without this device
 * AND this chip.  Two flash sectors are used alternately (sequence number + CRC)
 * so a power cut during an update never loses the previous valid table.
 */
#include <stdint.h>
#include <stddef.h>
#include "se.h"

#define CRED_ID_LEN 64

#define CRED_OK            0
#define CRED_E_FULL       -1   /* every key slot is in use                   */
#define CRED_E_CHIP       -2   /* table belongs to a different chip           */
#define CRED_E_FLASH      -3
#define CRED_E_NOTFOUND   -4
#define CRED_NEW           1   /* open(): no table existed, an empty one was created */

int  cred_store_open(const uint8_t serial[SE_SERIAL_LEN]);       /* CRED_OK / CRED_NEW / CRED_E_* */
int  cred_pick_free(uint8_t *slot);                              /* lowest free slot, or CRED_E_FULL */
int  cred_commit(uint8_t slot, const uint8_t rp[32], const uint8_t id[CRED_ID_LEN], const uint8_t pub[64]);
int  cred_find(const uint8_t rp[32], const uint8_t id[CRED_ID_LEN], uint8_t *slot, uint8_t pub[64]);
int  cred_wipe(void);                                            /* forget every credential */
unsigned cred_count(void);

#endif
