#include <string.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "cred_store.h"

#define FLASH_CRED_A   0x74000
#define FLASH_CRED_B   0x75000
#define CRED_MAGIC     0x31445243u      /* "CRD1" */

struct __attribute__((packed)) cred_entry {
    uint8_t used;
    uint8_t slot;
    uint8_t rp[32];
    uint8_t id[CRED_ID_LEN];
    uint8_t pub[64];
};

struct __attribute__((packed)) cred_snapshot {
    uint32_t magic;
    uint32_t seq;
    uint8_t  serial[SE_SERIAL_LEN];
    uint8_t  pad[3];
    struct cred_entry e[SE_CRED_SLOTS];
    uint32_t crc;
};

#define SNAP_PROG_LEN (((sizeof(struct cred_snapshot) + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)
_Static_assert(sizeof(struct cred_snapshot) <= FLASH_SECTOR_SIZE, "credential table must fit one sector");

static struct cred_snapshot g_snap;     /* RAM copy of the active table */
static uint32_t g_active_off;           /* sector the active copy was read from / written to */
static bool g_open;

static uint32_t crc32(const uint8_t *d, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *d++;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(c & 1u));
    }
    return ~c;
}

static bool snap_valid(const struct cred_snapshot *s)
{
    return s->magic == CRED_MAGIC &&
           s->crc == crc32((const uint8_t *)s, offsetof(struct cred_snapshot, crc));
}

static const struct cred_snapshot *flash_snap(uint32_t off)
{
    return (const struct cred_snapshot *)(XIP_BASE + off);
}

/* Write g_snap (seq already updated) into `off`.  Runs from RAM. */
static int __not_in_flash_func(snap_write)(uint32_t off)
{
    static uint8_t buf[SNAP_PROG_LEN];
    memset(buf, 0xFF, sizeof(buf));
    g_snap.crc = crc32((const uint8_t *)&g_snap, offsetof(struct cred_snapshot, crc));
    memcpy(buf, &g_snap, sizeof(g_snap));
    flash_range_erase(off, FLASH_SECTOR_SIZE);
    flash_range_program(off, buf, SNAP_PROG_LEN);
    if (memcmp((const void *)(XIP_BASE + off), buf, sizeof(g_snap)) != 0)
        return CRED_E_FLASH;
    return CRED_OK;
}

static uint32_t other_off(void) { return g_active_off == FLASH_CRED_A ? FLASH_CRED_B : FLASH_CRED_A; }

/* Persist the table: write the inactive sector, then it becomes the active one. */
static int persist(void)
{
    uint32_t target = other_off();
    g_snap.seq++;
    int r = snap_write(target);
    if (r != CRED_OK) { g_snap.seq--; return r; }
    g_active_off = target;
    return CRED_OK;
}

int cred_store_open(const uint8_t serial[SE_SERIAL_LEN])
{
    const struct cred_snapshot *a = flash_snap(FLASH_CRED_A), *b = flash_snap(FLASH_CRED_B), *best = NULL;
    bool va = snap_valid(a), vb = snap_valid(b);

    if (va && vb) best = (b->seq > a->seq) ? b : a;
    else if (va)  best = a;
    else if (vb)  best = b;

    g_open = false;
    if (best) {
        if (memcmp(best->serial, serial, SE_SERIAL_LEN) != 0)
            return CRED_E_CHIP;                       /* chip swapped after enrolment */
        memcpy(&g_snap, best, sizeof(g_snap));
        g_active_off = (best == a) ? FLASH_CRED_A : FLASH_CRED_B;
        g_open = true;
        return CRED_OK;
    }
    /* First boot (or both copies unreadable): start with an empty table bound to this chip.
     * Any legacy data in these sectors (older firmware) is erased by the write. */
    memset(&g_snap, 0, sizeof(g_snap));
    g_snap.magic = CRED_MAGIC;
    g_snap.seq = 0;
    memcpy(g_snap.serial, serial, SE_SERIAL_LEN);
    g_active_off = FLASH_CRED_B;                      /* persist() writes to A first */
    if (persist() != CRED_OK)
        return CRED_E_FLASH;
    /* make sure the other sector cannot be mistaken for a newer table */
    flash_range_erase(FLASH_CRED_B, FLASH_SECTOR_SIZE);
    g_open = true;
    return CRED_NEW;
}

int cred_pick_free(uint8_t *slot)
{
    if (!g_open) return CRED_E_FLASH;
    for (unsigned i = 0; i < SE_CRED_SLOTS; i++) {
        bool taken = false;
        for (unsigned k = 0; k < SE_CRED_SLOTS; k++)
            if (g_snap.e[k].used == 1 && g_snap.e[k].slot == SE_CRED_SLOT_FIRST + i) taken = true;
        if (!taken) { *slot = (uint8_t)(SE_CRED_SLOT_FIRST + i); return CRED_OK; }
    }
    return CRED_E_FULL;
}

int cred_commit(uint8_t slot, const uint8_t rp[32], const uint8_t id[CRED_ID_LEN], const uint8_t pub[64])
{
    if (!g_open) return CRED_E_FLASH;
    for (unsigned k = 0; k < SE_CRED_SLOTS; k++) {
        if (g_snap.e[k].used != 1) {
            struct cred_entry saved = g_snap.e[k];
            g_snap.e[k].used = 1;
            g_snap.e[k].slot = slot;
            memcpy(g_snap.e[k].rp, rp, 32);
            memcpy(g_snap.e[k].id, id, CRED_ID_LEN);
            memcpy(g_snap.e[k].pub, pub, 64);
            int r = persist();
            if (r != CRED_OK) g_snap.e[k] = saved;
            return r;
        }
    }
    return CRED_E_FULL;
}

int cred_find(const uint8_t rp[32], const uint8_t id[CRED_ID_LEN], uint8_t *slot, uint8_t pub[64])
{
    int found = -1;
    if (!g_open) return CRED_E_NOTFOUND;
    for (unsigned k = 0; k < SE_CRED_SLOTS; k++) {          /* no early exit: same work for every lookup */
        uint8_t diff = (uint8_t)(g_snap.e[k].used != 1);
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(g_snap.e[k].rp[i] ^ rp[i]);
        for (int i = 0; i < CRED_ID_LEN; i++) diff |= (uint8_t)(g_snap.e[k].id[i] ^ id[i]);
        if (diff == 0) found = (int)k;
    }
    if (found < 0) return CRED_E_NOTFOUND;
    *slot = g_snap.e[found].slot;
    if (pub) memcpy(pub, g_snap.e[found].pub, 64);
    return CRED_OK;
}

int cred_wipe(void)
{
    if (!g_open) return CRED_E_FLASH;
    uint32_t old = g_active_off;
    memset(g_snap.e, 0, sizeof(g_snap.e));
    int r = persist();
    if (r == CRED_OK)
        flash_range_erase(old, FLASH_SECTOR_SIZE);        /* the old copy listed relying parties: drop it */
    return r;
}

unsigned cred_count(void)
{
    unsigned n = 0;
    for (unsigned k = 0; k < SE_CRED_SLOTS; k++) n += (g_snap.e[k].used == 1);
    return n;
}
