#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

// Access hardware timestamp counter
#define RDTSC(cycles) __asm__ volatile ("rdtsc" : "=a" (cycles));

// Serialize execution
#define CPUID() asm volatile ("CPUID" : : : "%rax", "%rbx", "%rcx", "%rdx");

// Intrinsic CLFLUSH for FLUSH+RELOAD attack
#define CLFLUSH(address) _mm_clflush(address);

#define SAMPLES 10000 // TODO: CONFIGURE THIS

#define L1_CACHE_SIZE (32*1024)
#define LINE_SIZE 64
#define ASSOCIATIVITY 8 // num ways
#define L1_NUM_SETS (L1_CACHE_SIZE/(LINE_SIZE*ASSOCIATIVITY)) // = 64
#define NUM_OFFSET_BITS 6
#define NUM_INDEX_BITS 6
#define NUM_OFF_IND_BITS (NUM_OFFSET_BITS + NUM_INDEX_BITS)

uint64_t eviction_counts[L1_NUM_SETS] = {0};
__attribute__ ((aligned (64))) uint64_t trojan_array[32*4096];
__attribute__ ((aligned (64))) uint64_t spy_array[4096];


/* TODO:
 * This function provides an eviction set address, given the
 * base address of a trojan/spy array, the required cache
 * set ID, and way ID.
 *
 * Describe the algorithm used here:
 
 Step 1: The algorithm isolates the tag bits and index bits by right shifting the base address to ignore the offset bits.
 Step 2: Then, it calculates the decimal value of the index bits.
 Step 3: Comparing it to the set ID needed, we can determine if the base (or starting) address of the array has default index bits that are already larger 
        than the index value of the set in the victim's cache (ie. does the default bits located in the index segment of the base address already pass 
        the required set value from the victim's cache WHICH THE ADDRESSES IN THE TROJAN/SPY ARRAY MUST MATCH FOR THE ATTACK TO WORK. This could be a problem 
        since the addresses located in the trojan/spy array can only grow upward past the base address. Thus if the index segment of the base addr is already
        larger than a set ID from the victim's cache, then the malicious array might not match all necessary values linked to all possible sets in the victim's cache
        to cause the appropriate conflict misses necessary for the attack to work):

        3a) IF the value of the index bits in the base addr are already bigger than the required set ID,
           - We use the tag bits as determined in step 1 and left shift 6 to leave room for the index bits in the address.
           - We match the index bits of the set in the victim's cache by using L1_NUM_SETS (whose value is 64) + set ID as the index value of the eviction set address.
            Since values greater than or equal to 64 need 7 bits, and the index bits only use 6 bits, this means that we can still arrive at an address within the array where the index
            bits will match. For example, 64 + 1 (the set ID) = 65 is 100 0001 in binary, which, when only its 6 least sig bits are used designated as index bits, will result in an 
            index value of 1, as desired. We then left shift 6 to leave room for the "offset" bits in the address.
           - For the eviction set, the offset bits do not matter. Rather, (L1_NUM_SETS * LINE_SIZE * way) generates tag bits for each address in an eviction set that are different
            from the tag bits of the addresses used in the victim's cache. For example, given L1_NUM_SIZE = L1_NUM_SETS = 64, L1_NUM_SETS * LINE_SIZE * way = 64 * 64 * way = 4096 * way.
            4096 = 2^12, which means that its value affects the 13th bit, or greater - all of which impact the tag bits. Therefore, for every way => 1, the least significant
            tag bits are increased according to the way value in the set. (ie. Let's assume tag bits that end with a series like 0000 for simplicity of explanation. When way = 1, 4096*1
            means that the least sig tag bits would be 1. When way = 2, 4096*2 means that the least sig tag bits would be 10. When way = 3, 4096*3 means that the least sig tag bits 
            would be 11. When way = 4, 4096*4 means that the least sig tag bits would have a 100 and so on and so forth until way = 7).
           - After configuring the address as appropriate, the eviction set address is returned.


        3b) IF the value of the index bits in the base addr is not larger than the required set ID,
            - We use the tag bits as determined in step 1 and left shift 6 to leave room for the index bits in the address.
            - We can simply match the index bits of the set ID as the index bits of our eviction set address, as desired. We then left shift 6 to leave room for the "offset" bits in the address.
            - Again, the offset bits of the eviction set do not matter. We follow the above principles as in 3a, to achieve our different tag bits for the eviction set address, assigned 
              according to way.
            - After configuring the address as appropriate, the eviction set address is returned.
 
 */
uint64_t* get_eviction_set_address(uint64_t *base, int set, int way)
{
    uint64_t tag_bits = (((uint64_t)base) >> NUM_OFF_IND_BITS); 
    int idx_bits = (((uint64_t)base) >> NUM_OFFSET_BITS) & 0x3f;

    if (idx_bits > set) {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) +
                               (L1_NUM_SETS + set)) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    } else {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) + set) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way)); 
    }
}

/* This function sets up a trojan/spy eviction set using the
 * function above.  The eviction set is essentially a linked
 * list that spans all ways of the conflicting cache set.
 *
 * i.e., way-0 -> way-1 -> ..... way-7 -> NULL
 *
 */
void setup(uint64_t *base, int assoc) // exploits spatial and temporal locality
{
    uint64_t i, j;
    uint64_t *eviction_set_addr; //stores an address

    // Prime the cache set by set (i.e., prime all lines in a set) so basically at address for way-0, it stores the address for way-1; address at way-1 stores address for way-2...
    for (i = 0; i < L1_NUM_SETS; i++) { //parses from set to set
        eviction_set_addr = get_eviction_set_address(base, i, 0); //eviction_set_addr stores the address at the beginning of the set
        for (j = 1; j < assoc; j++) { //parses from cache line to cache line within the set
            *eviction_set_addr = (uint64_t)get_eviction_set_address(base, i, j); //at the memory location of the address at base, store the eviction set address
            eviction_set_addr = (uint64_t *)*eviction_set_addr; //make the eviction_set_addr point to this new eviction set address just found
        }
        *eviction_set_addr = 0;
    }
}

/* TODO:
 *
 * This function implements the trojan that sends a message
 * to the spy over the cache covert channel.  Note that the
 * message forgoes case sensitivity to maximize the covert
 * channel bandwidth.
 *,
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
void trojan(char byte)
{
    int set;
    uint64_t *eviction_set_addr;
    uint64_t *trojan_cache_addr;

    if (byte >= 'a' && byte <= 'z') { // from 97 to 122
        byte -= 32; // makes sure that these characters can be matched to cache set of limit 64 sets
        //foregoes case sensitivity
    }
    if (byte == 10 || byte == 13) { // encode a new line
        set = 63; // automatically set index as 63 = the last possible set index
    } else if (byte >= 32 && byte < 96) {
        set = (byte - 32); // assign sets according to byte value, limit at index 63
    } else {
        printf("pp trojan: unrecognized character %c\n", byte);
        exit(1);
    }

    eviction_set_addr = get_eviction_set_address(spy_array, set, 0); //gets the beginning address of the cache set in spy array
    trojan_cache_addr = get_eviction_set_address(trojan_array, set, 0);
    *eviction_set_addr = (uint64_t) trojan_cache_addr; //set spy array's cache set to trojan array's dummy cache set
}

/* TODO:
 *
 * This function implements the spy that receives a message
 * from the trojan over the cache covert channel.  Evictions
 * are timed using appropriate hardware timestamp counters
 * and recorded in the eviction_counts array.  In particular,
 * only record evictions to the set that incurred the maximum
 * penalty in terms of its access time.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
char spy()
{
    int i, j, max_set;
    uint64_t *eviction_set_addr;
    uint64_t start = 0;
    uint64_t end = 0;

    // Probe the cache line by line and take measurements
    max_set = 0;
    uint64_t max_penalty = 0;
    uint64_t penalty;
    for (i = 0; i < L1_NUM_SETS; i++) //goes through, and takes time measurements; at the set affected by the trojan, will parse manipulated cache, resulting in longer runtime
    {
        CPUID();
        //uint64_t before = RDTSC((uint64_t) i);
        RDTSC(start);
        //CPUID();
        eviction_set_addr = get_eviction_set_address(spy_array, i, 0);
        for(j = 1; j < ASSOCIATIVITY; j++) //probe linked lists of cache sets
        {
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
        }
        CPUID();
        RDTSC(end);
        if (end > start){
            penalty = end - start;
        }
       // penalty = __rdtsc() - before;
        if(penalty > max_penalty)
        {
            max_set = i;
            max_penalty = penalty;
        }
    }
    eviction_counts[max_set]++;
}

int main()
{
    FILE *in, *out;
    in = fopen("transmitted-secret.txt", "r");
    out = fopen("received-secret.txt", "w");

    int j, k;
    int max_count, max_set;

    // TODO: CONFIGURE THIS -- currently, 32*assoc to force eviction out of L2
    setup(trojan_array, ASSOCIATIVITY*32);

    setup(spy_array, ASSOCIATIVITY);
    
    for (;;) {
        char msg = fgetc(in);
        if (msg == EOF) {
            break;
        }
        for (k = 0; k < SAMPLES; k++) {
          trojan(msg); 
          spy(); // sets eviction counts?
        }
        for (j = 0; j < L1_NUM_SETS; j++) { // finds the set with the longest eviction time = more cache misses
            if (eviction_counts[j] > max_count) {
                max_count = eviction_counts[j];
                max_set = j;
            }
            eviction_counts[j] = 0; //reset the counts
        }
        if (max_set >= 33 && max_set <= 59) {
            max_set += 32;
        } else if (max_set == 63) {
            max_set = -22;
        }
        fprintf(out, "%c", 32 + max_set);
        max_count = max_set = 0;
    }
    fclose(in);
    fclose(out);
}
