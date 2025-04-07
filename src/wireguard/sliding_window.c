#include "wireguard/sliding_window.h"

#include <limits.h>
#include <stddef.h>

// implementation is based on RFC 2401, Appendix C
bool sliding_window_is_replay(struct sliding_window *swin, uint64_t counter,
        struct sliding_window *swin_new) {
    static const uint64_t window_size = sizeof(swin->bitmap) * CHAR_BIT;

    if (counter > swin->last_counter) {
        // new larger sequence number
        uint64_t diff = counter - swin->last_counter;

        if (diff < window_size) {
            // in window
            swin_new->bitmap = swin->bitmap << diff;
            // set bit for this packet
            swin_new->bitmap |= 1;
        } else {
            // way larger counter: set bit only for this packet
            swin_new->bitmap = 1;
        }

        swin_new->last_counter = counter;

        return false;
    }

    uint64_t diff = swin->last_counter - counter;
    if (diff >= window_size) {
        // too old or wrapped
        return true;
    }

    uint64_t this_bit = ((uint64_t)1 << diff);
    if (swin->bitmap & this_bit) {
        // already seen
        return true;
    }

    // mark as seen
    swin_new->bitmap = swin->bitmap | this_bit;
    swin_new->last_counter = swin->last_counter;

    // out of order but good
    return false;
}
