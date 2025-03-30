#include <stdbool.h>
#include <stdint.h>

#define SLIDING_WINDOW_INIT ((struct sliding_window){ 0 })

struct sliding_window {
    uint64_t bitmap;
    uint64_t last_counter;
};

bool sliding_window_is_replay(
        struct sliding_window *swin, uint64_t counter, struct sliding_window *swin_new);
