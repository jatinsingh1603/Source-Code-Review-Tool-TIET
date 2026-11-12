#define MAX_SESSIONS 64
#define SQUARE_OF(value) ((value) * (value))

enum session_state { SESSION_OPEN, SESSION_CLOSED };

int count_open(enum session_state *states, int session_count) {
    int open_total = 0;
    for (int slot = 0; slot < session_count && slot < MAX_SESSIONS; slot++) {
        if (states[slot] == SESSION_OPEN) {
            open_total += SQUARE_OF(1);
        }
    }
    return open_total;
}
