typedef int (*audit_callback)(int event_code);

static audit_callback registered_hook = 0;

void register_hook(audit_callback hook_function) {
    registered_hook = hook_function;
}

int fire_event(int event_code) {
    if (registered_hook != 0) {
        return registered_hook(event_code);
    }
    goto done;
done:
    return -1;
}
