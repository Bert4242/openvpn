# 02: `delete_all_dhcp_fo()` leaves every second `foreign_option_*` entry and leaks memory

- **Severity:** High
- **Platforms:** Unix (non-Windows, non-Android)
- **Status:** confirmed with a test program
- **Upstream:** PR #1121 described this exact problem. It was closed without merging on
  2026-10-13 and is still unfixed on master.

## Where

- `src/openvpn/options.c`: `delete_all_dhcp_fo()`, around line 1017 (current branch: 1015).
- **Callers:**
  - `remove_option()` for `-dhcp-option`
  - `update_option()` for the first `dhcp-option` line of a PUSH_UPDATE; shared through
    `reset_dhcp_options()` on master

```c
for (current = *list, prev = NULL; current != NULL; current = current->next)
{
    if (<is foreign_option_N=dhcp-option ...>)
    {
        if (prev) prev->next = current->next; else *list = current->next;
        o->foreign_option_index--;
    }
    prev = current;          /* <-- bug: prev becomes the node that was just unlinked */
}
```

## What goes wrong

1. **Every second entry survives.** After a node is unlinked, `prev` points at that detached
   node, so unlinking the *next* matching node changes only the detached node. New env items
   are added at the head of the list (`add_env_item`), so pushed `dhcp-option` entries sit
   next to each other. About every second entry stays, yet `foreign_option_index` still
   counts down for all of them.
2. **Memory leak.** `c->c2.es` is created with `env_set_create(NULL)` (`init.c:4142`), so its
   items are allocated with `malloc`. Removed items are never freed, and every PUSH_UPDATE
   that touches dhcp-options leaks the strings.

**Consequence:** `--up` scripts, plugins, and `dns-updown` (through the
`dhcp_options_postprocess_dns` conversion) can see out-of-date
`foreign_option_N=dhcp-option DNS/DOMAIN-SEARCH …` values. When the new push has fewer
dhcp-options than the old one, the leftover higher-numbered entries are never overwritten.

## Reproduction (already run)

A test program built from the verbatim function source, run on 3 adjacent
`foreign_option_*` entries plus one other variable:

```
foreign_option_index=0
  left: foreign_option_2=dhcp-option DOMAIN-SEARCH old.corp
  left: dev=tun0
```

**End-to-end check:**

1. The server pushes three options: `dhcp-option DNS 10.0.0.1`,
   `dhcp-option DOMAIN-SEARCH old.corp` and `dhcp-option DOMAIN old.corp`.
2. Then send `push-update-cid <cid> "dhcp-option DNS 10.0.0.2"`.
3. A client `--up` script that dumps `foreign_option_*` still sees
   `foreign_option_2=dhcp-option DOMAIN-SEARCH old.corp`.

## Proposed fix

Prefer reusing the env_set API so that freeing is handled correctly. Otherwise, fix the loop:

```c
static void
delete_all_dhcp_fo(struct options *o, struct env_set *es)
{
    struct env_item **link = &es->list;
    while (*link)
    {
        struct env_item *cur = *link;
        const char *v = strchr(cur->string, '=');
        if (!strncmp(cur->string, "foreign_option_", sizeof("foreign_option_") - 1)
            && v && !strncmp(v + 1, "dhcp-option ", sizeof("dhcp-option ") - 1))
        {
            *link = cur->next;
            o->foreign_option_index--;
            if (!es->gc)
            {
                secure_memzero(cur->string, strlen(cur->string));
                free(cur->string);
                free(cur);
            }
            continue;           /* do not advance link */
        }
        link = &cur->next;
    }
}
```

- **Signature change.** The function currently takes `struct env_item **list`. It needs the
  `env_set` to know how items were allocated (`es->gc`). Change its callers to pass `es`.
  Alternatively, gather the names and call `env_set_del()` for each.
- **Related gap.** `dhcp_options_postprocess_dns()` does `strchr(env_str, '=') + 1` without a
  NULL check on `env_set_get()`. With a correct index this cannot crash, but add a guard.

## Tests

Add a unit test that fills an `env_set` (with `gc == NULL` and with a gc) with N adjacent
`foreign_option_*=dhcp-option …` entries plus other variables. Call the function and assert:

- no `foreign_option_*` is left
- `foreign_option_index == 0`
- the other variables are untouched
- for the malloc case, the leak check passes (run under ASan in CI)
