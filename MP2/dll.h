#ifndef _DOUBLLY_LINKED_LIST_H_
#define _DOUBLLY_LINKED_LIST_H_

/* Structure for holding every entry of link list */
typedef struct _dll_entry_t {
	void *data;
        struct _dll_entry_t *next,*prev;
}dll_entry_t;

/* Structure for holding the head to the list */
typedef struct _dll_t {
	unsigned int size;
        dll_entry_t *head,*tail;
}dll_t;
 

void dll_init(dll_t *l);
void dll_destroy(dll_t *l);
void dll_add_to_tail(dll_t *l, void *data);
void* dll_remove_from_head(dll_t *l);
dll_entry_t* dll_pointer_at(dll_t *l,int index);
void* dll_at(dll_t *l,int index);
int dll_size(dll_t *l);

#endif
