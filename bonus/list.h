#ifndef __LIST_H__
#define __LIST_H__

typedef int (*trav_func)(void *);

void *list_create();
void list_add_tail(void *,void *);
void *list_del_head(void *);
void list_trav(void *, trav_func);
void *list_peek_head(void *list_head);

#endif
