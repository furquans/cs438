#include<stdio.h>
#include<stdlib.h>

/* Structure for holding every entry of link list */
typedef struct list_entry {
	void *data;
	struct list_entry *next;
}LIST_ENTRY;

/* Structure for holding the head to the list */
typedef struct list_head {
	LIST_ENTRY *first;
	LIST_ENTRY *last;
}LIST_HEAD;

/* Pointer to the header */
typedef LIST_HEAD* LIST_HEAD_PTR;
/* Pointer to the link list entry */
typedef LIST_ENTRY* LIST_ENTRY_PTR;

/*
 * Func: ll_create_head
 * Desc: Create and initialize header to a new list
 *
 */
void *ll_create_head()
{
	LIST_HEAD_PTR head = malloc(sizeof(*head));
	head->first = NULL;
	head->last  = NULL;
	return((void*)head);
}

void ll_destroy_head(void *head)
{
	free(head);
}

void ll_add_tail(void *list,
		 void *data)
{
	LIST_HEAD_PTR head = (LIST_HEAD_PTR)list;
	LIST_ENTRY_PTR new;

	if (head == NULL) {
		printf("List error: Head null\n");
		exit(1);
	}

	new = malloc(sizeof(*new));
	new->data = data;
	new->next = NULL;

	if (head->first == NULL) {
		head->first = new;
	} else {
		head->last->next = new;
	}

	head->last = new;
}

void *ll_remove_first(void *list)
{
	LIST_HEAD_PTR head = (LIST_HEAD_PTR)list;
	LIST_ENTRY_PTR tmp;
	void *data;

	if ((head == NULL) || (head->first == NULL)) {
		printf("List: Nothing to return\n");
		return(NULL);
	}

	tmp = head->first;

	head->first = tmp->next;

	if (head->first == NULL) {
		head->last = NULL;
	}

	data = tmp->data;
	free(tmp);

	return(data);
}

void *ll_head(void *list, void **tmp)
{
	void *data = NULL;
	LIST_ENTRY_PTR ptr;

	ptr = ((LIST_HEAD_PTR)list)->first;

	if (ptr != NULL) {
		data = ptr->data;
	}

	*tmp = ptr;

	return data;
}

void *ll_head_safe(void *list, void **tmp, void **swap)
{
	void *data = ll_head(list,tmp);
	*swap = (*((LIST_ENTRY_PTR*)tmp))->next;

	return data;
}

void *ll_next(void **tmp)
{
	void *data = NULL;
	LIST_ENTRY_PTR ptr = (LIST_ENTRY_PTR)*tmp;

	ptr = ptr->next;

	if (ptr != NULL) {
		data = ptr->data;
	}

	*tmp = ptr;

	return data;
}

void *ll_next_safe(void **tmp, void **swap)
{
	void *data = ll_next(tmp);

	*swap = (*((LIST_ENTRY_PTR*)tmp))->next;

	return data;
}
