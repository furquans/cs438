#include <stdio.h>
#include <stdlib.h>

struct header {
	struct node *head;
	struct node *tail;
};

struct node {
	void *data;
	struct node *next;
};

typedef int (*trav_func)(void *); 

void *list_create()
{
	struct header *tmp = malloc(sizeof(*tmp));
	tmp->head = tmp->tail = NULL;
	return tmp;
}

void list_add_tail(struct header *list_head,
		   void *data)
{
	struct node *tmp = malloc(sizeof(*tmp));
	tmp->data = data;
	tmp->next = NULL;

	if (list_head->tail) {
		list_head->tail->next = tmp;
	} else {
		list_head->head = tmp;
	}

	list_head->tail = tmp;
}

void *list_del_head(struct header *list_head)
{
	void *data = NULL;

	if (list_head->head) {
		struct node *tmp;
		tmp = list_head->head;
		data = tmp->data;
		list_head->head = tmp->next;
		if (list_head->head == NULL) {
			list_head->tail = NULL;
		}
		free(tmp);
	}

	return data;
}

void *list_peek_head(struct header *list_head)
{
	void *data = NULL;

	if (list_head->head) {
		data = list_head->head->data;
	}

	return data;
}

void list_trav(struct header *list_head,
		trav_func fnptr)
{
	struct node *tmp = list_head->head;

	while (tmp) {
		if (fnptr(tmp->data) == 0) {
			break;
		}
		tmp = tmp->next;
	}
}

int list_is_empty(struct header *list_head)
{
	if (list_head->head)
		return 0;
	return 1;
}
