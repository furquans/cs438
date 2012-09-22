#include<stdio.h>
#include<stdlib.h>
#include "link_list.h"

int main()
{
	void *list_head,*tmp;
	int i;
	int *ptr;

	/* Create a new linked list */
	list_head = ll_create_head();


	for (i=1;i<21;i++) {
		int *ptr;
		ptr = malloc(sizeof(*ptr));

		*ptr = i;

		/* Add any data to tail of link list */
		ll_add_tail(list_head,
			    ptr);
	}

	/* Traverse list */
	ll_for_each_entry(list_head,
			  tmp,
			  ptr) {
		printf("Data is %d\n",*ptr);
	}

	/* Removing entries one by one from list */
	for(i=1;i<21;i++) { 
		ptr = ll_remove_first(list_head);
		printf("removed:%d\n",*ptr);
	}
}
