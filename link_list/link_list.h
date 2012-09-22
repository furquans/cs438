

void *ll_create_head();
void ll_add_tail(void *list,
		 void *data);
void *ll_remove_first(void *list);
void *ll_head(void *list, void **tmp);
void *ll_next(void **tmp);


#define ll_for_each_entry(list, tmp, data) \
  for ( data = ll_head(list, &tmp); tmp != NULL; data = ll_next(&tmp) )
