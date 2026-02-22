#include <stdlib.h>

int evictAnyLruHandle(void);

#define ALLOC_ZERO_INIT 1
#define ALLOC_USE_LRU   2

void *gameAlloc(unsigned int size, int flags)
{
	int can_evict;
	void *ptr;

	can_evict = (flags & ALLOC_USE_LRU) != 0;
	ptr = NULL;
	while (1) {
		if (ptr == NULL) {
			if (flags & ALLOC_ZERO_INIT)
				ptr = calloc(size, 1);
			else
				ptr = malloc(size);
		}
		if (ptr == NULL && can_evict && evictAnyLruHandle() == 0) {
			can_evict = 0;
		}
		if (ptr == NULL && !can_evict)
			break;
		if (ptr != NULL)
			return ptr;
	}
	return NULL;
}
