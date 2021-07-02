#pragma once
class CTimer
{
	CTimer
};




#include <assert.h>
#include <limits.h>
#include <stddef.h> 
#include "Common.h"

# define HEAP_EXPORT

typedef void(*uv_timer_cb)(void* handle);

enum eState {
	init	= 0x00000000,
	closing = 0x00000001,
	closed = 0x00000002,
	active = 0x00000004,
}eState;
typedef struct uv_timer_s
{
	ULONG64 timeout;
	ULONG64 repeat;
	ULONG64 start_id;
	eState state;
	uv_timer_cb timer_cb;
	uv_timer_s()
	{
		timeout = 0;
		repeat = 0;
		start_id = 0;
		state = init;
		timer_cb = NULL;
	}

}uv_timer_t;

bool uv__is_closing();


// static int timer_less_than(const struct heap_node* ha,
// 	const struct heap_node* hb) {
// 	const uv_timer_t* a;
// 	const uv_timer_t* b;
// 
// 	a = container_of(ha, uv_timer_t, heap_node);
// 	b = container_of(hb, uv_timer_t, heap_node);
// 
// 	if (a->timeout < b->timeout)
// 		return 1;
// 	if (b->timeout < a->timeout)
// 		return 0;
// 
// 	/* Compare start_id when both have the same timeout. start_id is
// 	* allocated with loop->timer_counter in uv_timer_start().
// 	*/
// 	return a->start_id < b->start_id;
// }



int uv_timer_start(uv_timer_t* handle,
	uv_timer_cb cb,
	ULONG64 timeout,
	ULONG64 repeat) {
	ULONG64 clamped_timeout;

	static ULONG64 timer_counter = 0;

	if (uv__is_closing(handle) || cb == NULL)
		return -1;

	if (uv__is_active(handle))
		uv_timer_stop(handle);

	clamped_timeout = handle->loop->time + timeout;
	if (clamped_timeout < timeout)
		clamped_timeout = (ULONG64)-1;

	handle->timer_cb = cb;
	handle->timeout = clamped_timeout;
	handle->repeat = repeat;
	/* start_id is the second index to be compared in timer_less_than() */
	handle->start_id = timer_counter++;

	heap_insert(timer_heap(handle->loop),
		(struct heap_node*) &handle->heap_node,
		timer_less_than);
	uv__handle_start(handle);

	return 0;
}


int uv_timer_stop(uv_timer_t* handle) {
	if (!uv__is_active(handle))
		return 0;

	heap_remove(timer_heap(handle->loop),
		(struct heap_node*) &handle->heap_node,
		timer_less_than);
	uv__handle_stop(handle);

	return 0;
}


int uv_timer_again(uv_timer_t* handle) {
	if (handle->timer_cb == NULL)
		return -1;

	if (handle->repeat) {
		uv_timer_stop(handle);
		uv_timer_start(handle, handle->timer_cb, handle->repeat, handle->repeat);
	}

	return 0;
}


void uv_timer_set_repeat(uv_timer_t* handle, ULONG64 repeat) {
	handle->repeat = repeat;
}


ULONG64 uv_timer_get_repeat(const uv_timer_t* handle) {
	return handle->repeat;
}


int uv__next_timeout(const uv_loop_t* loop) {
	const struct heap_node* heap_node;
	const uv_timer_t* handle;
	ULONG64 diff;

	heap_node = heap_min(timer_heap(loop));
	if (heap_node == NULL)
		return -1; /* block indefinitely */

	handle = container_of(heap_node, uv_timer_t, heap_node);
	if (handle->timeout <= loop->time)
		return 0;

	diff = handle->timeout - loop->time;
	if (diff > INT_MAX)
		diff = INT_MAX;

	return (int)diff;
}


void uv__run_timers(uv_loop_t* loop) {
	struct heap_node* heap_node;
	uv_timer_t* handle;

	for (;;) {
		heap_node = heap_min(timer_heap(loop));
		if (heap_node == NULL)
			break;

		handle = container_of(heap_node, uv_timer_t, heap_node);
		if (handle->timeout > loop->time)
			break;

		uv_timer_stop(handle);
		uv_timer_again(handle);
		handle->timer_cb(handle);
	}
}


void uv__timer_close(uv_timer_t* handle) {
	uv_timer_stop(handle);
}
