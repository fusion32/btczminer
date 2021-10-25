// NOTE: This will work on windows only.

#ifndef THREAD_HH_
#define THREAD_HH_

#include "common.hh"
#include <intrin.h>
#include <windows.h>
#include <process.h>

// ----------------------------------------------------------------
// utility
// ----------------------------------------------------------------
static INLINE
i32 num_cpu_cores(void){
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
}

// ----------------------------------------------------------------
// atomics
// ----------------------------------------------------------------
static INLINE
i32 atomic_add(i32 *ptr, i32 value){
	return _InterlockedExchangeAdd((volatile long*)ptr, value);
}

static INLINE
i32 atomic_exchange(i32 *ptr, i32 value){
	return _InterlockedExchange((volatile long*)ptr, value);
}

// ----------------------------------------------------------------
// barrier
// ----------------------------------------------------------------
typedef SYNCHRONIZATION_BARRIER barrier_t;

static INLINE
void barrier_init(barrier_t *barrier, i32 num_threads){
	BOOL result = InitializeSynchronizationBarrier(barrier, num_threads, -1);
	if(result == FALSE)
		FATAL_ERROR("failed to initialize barrier\n");
}

static INLINE
void barrier_delete(barrier_t *barrier){
	DeleteSynchronizationBarrier(barrier);
}

static INLINE
void barrier_wait(barrier_t *barrier){
	EnterSynchronizationBarrier(barrier, 0);
}

// ----------------------------------------------------------------
// thread
// ----------------------------------------------------------------
typedef HANDLE thread_t;

void thread_spawn(thread_t *thr, void (*func)(void*), void *arg){
	*thr = (HANDLE)_beginthreadex(NULL, 0,
		(_beginthreadex_proc_type)func, arg, 0, NULL);
	if(*thr == NULL)
		FATAL_ERROR("failed to spawn thread\n");
}

void thread_join(thread_t *thr){
	if(WaitForSingleObject(*thr, INFINITE) != WAIT_OBJECT_0)
		FATAL_ERROR("failed to join thread\n");
}

#endif //THREAD_HH_
