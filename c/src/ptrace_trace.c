#include "eidos.h"

#ifdef __linux__

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static int append(eidos_trace_t *t, uint64_t ip, uint8_t is_sc)
{
  if (t->count >= t->cap)
  {
    uint32_t ncap = t->cap ? t->cap * 2 : 256;
    eidos_witness_t *nb =
        realloc(t->events, (size_t)ncap * sizeof(eidos_witness_t));
    if (!nb)
      return -ENOMEM;
    t->events = nb;
    t->cap = ncap;
  }
  t->events[t->count++] =
      (eidos_witness_t){.ip = ip, .is_syscall_entry = is_sc};
  return 0;
}

static int trace_loop(pid_t pid, uint32_t max_events,
                      eidos_trace_t *t)
{
  int status;
  if (waitpid(pid, &status, __WALL) < 0)
    return -errno;
  if (!WIFSTOPPED(status))
    return -ESRCH;

  long opts = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
  if (ptrace(PTRACE_SETOPTIONS, pid, 0L, opts) < 0)
    return -errno;

  while (t->count < max_events)
  {
    if (ptrace(PTRACE_SYSCALL, pid, 0L, 0L) < 0)
      break;
    if (waitpid(pid, &status, __WALL) < 0)
      break;

    if (WIFEXITED(status) || WIFSIGNALED(status))
      break;
    if (!WIFSTOPPED(status))
      continue;

    int sig = WSTOPSIG(status);
    uint8_t is_sc = (sig == (SIGTRAP | 0x80)) ? 1 : 0;

#ifdef __x86_64__
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0L, &regs) < 0)
      break;

    if (append(t, regs.rip, is_sc) < 0)
      break;
#else  /* !__x86_64__ */
    break;
#endif /* __x86_64__ */

    if (sig != SIGTRAP && sig != (SIGTRAP | 0x80))
      ptrace(PTRACE_CONT, pid, 0L, (long)sig);
  }

  ptrace(PTRACE_DETACH, pid, 0L, 0L);
  return 0;
}

int eidos_trace_pid(pid_t pid, uint32_t max_events,
                    eidos_trace_t *out)
{
  memset(out, 0, sizeof(*out));
  if (ptrace(PTRACE_SEIZE, pid, 0L, 0L) < 0)
    return -errno;
  if (ptrace(PTRACE_INTERRUPT, pid, 0L, 0L) < 0)
  {
    ptrace(PTRACE_DETACH, pid, 0L, 0L);
    return -errno;
  }
  return trace_loop(pid, max_events, out);
}

int eidos_trace_exec(char *const argv[], uint32_t max_events,
                     eidos_trace_t *out)
{
  memset(out, 0, sizeof(*out));
  pid_t child = fork();
  if (child < 0)
    return -errno;

  if (child == 0)
  {
    if (ptrace(PTRACE_TRACEME, 0, 0L, 0L) < 0)
      _exit(1);
    execvp(argv[0], argv);
    _exit(1);
  }

  return trace_loop(child, max_events, out);
}

void eidos_trace_free(eidos_trace_t *t)
{
  if (!t)
    return;
  free(t->events);
  t->events = NULL;
  t->count = 0;
  t->cap = 0;
}

#else /* !__linux__ */

int eidos_trace_pid(pid_t pid, uint32_t max_events,
                    eidos_trace_t *out)
{
  (void)pid;
  (void)max_events;
  (void)out;
  return -ENOSYS;
}

int eidos_trace_exec(char *const argv[], uint32_t max_events,
                     eidos_trace_t *out)
{
  (void)argv;
  (void)max_events;
  (void)out;
  return -ENOSYS;
}

void eidos_trace_free(eidos_trace_t *t)
{
  if (!t)
    return;
  free(t->events);
  t->events = NULL;
  t->count = 0;
  t->cap = 0;
}

#endif /* __linux__ */
