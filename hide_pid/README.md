# hide_pid

All processes in Linux have a PID (Process IDentifier) that is used to identify them. This is a unique number that is assigned to each process by the kernel. Programs like `ps` and `top` use this PID to identify processes. They work by listing the contents of the `/proc` directory, which contains a directory for each process, named after the PID of the process.

So hiding a process is as simple as removing the directory for that process from `/proc`, right? The problem is that the kernel doesn't allow you to remove directories from `/proc`. So how do we hide a process?

## Tracepoints

When you're using `ps` or `top`, the `getdents64` syscall is used to list the contents of the `/proc` directory. This syscall is traced by the kernel, and a tracepoint is generated for each invocation of this syscall. We can use this tracepoint to alter the contents of the `/proc` directory at execution time. (So we are not really deleting the directory, we are just making it disappear at the output of the syscall)