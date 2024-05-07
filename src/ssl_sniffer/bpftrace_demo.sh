#/bin/bash

bpftrace_cmd="bpftrace"
bptrace_start_args=""
bptrace_end_args=""

program=$1

if [ -z "$program" ]; then
    echo "To run this script, you need to provide a program to trace"
    echo "Supported libraries: libssl, libnspr, libgnutls"
    echo "Usage: $0 <program>"
    exit 1
fi

real_path=$(which $program)

# Check if the program exists
if [ ! -f "$real_path" ]; then
    echo "The program $program does not exist"
    exit 1
fi

# Check all the libraries that the program uses
libs=$(ldd $real_path | awk '{print $3}' | grep -E 'libssl|libnspr|libgnutls')

if [ -z "$libs" ]; then
    echo "The program $program does not use any of the supported libraries"
    exit 1
fi

printf "The program '$program' uses the following libraries:\n"
echo "$libs"

# Building the bpftrace command

for lib in $libs; do
    if [ $(echo $lib | grep -c "libssl") -gt 0 ]; then
        bptrace_start_args="$bptrace_start_args uprobe:$lib:SSL_read,"
        bptrace_start_args="$bptrace_start_args uprobe:$lib:SSL_write,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:SSL_read,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:SSL_write,"
    elif [ $(echo $lib | grep -c "libnspr") -gt 0 ]; then
        bptrace_start_args="$bptrace_start_args uprobe:$lib:PR_Write,"
        bptrace_start_args="$bptrace_start_args uprobe:$lib:PR_Send,"
        bptrace_start_args="$bptrace_start_args uprobe:$lib:RP_Read,"
        bptrace_start_args="$bptrace_start_args uprobe:$lib:PR_Recv,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:PR_Write,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:PR_Send,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:RP_Read,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:PR_Recv,"
    elif [ $(echo $lib | grep -c "libgnutls") -gt 0 ]; then
        bptrace_start_args="$bptrace_start_args uprobe:$lib:gnutls_record_recv,"
        bptrace_start_args="$bptrace_start_args uprobe:$lib:gnutls_record_send,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:gnutls_record_recv,"
        bptrace_end_args="$bptrace_end_args uretprobe:$lib:gnutls_record_send,"
    fi
done

# Removing the trailing comma
bptrace_start_args=$(echo $bptrace_start_args | sed 's/,$//')
bptrace_end_args=$(echo $bptrace_end_args | sed 's/,$//')

full_cmd="$bpftrace_cmd -e '$bptrace_start_args { @ctx[pid] = arg0; @buf[pid] = arg1; @len[pid] = arg2; } $bptrace_end_args { printf(\"[%d/%s] %s(%p, %p, %d) = %d\", pid, comm, probe, @ctx[pid], @buf[pid], @len[pid], retval); if ((int32)retval > 0) { @slen = retval; if (@slen >= 64) { printf(\" [[\n%s\n]] (truncated)\", str(@buf[pid], @slen)); } else { printf(\" [[\n%s\n]]\", str(@buf[pid], @slen)); } } printf(\"\n\"); delete(@ctx[pid]); delete(@buf[pid]); delete(@len[pid]); }'"

# Running the bpftrace command
eval $full_cmd

exit 0

# Some specific examples

# Anyconnect Cisco (they use libacciscossl.so instead of native libssl)
bpftrace -e '
uprobe:/opt/cisco/anyconnect/lib/libacciscossl.so:SSL_read,
uprobe:/opt/cisco/anyconnect/lib/libacciscossl.so:SSL_write {
        @ctx[pid] = arg0; @buf[pid] = arg1; @len[pid] = arg2;
    }
uretprobe:/opt/cisco/anyconnect/lib/libacciscossl.so:SSL_read,
uretprobe:/opt/cisco/anyconnect/lib/libacciscossl.so:SSL_write {
        printf("[%d/%s] %s(%p, %p, %d) = %d", pid, comm, probe, @ctx[pid], @buf[pid], @len[pid], retval);
        if ((int32)retval > 0) {
            @slen = retval;
            if (@slen >= 64) {
                printf(" [[\n%s\n]] (truncated)", str(@buf[pid], @slen));
            } else {
                printf(" [[\n%s\n]]", str(@buf[pid], @slen));
            }
        }
        printf("\n");
        delete(@ctx[pid]); delete(@buf[pid]); delete(@len[pid]);
    }
'