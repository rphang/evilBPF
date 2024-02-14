# hidden_ssh

`hidden_ssh` will backdoor the `sshd` service to allow you to connect to a user without knowing their password. It will either inject a public key into the `~/.ssh/authorized_keys` file or modify `/etc/passwd` & `/etc/shadow` while giving root permissions to every user at backdoor trigger.

## Features

### SSHD Backdoors

#### Public Key

> [!IMPORTANT]
> This will only work if the targetted user has a `~/.ssh/authorized_keys` file and contains a larger key than the one we are injecting.

- [x] Inject a public key into the `authorized_keys`
- [x] Support any user
- [x] Give UID & GID = 0
  
#### Password - WIP

- [ ] Modify `/etc/passwd` & `/etc/shadow` to give UID & GID = 0 to every user at trigger

### Trigger

- [x] Inject only when the connection is made from a specific TCP port

## Usage

Before compiling the program, you'll need to edit the `filename` and `overwritten_content` variables in `hidden_ssh.c` to match your needs. Then, compile the program:

```bash
$ make
```

After compiling the program, run it as root:

```bash
$ ./hidden_ssh
```

> [!IMPORTANT]
> It's necessary for the targetted user to have a `~/.ssh/authorized_keys` file and contain a larger key than the one we are injecting. Otherwise, the injection will fail.

You can now connect to the targetted user using the private key associated with the public key that you've injected.

```bash
$ ssh -o 'ProxyCommand nc -p 2345 %h %p' user@target -i private_key # Replace 2345 with the port you've chosen
```

> [!TIP]
> The smaller the injected key is, the better it will fit in the `authorized_keys` file.
>
> You can use the `ED25519` algorithm to generate a smaller key.
> ```bash
> $ ssh-keygen -t ed25519 -f my_key
> ```

## Detection

- As we are using `bpf_probe_write_user`, messages will be logged in the kernel logs at loading time.

- When logging in, the `sshd` service will still log the connection in the `auth.log` file. (This can be a good future improvement to work on)

> [!NOTE]
> Btw, i know that for now the code is not really clean... at all 💀 ... Looking to improve it one day