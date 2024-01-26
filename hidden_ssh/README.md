# hidden_ssh

This program is a proof of concept of hijacking `write` syscalls to inject a backdoor into `sshd` processes.

## Usage

Before compiling the program, you'll need to edit the `filename` and `overwritten_content` variables in `hidden_ssh.c` to match your needs. Then, compile the program:

```bash
$ make
```

After compiling the program, run it as root:

```bash
$ ./hidden_ssh
```

> **Important:** It's necessary for the targetted user to have a `~/.ssh/authorized_keys` file and contain a larger key than the one we are injecting. Otherwise, the injection will fail.

You can now connect to the targetted user using the private key associated with the public key that you've injected.

```bash
$ ssh user@host -i <private_key>
```

## Roadmap

- [ ] Add support for multiple users at runtime
- [ ] Have triggers to inject at only specific times
- [ ] Hide from syslogs