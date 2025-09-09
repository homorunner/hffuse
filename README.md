Example code for fuse patch for 3fs based on 6.8 kernel.

Q: Why `make[1]: *** /lib/modules/6.8.0-.../build: No such file or directory.  Stop.` ?

A: You need linux header:
```bash
sudo apt-get update && sudo apt-get install linux-headers-$(uname -r)
sudo ln -sf /usr/src/linux-headers-$(uname -r) /lib/modules/$(uname -r)/build
```
