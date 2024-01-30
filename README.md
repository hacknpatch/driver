# driver

## build
The source code and Makefile are located in the driver directory. There is also a helper install module bash script at
the root of the repository. You can execute it from either directory. Use the following commands:
```shell
cd ./driver
make
../mod_install.sh 1
```

Note: I have only tested this driver on Ubuntu 22.04 - 64bit x86 so far, with the kernel version 6.5.0-14-generic. I am
interested in cross-compiling for 32bit ARM and testing with QEMU via GitHub Actions when I have the time. For more
information, see Issue #5 in GitHub.

## source code:

* module.c  - Contains module file operations (fops) such as read, write, open, release, and also includes module initialization (__init) and exit (__exit) functions. 
* blocks.c  - Manages a pool of blocks and maintains two lists: used and free. 
* crypto.c  - Implements the AES/CBC/PKCS#7 encryption. It utilizes the Linux kernel crypto API.
* strings.c - Provides a function to convert a hex string to a byte array. There might be a better approach available!

## design

Data flow follows this sequence: `write() -> blocks functions -> read()`.

The `struct venc_blocks`, found in `blocks.c|h`, implements a pool of blocks/buffers. It also manages synchronization 
using a `spin_lock` and a `wait_queue`. The wait queue is utilized to notify the `reader`, `writer`, `release`, and 
`open` functions when a new block has been added or freed, or when a final padding block is completed.

## usage:

The driver implements AES/CBC/PKCS#7 encryption. This means data is encrypted in blocks of 16 bytes, and the last block
is always padded using the PKCS#7 method.

The encrypted data format is represented as: `[block[1] block[2] block[3] ... padded_PKCS7_block[N-1]]`.

IMPORTANT: When writing to the driver, if the buffers become full, writing will block until some data is read from the
driver.

IMPORTANT: After closing writing to `/dev/vencrypt_[pt|ct]`, you must fully read/drain `/dev/vencrypt_[ct|pt]` until you
receive ZERO/EOF from read(). Until this is done, opening `/dev/vencrypt_[pt|ct]` for writing will be blocked until the
reader has fully drained the buffers. This ensures the correct application of PKCS#7 padding.

### encryption mode
Load the module with the parameter encrypt=1 to output encrypted data at /dev/vencrypt_ct. If the data written to
`/dev/vencrypt_ct` is a multiple of 16 bytes (e.g., 16, 32, etc.), then an additional fully padded block is added.

### decryption mode
Set the module parameter to encrypt=0 to input encrypted data at `/dev/vencrypt_ct` and read decrypted data from
`/dev/vencrypt_pt`.

## examples

### encrypt
```shell
../mod_install.sh 1
echo "hello" > /dev/vencrypt_pt
cat /dev/vencrypt_ct | base64
$ WasyktyxbiO5e0zq2dDDwA==
```

### decrypt
```shell
../mod_install.sh 0
echo "WasyktyxbiO5e0zq2dDDwA==" | base64 -d > /dev/vencrypt_ct
cat /dev/vencrypt_pt
$ hello
```

### small file example:
```
../mod_install.sh 1

echo hello > hello.txt

cat hello.txt > /dev/vencrypt_pt
cat /dev/vencrypt_ct > hello.bin

../mod_install.sh 0

cat hello.bin > /dev/vencrypt_ct
cat /dev/vencrypt_pt > hello2.txt

cat hello2.txt
```
Note: If anything goes wrong, ensure that you drain the buffer by running `cat /dev/vencrypt_ct` until it blocks.
Alternatively, you can reload the module using `../mod_install.sh 1`.

### Large file example:
For large files, you will need two shells. This is necessary because when the buffer fills up during writing, the writer
will be blocked.

#### encrypt
1st shell:
```
../mod_install.sh 1

cat test.tar.gz > /dev/vencrypt_pt
```
2nd shell:
```
cat /dev/vencrypt_ct > test.bin
```

#### decrypt
1st shell:
```
../mod_install.sh 0

cat test.bin > /dev/vencrypt_ct
```
2nd shell:
```
cat /dev/vencrypt_pt > test2.tar.gz

diff test.tar.gz test2.tar.gz
```

What is interesting is that with larger files, I observe double the performance when using a simple Python script as
compared to using `cat`.  
Python example:
```python
with open('test2.tar.gz', 'wb') as wf:
    with open('/dev/vencrypt_pt', 'rb') as f:
        while c := f.read(16 * 1000):
            wf.write(c)
```

## linux kernel formatting
I'm using clang-format to format my code.
```shell
cd ./drive
find . -type f -name 'venc*.[ch]' -exec clang-format -style=file:../clang-fmt.txt -i {} \;
```
The format file I use is https://github.com/torvalds/linux/blob/master/.clang-format

## machine environment
my current environment is:
```shell
uname -a
Linux gregc-pc 6.5.0-14-generic #14~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon Nov 20 18:15:30 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

```shell
$ gcc-12 -v

Using built-in specs.
COLLECT_GCC=gcc-12
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/12/lto-wrapper
OFFLOAD_TARGET_NAMES=nvptx-none:amdgcn-amdhsa
OFFLOAD_TARGET_DEFAULT=1
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Ubuntu 12.3.0-1ubuntu1~22.04' --with-bugurl=file:///usr/share/doc/gcc-12/README.Bugs --enable-languages=c,ada,c++,go,d,fortran,objc,obj-c++,m2 --prefix=/usr --with-gcc-major-version-only --program-suffix=-12 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-plugin --enable-default-pie --with-system-zlib --enable-libphobos-checking=release --with-target-system-zlib=auto --enable-objc-gc=auto --enable-multiarch --disable-werror --enable-cet --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-offload-targets=nvptx-none=/build/gcc-12-ALHxjy/gcc-12-12.3.0/debian/tmp-nvptx/usr,amdgcn-amdhsa=/build/gcc-12-ALHxjy/gcc-12-12.3.0/debian/tmp-gcn/usr --enable-offload-defaulted --without-cuda-driver --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
Supported LTO compression algorithms: zlib zstd
gcc version 12.3.0 (Ubuntu 12.3.0-1ubuntu1~22.04) 
```
  
