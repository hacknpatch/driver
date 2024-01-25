# driver
I have only tested this driver in ubuntu 22.04 - 64bit x86 so far with the kernel
`6.5.0-14-generic`. I would like to cross-compile for 32bit arm and test
with qemu via github actions if I had time [https://github.com/hacknpatch/driver/issues/5]

TODOs:
* encryption using linux kernel API. [https://github.com/hacknpatch/driver/issues/1]
* locking. [https://github.com/hacknpatch/driver/issues/2]
* clean up the state logic. [https://github.com/hacknpatch/driver/issues/3]
* deal with paritally read packet / message when new writer reopens [https://github.com/hacknpatch/driver/issues/4]
  

## build 

```shell
cd ./driver
make
```

some scripts for installing / removing the module.
```shell
./mod_install.sh
./mod_remove.sh
```

for testing I currently 
```shell
cat /dev/vencrypt_read
echo "this is my string" > /dev/vencrypt_write
```

I will change the to using `/dev/vencrypt_pt` and `/dev/vencrypt_ct` by change 
that names in the module init by reading the module param `encrypt`. 
I.e. something like:
```c
device_create(..., cypher_encrypt ? "/dev/vencrypt_pt" : "/dev/vencrypt_ct")
```


## linux kernel formating 
I'm using clang-format to fomat my code.
```shell
clang-format -style=file:clang-format.txt -i ./driver/vencrypt.c
```
The format file I used is https://github.com/torvalds/linux/blob/master/.clang-format

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
  
