# m = dynamic module
obj-m += vencrypt.o
obj-m += crypto_test.o

# CC := x86_64-linux-gnu-gcc-12
#CONFIG_MODULE_SIG=n

# modules_install = /lib/module/<kernel_release>/extra/
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
