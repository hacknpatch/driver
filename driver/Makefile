obj-m += vencrypt.o
vencrypt-objs := vencrypt-module.o vencrypt-strings.o vencrypt-crypto.o vencrypt-buffers.o

obj-m += tests.o
tests-objs := tests-module.o vencrypt-strings.o vencrypt-crypto.o vencrypt-buffers.o

# modules_install = /lib/module/<kernel_release>/extra/
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
