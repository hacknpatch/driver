obj-m += vencrypt.o
vencrypt-objs := vencrypt-main.o vencrypt-crypto.o 

obj-m += tests.o
tests-objs := tests-main.o vencrypt-crypto.o 

# modules_install = /lib/module/<kernel_release>/extra/
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
