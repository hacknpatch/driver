obj-m += vencrypt.o
vencrypt-objs := module.o strings.o crypto.o blocks.o

# modules_install = /lib/module/<kernel_release>/extra/
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
