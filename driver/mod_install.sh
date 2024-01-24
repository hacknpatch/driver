module="vencrypt"
wildcard="/dev/${module}_*"

for d in ${wildcard}; do
    if [ -e $d ]; then
        sudo rm $d        
    fi	
done

test -n "$(grep -e "^${module} " /proc/modules)"
if [ $? -eq 0 ]; then
	sudo rmmod ${module}
fi

sudo insmod ${module}.ko key=C0FFEE encrypt=1
sudo chown -R root:${USER} ${wildcard}
sudo chmod -R 660 ${wildcard}
