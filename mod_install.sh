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

module_load_params="key=C0FFEE encrypt=1"

if [ -e ${module}.ko ]; then
    sudo insmod ${module}.ko ${module_load_params}
fi

if [ -e ./driver/${module}.ko ]; then
    sudo insmod ./driver/${module}.ko ${module_load_params}
fi

sudo chown -R root:${USER} ${wildcard}
sudo chmod -R 660 ${wildcard}
