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
