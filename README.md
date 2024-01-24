# driver

## build 

```
cd ./driver
make
```
  
install / remove module  
```
./mod_install.sh
./mod_remove.sh
```

## format to linux kernel style 
```
clang-format -style=file:clang-format.txt -i ./driver/vencrypt.c
```


