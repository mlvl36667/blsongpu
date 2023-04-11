cpp rns.c > rns.i 
gcc -S rns.i 
as -o rns.o rns.s
rm -rf rns.i rns.s

cpp utils.c > utils.i 
gcc -S utils.i 
as -o utils.o utils.s
rm -rf utils.i utils.s

gcc -o rns rns.o  utils.o
rm -rf *.o
