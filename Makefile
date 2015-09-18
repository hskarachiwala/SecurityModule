LDFLAGS=-lgcrypt -lgpg-error
LIBFLAGS=`libgcrypt-config --cflags`
all:
	gcc -g -c gatorenc.c $(LIBFLAGS)
	gcc -o gatorenc gatorenc.o $(LIBFLAGS) $(LDFLAGS)
	gcc -g -c gatordec.c $(LIBFLAGS)
	gcc -o gatordec gatordec.o $(LIBFLAGS) $(LDFLAGS)
clean:
	find . -type f -name '*.o' -delete
	find . -type f -name '*.uf' -delete
