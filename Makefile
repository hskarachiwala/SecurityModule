OBJS = gatorenc
LDFLAGS=-lgcrypt -lgpg-error

all:
	gcc -g -c gatorenc.c `libgcrypt-config --cflags`
	gcc -o gatorenc gatorenc.o `libgcrypt-config --libs` $(LDFLAGS)
clean:
	rm -rf $(OBJS)