CC=clang
DEBUG=-g
CFLAGS= ${DEBUG} -Wall -Werror -Wextra

sources=$(wildcard src/*.c)
OBJ=$(sources:.c=.o)

all: bastion

bastion: $(OBJ)
	$(CC) ${DEBUG} -o bastion $(OBJ) -lssh -lpthread -lssh_threads -lutil

clean:
	$(RM) bastion *.[do] src/*.[do]

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

valgrind:
	valgrind --leak-check=full --show-leak-kinds=all --suppressions=$HOME/.valgrind_suppressions ./bastion
	#valgrind -v --leak-check=full --show-leak-kinds=all --suppressions=$HOME/.valgrind_suppressions --gen-suppressions=yes ./bastion
