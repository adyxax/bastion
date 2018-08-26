CC=clang
DEBUG=-g -fsanitize=address
CFLAGS= ${DEBUG} -Wall -Werror -Wextra -Weverything -Wno-disabled-macro-expansion

sources=$(wildcard src/*.c)
OBJ=$(sources:.c=.o)

all: bastion

bastion: $(OBJ)
	$(CC) ${DEBUG} -o bastion $(OBJ) -lssh -lutil -ltty -lmysqlclient

clean:
	$(RM) bastion *.[do] src/*.[do]

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	$(CC) -MM $(CFLAGS) $*.c > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

# You must compile without -fsanitize=address to use valgrind
valgrind:
	valgrind --leak-check=full --show-leak-kinds=all --trace-children=yes --suppressions=${HOME}/.valgrind_suppressions ./bastion
	#valgrind -v --leak-check=full --show-leak-kinds=all --trace-children=yes --suppressions=${HOME}/.valgrind_suppressions --gen-suppressions=yes ./bastion

debug:
	ASAN_OPTIONS=allow_user_segv_handler=true:detect_leaks=true:fast_unwind_on_malloc=0:check_initialization_order=1:suppressions=asan.supp \
	ASAN_SYMBOLIZER_PATH=/usr/lib/llvm-6.0/bin/llvm-symbolizer \
	./bastion
