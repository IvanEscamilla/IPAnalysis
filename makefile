CC 		= gcc
FLAGS   = -std=c99 -o
WARN_AS_ERRORS_FLAGS = -pedantic-errors\
                       -Wall\
                       -Wextra\
                       -Werror\
                       -Wconversion
CFLAGS               = $(WARN_AS_ERRORS_FLAGS)\
                       $(FLAGS)
SRCS = IPAnalysis.c
OBJS = IPAnalysis.o

all:
	$(CC) $(SRCS) $(CFLAGS) $(OBJS)

clean:
	 rm $(OBJS)