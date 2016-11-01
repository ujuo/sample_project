JSONDIR = cJSON
OBJ = $(JSONDIR)/cJSON.o
LIBNAME = $(JSONDIR)/libcjson
TEST = test
STLIBNAME = $(LIBNAME).a
R_CFLAGS = -fpic $(CFLAGS) -Wall -Werror -Wstrict-prototypes -Wwrite-strings

.PHONY: all clean 

$(TEST): wakeup_test.c	$(JSONDIR)/cJSON.c $(JSONDIR)/cJSON.h
	$(CC) $(LIB) $(INCLUDES)  $(JSONDIR)/cJSON.c wakeup_test.c -o wakeup_test -lm -lssl -lcrypto
	
all: $(STLIBNAME) $(TEST)

$(STLIBNAME): $(OBJ)
	ar rcs $@ $<
	
$(OBJ): $(JSONDIR)/cJSON.c $(JSONDIR)/cJSON.h

.c.o:
	$(CC) $(R_CFLAGS) $<
	
clean:
	rm -r $(STLIBNAME) $(TEST) *.o
	