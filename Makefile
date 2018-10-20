APP = tstrings

GCC = gcc

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SRC := $(wildcard $(SRC_DIR)/*.c)
INC := $(wildcard $(SRC_DIR)/*.h)
OBJ := $(subst $(SRC_DIR),$(OBJ_DIR),$(SRC:%.c=%.o))

C_FLAGS := -g3 -O3 -Wall -I$(SRC_DIR)
C_FLAGS += $(shell pkg-config fuse --cflags)
ifdef WIRESHARK_INC
	C_FLAGS += -I${WIRESHARK_INC}/wiretap
	C_FLAGS += -I${WIRESHARK_INC}
else
	C_FLAGS += -I/usr/include/wireshark/wiretap
	C_FLAGS += -I/usr/include/wireshark
endif

C_FLAGS += $(shell pkg-config --cflags glib-2.0 gtk+-2.0)
LD_FLAGS := $(C_FLAGS)
LD_FLAGS += -lwiretap
LD_FLAGS += -lwireshark
LD_FLAGS += -lwsutil
LD_FLAGS += $(shell pkg-config --libs glib-2.0 gtk+-2.0)

.phony: all $(APP) clean fresh

all: $(APP)

$(APP): $(BIN_DIR)/$(APP)

$(BIN_DIR)/$(APP): $(OBJ)
	$(GCC) $^ -o $@ $(LD_FLAGS)

$(OBJ): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(GCC) -c $< -o $@ $(C_FLAGS)

clean:
	-rm -f $(BIN_DIR)/$(APP)
	-rm -f $(OBJ)

fresh: clean $(APP)
