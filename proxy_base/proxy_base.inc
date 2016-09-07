PROXY_BASE_DIR = $(PRG_DIR)/../proxy_base
SRC_C += $(PROXY_BASE_DIR)/ssl_util.c $(PROXY_BASE_DIR)/proxy_ssl.c
SRC_CC += $(PROXY_BASE_DIR)/channel.cpp
SRC_S += user_memcpy_linux.S
LIBS   += base base-common cxx stdcxx libc config libcrypto libssl vfs_jitterentropy
INC_DIR  += $(PRG_DIR) $(PROXY_BASE_DIR)
vpath user_memcpy_linux.S $(PRG_DIR)/../custom_memcpy_src/
