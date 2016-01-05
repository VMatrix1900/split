
#ifndef __GENODE_LIBRARY_C_H__
#define __GENODE_LIBRARY_C_H__

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef int bool;
#define true 1
#define false 0

/*
 * Structure for metadata
 */
typedef struct sharedmem_acket_info
{
	unsigned int id;
	unsigned long addr;
	bool valid;
}sharedmem_packet_info;

/*
 * Structure for buffer base
 * - The same structure should be shared between worlds
 */
typedef struct sharedmem_buffer_base
{
	int read_head;
	int write_head;
	int size;
	sharedmem_packet_info* buffer;	//NULL
}sharedmem_buffer_base;

/*
 * Class for simple circular queue
 */
void circular_queue_initialize(int size);
void circular_queue_init_private(sharedmem_buffer_base* bb);
void circular_queue_free();
int circular_queue_push(sharedmem_packet_info pi);
int circular_queue_push_private(sharedmem_buffer_base* bb, sharedmem_packet_info pi);
sharedmem_packet_info circular_queue_pop(void);
sharedmem_packet_info circular_queue_pop_private(sharedmem_buffer_base* bb);
//sharedmem_buffer_base* circular_queue_get_buffer_base(void);

/*
 * Helper class for the Genode shared memory
 */
static int sharedmem_fd;
static int sharedmem_fdmem;
static long unsigned *sharedmem_map = NULL;
static char *sharedmem_buf = NULL;
const static int sharedmem_channel_buf_size = 128;	//number of fixed element of the channel
const static int sharedmem_addr_buf_size = 4 * 1024 * 1024; //in bytes (4MB)

//channel
static sharedmem_buffer_base* sharedmem_to_genode_ch = NULL;
static sharedmem_buffer_base* sharedmem_to_linux_ch = NULL;

/*
 * Initialize the class
 * - Open the shared memory device
 */
void sharedmem_initialize(void);

/*
 * Free the class
 * - Close the shared memory device
 */
void sharedmem_exit(void);

/*
 * Get the size of the shared memory
 */
int sharedmem_get_size();

/*
 * Get the shared memory address for the packet buffer
 */
unsigned long * sharedmem_get_addr();

/*
 * Run the benchmark for the performance of the shared memory
 */
void sharedmem_run_benchmark();

/*
 * Run the channel test
 */
void sharedmem_run_channel_test();

/*
 * Add the data into the to_genode_channel
 * @param
 * pi: metadata(packet_info) that should be passed over
 * @return
 * 0: if passed well, -1: if the channel is full
 */
int sharedmem_add_packet_info(sharedmem_packet_info pi);

/*
 * Get the data from the to_linux_channel
 * @param
 * @return
 * packet_info will be returned with the flag "valid"
 * valid will be set to false if there is no new packet info
 */
sharedmem_packet_info sharedmem_pull_packet_info(void);

/*
 * Write the command into the shared memory device
 * @param
 * command: command string that sends to the device
 * size: length of the command
 */
int sharedmem_write_into_device(const char* command, int size);

/*
 * Read the shared memory device
 * - We can get the result for the corresponding command
 * @param
 * buffer: buffer that the result will be stored
 * size: size of the buffer
 */
ssize_t sharedmem_read_from_device(char* buffer, int size);

/*
 * Get the mapped virtual address for the shared memory address
 * @param
 * mem_addr: physical memory address of the target memory space
 */
unsigned long * sharedmem_get_mem_map(long unsigned mem_addr);

#endif
