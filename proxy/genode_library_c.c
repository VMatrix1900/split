#include <stdio.h>
#include <stdlib.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <asm/errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "genode_library_c.h"

#define CEHCK_FD                              \
    if (sharedmem_fd < 0) {                   \
        printf("fd must be larger than 0\n"); \
        return -1;                            \
    }

/*
 * Circular queue
 */
void circular_queue_initialize(int size)
{
    // make new buffers with size
    sharedmem_to_genode_ch =
        (sharedmem_buffer_base*)malloc(sizeof(sharedmem_buffer_base));
    sharedmem_to_linux_ch =
        (sharedmem_buffer_base*)malloc(sizeof(sharedmem_buffer_base));

    sharedmem_to_genode_ch->size = size;
    sharedmem_to_genode_ch->buffer = NULL;
    sharedmem_to_linux_ch->size = size;
    sharedmem_to_linux_ch->buffer = NULL;

    // TODO: update to use the mapping inside the shared memory

    // call the base constructor
    circular_queue_init_private(sharedmem_to_genode_ch);
    circular_queue_init_private(sharedmem_to_linux_ch);
}

void circular_queue_init_private(sharedmem_buffer_base* bb)
{
    bb->read_head = 0;
    bb->write_head = 0;

    // allocate buffer space
    if (bb->buffer != NULL) free(bb->buffer);
    bb->buffer = (sharedmem_packet_info*)malloc(sizeof(sharedmem_packet_info) *
                                                bb->size);
}

void circular_queue_free()
{
    // free the buffer space
    if (sharedmem_to_genode_ch != NULL) {
        free(sharedmem_to_genode_ch);
        sharedmem_to_genode_ch = NULL;
    }
    if (sharedmem_to_linux_ch != NULL) {
        free(sharedmem_to_linux_ch);
        sharedmem_to_linux_ch = NULL;
    }
}

// push
int circular_queue_push(sharedmem_packet_info pi)
{
    return circular_queue_push_private(sharedmem_to_genode_ch, pi);
}

int circular_queue_push_private(sharedmem_buffer_base* bb,
                                sharedmem_packet_info pi)
{
    // check the header first
    if ((bb->read_head - 1 == bb->write_head) ||
        (bb->read_head == 0 &&
         bb->write_head == bb->size - 1))  // if the queue if full
    {
        return -1;
    }

    if (bb->write_head >= bb->size)  // fetal error
        return -1;

    // copy the data
    bb->buffer[bb->write_head] = pi;

    // update the header
    bb->write_head++;
    if (bb->write_head >= bb->size) bb->write_head = 0;

    return 0;
}

// pop
sharedmem_packet_info circular_queue_pop(void)
{
    return circular_queue_pop_private(sharedmem_to_linux_ch);
}

sharedmem_packet_info circular_queue_pop_private(sharedmem_buffer_base* bb)
{
    sharedmem_packet_info result;
    result.valid = false;  // default null

    // check the header first
    if (bb->read_head == bb->write_head)  // if there is no data
    {
        return result;
    }

    // copy the value
    result = bb->buffer[bb->read_head];

    // update the header
    bb->read_head++;
    if (bb->read_head >= bb->size) bb->read_head = 0;

    // return the value
    return result;
}

// return buffer base pointer
/*
buffer_base* genode_circular_buffer::get_buffer_base(void)
{
        return buffer;
}
*/

/*
 * Genode Shared Memory Helper
 */
// initializer
void sharedmem_initialize(void)
{
    sharedmem_fd = open("/dev/shared_memory_allocator", O_RDWR | O_NONBLOCK);
    if (sharedmem_fd < 0)
        ;  // handle error

    // Initialize buffer
    sharedmem_buf = (char*)malloc(sizeof(char) * sharedmem_addr_buf_size);

    // Initialize channel structure
    circular_queue_initialize(sharedmem_channel_buf_size);
}

// destructor
void sharedmem_exit(void)
{
    // TODO: free the region
    /* unmap the area & error checking */
    if (munmap(sharedmem_map, sharedmem_addr_buf_size) == -1) {
        perror("Error un-mmapping the file");
    }

    /* close the character device */
    close(sharedmem_fd);

    // Free the buffer
    if (sharedmem_buf != NULL) {
        free(sharedmem_buf);
        sharedmem_buf = NULL;
    }
    // Free the circular queues
    circular_queue_free();
}

int sharedmem_get_size() { return sharedmem_addr_buf_size; }
unsigned long* sharedmem_get_addr()
{
    char command[32] = {0};
    long unsigned recv_buf_addr;
    long unsigned recv_buf_phy_addr;

    // Write down get address command
    strcpy(command, "GET_ADDR\0");
    sharedmem_write_into_device(command, (int)strlen(command));

    // Read address from the device
    ssize_t read_data_cnt =
        sharedmem_read_from_device(sharedmem_buf, sharedmem_addr_buf_size);
    sscanf(sharedmem_buf, "%lx\n%lx\n", &recv_buf_addr, &recv_buf_phy_addr);
    printf("Buffer:[%lx] Phy:[%lx][size: %d]\n", recv_buf_addr,
           recv_buf_phy_addr, read_data_cnt);

    // return mapping pointer
    return sharedmem_get_mem_map(recv_buf_phy_addr);
}

void sharedmem_run_benchmark()
{
    char command[32] = {0};
    strcpy(command, "RUN_BENCHMARK\0");
    // printf("Run Benchmark...[fd=%d] %s[%d]\n", fd, command,
    // (int)strlen(command));
    sharedmem_write_into_device(command, (int)strlen(command));
    sharedmem_read_from_device(sharedmem_buf, sharedmem_addr_buf_size);
}

void sharedmem_run_channel_test()
{
    int i = 0;
    sharedmem_packet_info test_pi;
    test_pi.valid = true;
    test_pi.id = 1;
    test_pi.addr = 0x30001000;

    for (i = 0; i < 100; i++) {
        sharedmem_add_packet_info(test_pi);
        sharedmem_packet_info temp =
            circular_queue_pop_private(sharedmem_to_genode_ch);
        circular_queue_push_private(sharedmem_to_linux_ch, temp);
        sharedmem_packet_info recv = sharedmem_pull_packet_info();
        printf("packet[%d][%lx]\n", recv.id, recv.addr);
    }
}

int sharedmem_add_packet_info(sharedmem_packet_info pi)
{
    int ret = -1;
    // add the packet info
    if (sharedmem_to_linux_ch != NULL) ret = circular_queue_push(pi);
    return ret;
}

sharedmem_packet_info sharedmem_pull_packet_info(void)
{
    sharedmem_packet_info ret;
    ret.valid = -1;
    // pull the packet_info
    if (sharedmem_to_linux_ch != NULL) ret = circular_queue_pop();
    return ret;
}

int sharedmem_write_into_device(const char* command, int size)
{
    CEHCK_FD

    ssize_t written = write(sharedmem_fd, command, size);
    if (written >= 0)
        ;  // printf("written data: %d\n", written);  // handle successful write
           // (which might be a partial write!)
    else
        printf(
            "write_into_device:: data isn't written\n");  // handle real error

    return written;
}

ssize_t sharedmem_read_from_device(char* buffer, int size)
{
    CEHCK_FD

    ssize_t read_data_cnt = read(sharedmem_fd, buffer, size);
    return read_data_cnt;
}

unsigned long* sharedmem_get_mem_map(long unsigned mem_addr)
{
    const char memDevice[] = "/dev/mem";

    /* open /dev/mem and error checking */
    sharedmem_fdmem = open(memDevice, O_RDWR | O_SYNC);
    //_fdmem = open( memDevice, O_RDWR );

    if (sharedmem_fdmem < 0) {
        printf("Failed to open the /dev/mem !\n");
        return 0;
    } else {
        printf("open /dev/mem successfully\n");
    }

    /* mmap() the opened /dev/mem */
    // map= (long unsigned *)(mmap(0,_addr_buf_size,
    // PROT_READ|PROT_WRITE,MAP_SHARED,_fdmem,mem_addr));

    sharedmem_map = (long unsigned*)(mmap(0, sharedmem_addr_buf_size,
                                          PROT_READ | PROT_WRITE, MAP_SHARED,
                                          sharedmem_fdmem, mem_addr));

    printf("Mapped: virt[0x%0lx] -> phy[0x%0lx]\n",
           (long unsigned)(sharedmem_map), (long unsigned)mem_addr);
    // printf("content: 0x%0lx[0x%0lx]\n",(long unsigned)(*(map)), (long
    // unsigned)map);
    /*
    //TEST
    while(1)
    {
            // use 'map' pointer to access the mapped area!
            printf("content: 0x%0lx[0x%0lx]\n",(long unsigned)(*(map)), (long
    unsigned)map);
            //printf("content: 0x%0lx[0x%0lx]\n",*((long unsigned*)mem_addr),
    mem_addr);
            sleep(5);
    }
    */
    return sharedmem_map;
}
