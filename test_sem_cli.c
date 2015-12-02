#include <stdio.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define SHMSZ 27
#define BUFSZ 4096
char DOWN_SEM[]= "up";
char UP_SEM[]= "down";

void strupr(char s[]) {
   int c = 0;

   while (s[c] != '\0') {
      if (s[c] >= 'a' && s[c] <= 'z') {
         s[c] = s[c] - 32;
      }
      c++;
   }
}

int main ()
{

    int shmid;
    key_t key;
    char *shm;
    sem_t *down, *up;

    //name the shared memory segment
    key = 1000;

    //create & initialize semaphore
    down = sem_open(DOWN_SEM,O_CREAT,0644,0);
    if(down == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(DOWN_SEM);
        exit(-1);
    }

    up = sem_open(UP_SEM,O_CREAT,0644,0);
    if(up == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        exit(-1);
    }

    //create the shared memory segment with this key
    shmid = shmget(key,SHMSZ,IPC_CREAT|0666);
    if(shmid<0)
    {
        perror("failure in shmget");
        exit(-1);
    }

    //attach this segment to virtual memory
    shm = shmat(shmid,NULL,0);

    sem_wait(down);
    printf("received: %s\n", shm);

    strupr(shm);
    sem_post(up);
    return 0;
}
