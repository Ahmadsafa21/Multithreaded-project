#include <stdio.h>
#include <unistd.h>
#include <crypt.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <grp.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>


# define OPTIONS "i:o:hva:l:R:t:r:"


#include "thread_crypt.h"
#define DES 0
#define MD 1
#define SHA 5
#define SHA6 6

char line[1024];
char saltString[200];
char s[20];
int algo = DES;
FILE * file;
int saltLength = 2;
int rounds = 5000;
int ofd = STDOUT_FILENO; //points to stdout
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *hashing_function(void *);
void *hashing_function(void * vid){
    int randomVal = 0;
    char *hash = NULL;
    static const char saltChars[] = {SALT_CHARS};
    char  buffer[2048]; 
    struct crypt_data data;
    int len = 0;
    data.initialized = 0;

    while(true){
        pthread_mutex_lock(&lock);  // Lock the file access
        // Use fgets to read a line from the file
        if (fgets(line, sizeof(line), file) == NULL) {
            pthread_mutex_unlock(&lock);  // Unlock the file access
            break;  // End of file or error
        }
        pthread_mutex_unlock(&lock);  // Unlock the file access
        for(int i = 0; i < saltLength; ++i){
            randomVal = rand();
            randomVal %= strlen(saltChars);
            s[i] = saltChars[randomVal];
        }
        switch(algo){
            case MD:
                sprintf(saltString, "$%d$%s$", algo, s);
                break;
            case SHA:
                sprintf(saltString, "$%d$rounds=%d$%s$", algo, rounds,s);
                break;
            case SHA6:
                sprintf(saltString, "$%d$rounds=%d$%s$", algo, rounds,s);
                break;
            default:
                sprintf(saltString, "%s", s);
                break;
        }
        saltString[saltLength] = '\0';

        line[strcspn(line, "\n")] = '\0'; //remove new line char 
        hash = crypt_rn(line, saltString, &data, sizeof(data) );
        if(hash){
            len = sprintf(buffer,"%s:%s\n", line, hash);
            write(ofd, buffer, len);
            //printf("%s:%s\n", line, hash);
        }
    }
//    free(hash);
    return NULL;
}
int main(int argc, char * argv[]){

    int ifd = STDIN_FILENO;  //points to stdin
    int opt = 0;
    int seed = 1;
    int num_threads = 1;
    char *outFileName = NULL;
    char *inFileName = NULL;
    pthread_t *threads = NULL;
    long tid = 0;

    while( (opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch(opt){
            case 'i':
                ifd = open(optarg, O_RDONLY);
                if (ifd < 0){
                    fprintf(stderr, "cannot open %s for input", optarg);
                    exit(EXIT_FAILURE);
                }
                inFileName = optarg;
                break;
            case 'o':
                outFileName = optarg;
                break;
            case 'h':
                printf("\tOptions:i:o:hva:l:R:t:r:\n");
                printf("\t-i file     input file name (required)\n");
                printf("\t-o file     output file name (default stdout)\n");
                printf("\t-a #        algorithm to use for hashing [0,1,5,6] (default 0 = DES)\n");
                printf("\t-l #        length of salt (default 2 for DES, 8 for MD-5, 16 for SHA)\n");
                printf("\t-r #        rounds to use for SHA-256, or SHA-512 (default 5000)\n");
                printf("\t-R #        seed for rand() (default none)\n");
                printf("\t-t #        number of threads to create (default 1)\n");
                printf("\t-v      enable verbose mode\n");
                printf("\t-h      helpful text\n");
                break;
            case 'v':
                fprintf(stderr, "verbose enabled\n");
                break;
            case 'a':
                algo = atoi(optarg);
                break;
            case 'l':
                saltLength = atoi(optarg);
                break;
            case 'R':
                seed = atoi(optarg);
                srand(seed);
                break;
            case 't':
                num_threads= atoi(optarg);
                break;
            case 'r':
                rounds= atoi(optarg);
                break;
            default:
                fprintf(stderr, "Invalid option: %c\n", opt);
                break;
        } 
    }
    if(algo != DES && saltLength == 2 ){
        if( (algo == SHA) || algo == SHA6){
            saltLength = 16;
        }
        else if (algo == MD){
            saltLength = 8;
        }
        else{
            exit(EXIT_FAILURE);
        }
    }

    //Open output file if provided with filename
    if(outFileName != NULL){
        ofd = open(outFileName
                 , O_WRONLY | O_TRUNC | O_CREAT);
        if(ofd < 0){
            fprintf(stderr, "cannot open %s for output", outFileName);
            exit(EXIT_FAILURE);
        }
    }

    //TODO: Take input file and read every line seperately
    //TODO: Add the salt using macro from the .h file and code provided in slide
    //TODO: Take that input and hash it using the algorithm passed in, using the crypt function
    file = fopen(inFileName, "r");
    if(file == NULL){
        fprintf(stderr, "cannot open %s for input\n", inFileName);
        exit(EXIT_FAILURE);
    }
    threads = malloc(num_threads * sizeof(pthread_t));
    //hashing_function(temp);
    //TODO: Multithreading

    for(tid = 0; tid < num_threads; tid++){
         pthread_create(&threads[tid], NULL, hashing_function, (void *)tid);
     }
     for(tid = 0; tid < num_threads; tid++){
         pthread_join(threads[tid], NULL);
     }

    free(threads);
    //free(inFileName);
    //free(outFileName);
    fclose(file);
    //pthread_mutex_destroy(&lock);

    return EXIT_SUCCESS;
}
