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

//When pass in seed, output not good

#include "thread_crypt.h"
#define DES 0
#define MD 1
#define SHA 5
#define SHA6 6
typedef struct {
    char line[1024];
    char saltString[200];
    char s[20];
    int algo;
    FILE * file;
    int saltLength;
    int rounds;
    int ofd; //points to stdout
    // Other variables as needed
} ThreadData;


void *hashing_function(void *); //responsible for hashing and create salt string
void *hashing_function(void * vid){
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    ThreadData *data = (ThreadData*) vid;

    int randomVal = 0;
    char *hash = NULL;
    static const char saltChars[] = {SALT_CHARS};
    char  buffer[2048]; 
    struct crypt_data cdata;
    int len = 0;
    cdata.initialized = 0;

    while(true){
        pthread_mutex_lock(&lock);  // Lock the file access
                                    
        // Use fgets to read a line from the file
        if (fgets(data->line, sizeof(data->line), data->file) == NULL) {
            pthread_mutex_unlock(&lock);  // Unlock the file access
            break;  // End of file or error
        }
        pthread_mutex_unlock(&lock);  // Unlock the file access
        for(int i = 0; i < data->saltLength; ++i){ // create salt string
            randomVal = rand();
            randomVal %= strlen(saltChars);
            data->s[i] = saltChars[randomVal];
        }
        switch(data->algo){ //add all necessary prefixes to saltString, so we can pass it to crypt_rn
            case MD:
                sprintf(data->saltString, "$%d$%s$", data->algo, data->s);
                break;
            case SHA:
                sprintf(data->saltString, "$%d$rounds=%d$%s$", data->algo, data->rounds,data->s);
                break;
            case SHA6:
                sprintf(data->saltString, "$%d$rounds=%d$%s$", data->algo, data->rounds,data->s);
                break;
            default:
                sprintf(data->saltString, "%s", data->s);
                break;
        }

        data->line[strcspn(data->line, "\n")] = '\0'; //remove new line char because of fgets
        hash = crypt_rn(data->line, data->saltString, &cdata, sizeof(cdata) );
        if(hash){
            len = sprintf(buffer,"%s:%s\n", data->line, hash);
            write(data->ofd, buffer, len);
        }
    }
    pthread_exit(EXIT_SUCCESS);
}
int main(int argc, char * argv[]){

    int ifd = STDIN_FILENO;  //points to stdin
    int opt = 0;
    int seed = 1;
    int num_threads = 1;
    char *outFileName = NULL;
    char *inFileName = NULL;
    pthread_t *threads = NULL;
    bool uniqueLen = false;
    char line[1024];
    char saltString[200];
    char s[20];
    int algo = DES;
    FILE * file;
    int saltLength = 2;
    int rounds = 5000;
    int ofd = STDOUT_FILENO; //points to stdout
    ThreadData *data; //data that will be passed around safely between threads

    while( (opt = getopt(argc, argv, OPTIONS)) != -1) { //manage command line arguments
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
                printf("\t-i file\t\tinput file name (required)\n");
                printf("\t-o file\t\toutput file name (default stdout)\n");
                printf("\t-a #\t\talgorithm to use for hashing [0,1,5,6] (default 0 = DES)\n");
                printf("\t-l #\t\tlength of salt (default 2 for DES, 8 for MD-5, 16 for SHA)\n");
                printf("\t-r #\t\trounds to use for SHA-256, or SHA-512 (default 5000)\n");
                printf("\t-R #\t\tseed for rand() (default none)\n");
                printf("\t-t #\t\tnumber of threads to create (default 1)\n");
                printf("\t-v\t\tenable verbose mode\n");
                printf("\t-h\t\thelpful text\n");
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                fprintf(stderr, "verbose enabled\n");
                break;
            case 'a':
                algo = atoi(optarg);
                break;
            case 'l':
                saltLength = atoi(optarg);
                uniqueLen = true;
                break;
            case 'R':
                seed = atoi(optarg);
                srand(seed);
                break;
            case 't':
                num_threads= atoi(optarg);
                if(num_threads > 20){
                    num_threads = 20;
                }
                break;
            case 'r':
                rounds= atoi(optarg);
                break;
            default:
                fprintf(stderr, "Invalid option: %c\n", opt);
                break;
        } 
    }
    switch(algo){//take care of length of salt
        case DES:
            saltLength = 2;
            break;
        case MD:
            if(saltLength > 8 || !uniqueLen)
                saltLength = 8;
            break;
        case SHA:
            if(saltLength > 16 || !uniqueLen)
                saltLength = 16;
            break;
        case SHA6:
            if(saltLength > 16 || !uniqueLen)
                saltLength = 16;
            break;
        default:
            fprintf(stderr, "%d is not a valid algo number\n", algo);
            exit(EXIT_FAILURE);
            break;
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

    //check if input file is valid
    file = fopen(inFileName, "r");
    if(file == NULL){
        fprintf(stderr, "cannot open %s for input\n", inFileName);
        exit(EXIT_FAILURE);
    }

    // Multithreading
    threads = malloc(num_threads * sizeof(pthread_t));
    data = malloc(num_threads * sizeof(ThreadData));
    memset(data, 0, sizeof(ThreadData) );
    for(int i = 0; i < num_threads; i++){ 
        strcpy(data[i].line, line);
        strcpy(data[i].saltString, saltString);
        strcpy(data[i].s, s);
        data[i].algo = algo;
        data[i].file = file;
        data[i].saltLength = saltLength;
        data[i].rounds = rounds;
        data[i].ofd = ofd;
         pthread_create(&threads[i], NULL, hashing_function, &data[i]);

     }
     for(int i = 0; i < num_threads; i++){
         pthread_join(threads[i], NULL);
     }

    free(threads);
    fclose(file);

    return EXIT_SUCCESS;
}
