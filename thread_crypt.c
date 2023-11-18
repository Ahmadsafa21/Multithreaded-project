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


void hashing_function(){

}
int main(int argc, char * argv[]){
    int ofd = STDOUT_FILENO; //points to stdout
    int ifd = STDIN_FILENO;  //points to stdin
    int opt = 0;
    int algo = DES;
    int saltLength = 2;
    int seed = 1;
    int rounds = 5000;
    int num_threads = 1;
    char *outFileName = NULL;
    char *inFileName = NULL;
    FILE *file;
    static const char saltChars[] = {SALT_CHARS};
    char s[20];
    char saltString[200];
    char *hash = NULL;
    char line[1024];
    char *temp = NULL;
    struct crypt_data data;
    int randomVal = 0;
    data.initialized = 0;

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
    while(fgets(line, 1024, file) != NULL){
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
        //    printf("Line from input: %s\n", line);
          //  printf("Saltstring: %s\n", saltString);
           // printf("Hashed string: %s\n", hash);
            printf("%s:%s\n", line, hash);
        }
    }
    //TODO: Print out the whole thing to ofd


    return EXIT_SUCCESS;
}
