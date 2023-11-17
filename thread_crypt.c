 #include <stdio.h>
 #include <stdlib.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include <string.h>
 #include <grp.h>
 #include <time.h>
 #include <pwd.h>
 #include <fcntl.h>
 #include <unistd.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/time.h>


# define OPTIONS "i:o:hva:l:R:t:r:"


#include "thread_crypt.h"
#define DES 0
#define MD 1
#define SHA 5


int main(int argc, char * argv[]){
    int ofd = STDOUT_FILENO; //points to stdout
    int ifd = STDIN_FILENO;  //points to stdin
    int opt = 0;
    int algo = DES;
    int saltLength = 2;
    int seed = 1;
    int rounds = 5000;
    int threads = 1;
    char *outFileName = NULL;
    static const char saltChars[] = {SALT_CHARS};
    char saltString[20];

    while( (opt = getopt(argc, argv, OPTIONS)) != -1) {
        switch(opt){
            case 'i':
                ifd = open(optarg, O_RDONLY);
                if (ifd < 0){
                    fprintf(stderr, "cannot open %s for input", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'o':
                outFileName = optarg;
                break;
            case 'h':
                printf("\tOptions:i:o:hva:l:R:t:r:\n");
                printf("\t-i file     input file name (required)");
                printf("\t-o file     output file name (default stdout)");
                printf("\t-a #        algorithm to use for hashing [0,1,5,6] (default 0 = DES)");
                printf("\t-l #        length of salt (default 2 for DES, 8 for MD-5, 16 for SHA)");
                printf("\t-r #        rounds to use for SHA-256, or SHA-512 (default 5000)");
                printf("\t-R #        seed for rand() (default none)");
                printf("\t-t #        number of threads to create (default 1)");
                printf("\t-v      enable verbose mode");
                printf("\t-h      helpful text");
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
                break;
            case 't':
                threads= atoi(optarg);
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
        if(algo == SHA){
            saltLength = 16;
        }
        else if (algo == MD){
            saltLength = 8;
        }
        else{
            exit(EXIT_FAILURE);
        }
    }



    if(outFileName != NULL){
        ofd = open(outFileName
                 , O_WRONLY | O_TRUNC | O_CREAT);
        if(ofd < 0){
            fprintf(stderr, "cannot open %s for output", outFileName);
            exit(EXIT_FAILURE);
        }
    }

    //TODO: Take input file and read every line seperately
    //TODO: Take that input and hash it using the algorithm passed in, using the crypt function
    //TODO: Add the salt using macro from the .h file and code provided in slide

    srand(seed);
    for(int i = 0; i < saltLength; ++i){
        int randomVal = rand();
        randomVal %= saltLength;
        saltString[i] = saltChars[randomVal];
    }
    //TODO: Print out the whole thing


    return EXIT_SUCCESS;
}
