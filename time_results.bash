#!/bin/bash

ROUNDS=5000
ALGOL=5
ALGOL_EXT=sha512
IP=words-big.txt
SEED=333

> time_results_r${ROUNDS}.txt
#for T in 1 2 3 5 8 10 13 16 20 25
for T in 8 10 13 16  
do
    echo ${T} >> time_results_r${ROUNDS}.txt
    time ( ./thread_crypt -i ${IP} -o words-big-${T}.${ALGOL_EXT} -a ${ALGOL} -r ${ROUNDS} -R ${SEED} -t ${T} ) >> time_results_r${ROUNDS}.txt 2>&1
done
