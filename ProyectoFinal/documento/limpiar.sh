#!/bin/bash

files=$(ls tfg_alberto.*)

for i in $files
do
	if [[ "$i" = "tfg_alberto.tex" || "$i" = "tfg_alberto.pdf" ]]
    then
        continue # Skip to the next file
    fi

	rm $i

done
