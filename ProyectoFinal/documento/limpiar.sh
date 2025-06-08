#!/bin/bash

files=$(ls tfg_alberto.*)

for i in $files
do
	if [[ $i -eq "tfg_alberto.tex" || $i -eq "tfg_alberto.pdf" ]]
	then
		continue
	fi

	rm $i
done
