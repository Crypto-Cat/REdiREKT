#!/bin/bash

for file in *.zip
do
	unzip -P infected $file
	rm -rf $file
done

ls *.pcap > new
cat new
rm new