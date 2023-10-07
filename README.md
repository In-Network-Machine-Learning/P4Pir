# P4Pir
source code for P4Pir 
Simplified version for demo

To run this code: 
1. Compile and run the BMv2 environment:
```
$ make clean && make run
```

2. Open a new terminal to run the controller:
```  
$ python3 conroller_cleaned.py
```
3. Back to the BMv2 terminal and generate some traffic:
```
mininet> sh timeout 15 tcpreplay -i s1-eth1 ./Data/EDGEIIOT/DDoSTCPSYN.pcap
```
