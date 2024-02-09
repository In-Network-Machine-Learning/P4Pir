# P4Pir  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

P4Pir is an in-network traffic analysis framework in IoT gateway, leveraging in-network ML inference for accurate detection and fast mitigation of emerging attacks. 

This repo is a simplified version of the demo.

## Prepare your environment

This demo is based on [BMv2](https://github.com/p4lang/behavioral-model) in Ubuntu 20.04.

Please make sure the following packages are installed by running: 
```
$ pip3 install -r ./requirements.txt
```
💡 To run the demo on Raspberry Pi, please follow the [P4Pi](https://github.com/p4lang/p4pi) guideline to configure the environment. 

## Run a simple demo
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

* The source of the pcap capture and dataset: [Edge-IIoTset](http://ieee-dataport.org/8939)


## Citation

P4Pir builds upon [Planter](https://github.com/In-Network-Machine-Learning/Planter) and is further inspired by [IIsy](https://github.com/cucl-srg/IIsy), [SwitchTree](https://github.com/ksingh25/SwitchTree), [pForest](https://arxiv.org/abs/1909.05680), [ACC-Turbo](https://github.com/nsg-ethz/ACC-Turbo).

If you find this code helpful, please cite: 

````
@inproceedings{zang2022p4pir,
author = {Zang, Mingyuan and Zheng, Changgang and Stoyanov, Radostin and Dittmann, Lars and Zilberman, Noa},
title = {P4Pir: In-Network Analysis for Smart IoT Gateways},
year = {2022},
isbn = {9781450394345},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3546037.3546060},
doi = {10.1145/3546037.3546060},
booktitle = {Proceedings of the SIGCOMM '22 Poster and Demo Sessions},
pages = {46–48},
numpages = {3},
location = {Amsterdam, Netherlands},
series = {SIGCOMM '22}
}

@ARTICLE{zang2023p4pir,
  author={Zang, Mingyuan and Zheng, Changgang and Dittmann, Lars and Zilberman, Noa},
  journal={IEEE Internet of Things Journal}, 
  title={Towards Continuous Threat Defense: In-Network Traffic Analysis for IoT Gateways}, 
  year={2023},
  volume={},
  number={},
  pages={1-1},
  doi={10.1109/JIOT.2023.3323771}}

````

💡 If you are interested in further details and more use cases of In-Network Machine Learning inference and how an ML model is mapped to a programmable data plane, please refer to [Planter](https://arxiv.org/abs/2205.08824), [IIsy](https://arxiv.org/abs/2205.08243), [Linnet](https://dl.acm.org/doi/abs/10.1145/3546037.3546057), [LOBIN](https://ieeexplore.ieee.org/document/10147958):

````
@article{zheng2022automating,
  title={Automating In-Network Machine Learning},
  author={Zheng, Changgang and Zang, Mingyuan and Hong, Xinpeng and Bensoussane, Riyad and Vargaftik, Shay and Ben-Itzhak, Yaniv and Zilberman, Noa},
  journal={arXiv preprint arXiv:2205.08824},
  year={2022}
}

@incollection{zheng2021planter,
  title={Planter: seeding trees within switches},
  author={Zheng, Changgang and Zilberman, Noa},
  booktitle={Proceedings of the SIGCOMM'21 Poster and Demo Sessions},
  pages={12--14},
  year={2021}
}

@article{zheng2022iisy,
  title={IIsy: Practical In-Network Classification},
  author={Zheng, Changgang and Xiong, Zhaoqi and Bui, Thanh T and Kaupmees, Siim and Bensoussane, Riyad and Bernabeu, Antoine and Vargaftik, Shay and Ben-Itzhak, Yaniv and Zilberman, Noa},
  journal={arXiv preprint arXiv:2205.08243},
  year={2022}
}

@incollection{hong2022linnet,
  title={Linnet: Limit Order Books Within Switches},
  author={Hong, Xinpeng and Zheng, Changgang and Zohren, Stefan and Zilberman, Noa},
  booktitle={Proceedings of the SIGCOMM'22 Poster and Demo Sessions},
  year={2022}
}

@INPROCEEDINGS{hong2023LOBIN,
  author={Hong, Xinpeng and Zheng, Changgang and Zohren, Stefan and Zilberman, Noa},
  booktitle={2023 IEEE 24th International Conference on High Performance Switching and Routing (HPSR)}, 
  title={LOBIN: In-Network Machine Learning for Limit Order Books}, 
  year={2023},
  volume={},
  number={},
  pages={159-166},
  doi={10.1109/HPSR57248.2023.10147958}}



````


## Acknowledgment
This work was partly supported by the Otto Mønsted Foundation, VMware, and EU Horizon SMARTEDGE (101092908).

