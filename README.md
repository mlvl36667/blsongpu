# blsongpu

Setup and compile:
```
/usr/local/cuda-12.0/bin/nvcc -o sign sign.cu  -rdc=false -Xptxas -v  -O0  -lineinfo --ptxas-options=-O0
sudo apt-get purge nvidia*
sudo apt-get autoremove
sudo reboot
lsmod | grep nvidia.drm
sudo sh cuda_12.0.0_525.60.13_linux.run
sudo /usr/local/NVIDIA-Nsight-Compute-2022.4/ncu --call-stack -f --set detailed -k saxpy -o res ./sign --metrics gpu__time_duration.sum
```
