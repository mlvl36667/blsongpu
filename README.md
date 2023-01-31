# blsongpu

nvcc -o sign sign.cu  -rdc=false -Xptxas -v  -O0  -lineinfo --ptxas-options=-O0
