INPUT_FILE=$1

if [ -d build ]; then
    rm -Rf build
fi

mkdir build

echo calling the python script to build the c file
python src/format.py build_tests/shellcode.bin

echo compiling the produced c file
x86_64-w64-mingw32-gcc -Iinclude build/main.c -o build/out.exe -Wl,--omagic \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase \
  -lkernel32 -mconsole