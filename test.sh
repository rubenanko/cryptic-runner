
if [ -d build_tests ]; then
    rm -Rf build_tests
fi

if ! [ -d build ]; then
    mkdir build
fi

mkdir build_tests

# compiling the test program
echo compiling peb-lookup
x86_64-w64-mingw32-gcc -IInclude -o build_tests/peb-lookup.o -c src/peb-lookup.c -Os -ffreestanding -nostdlib 
echo compiling test.c
x86_64-w64-mingw32-gcc -IInclude -o build_tests/test.o -c test/test.c -Os -ffreestanding -nostdlib
echo combining object files
x86_64-w64-mingw32-ld build_tests/test.o build_tests/peb-lookup.o -o build_tests/combined.o -e WinMain -nostdlib
echo extracting the shellcode .text
x86_64-w64-mingw32-objcopy -O binary --only-section=.text build_tests/combined.o build_tests/text.bin
x86_64-w64-mingw32-objcopy -O binary --only-section=.data build_tests/combined.o build_tests/data.bin
x86_64-w64-mingw32-objcopy -O binary --only-section=.rdata build_tests/combined.o build_tests/rdata.bin
cat build_tests/text.bin build_tests/data.bin build_tests/rdata.bin > build_tests/shellcode.bin

# linking the test program
x86_64-w64-mingw32-gcc -Iinclude  build_tests/combined.o -o  build_tests/peb_lookup_test.exe -fno-stack-protector \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase \
  -nostdlib -nodefaultlibs \
  -lkernel32 -mconsole

python src/format.py build_tests/shellcode.bin

x86_64-w64-mingw32-gcc -Iinclude build/main.c -o build/cryptic_runner_test.exe -fno-stack-protector \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase \
  -nostdlib -nodefaultlibs \
  -lkernel32 -mconsole