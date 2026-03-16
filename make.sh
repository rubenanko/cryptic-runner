OUTPUT_FILE=build/out.exe
SOURCE_FILE="build/main.c"
SCRIPT_PATH=src/format.py
INPUT_FILE=$1

if [ -d build ]; then
    rm -Rf build
fi

mkdir build

# python $SCRIPT_PATH $INPUT_FILE

# x86_64-w64-mingw32-gcc -Iinclude $SOURCE_FILE -o $OUTPUT_FILE -fno-stack-protector \
#   -Wl,--disable-nxcompat \
#   -Wl,--disable-dynamicbase \
#   -nostdlib -nodefaultlibs \
#   -lkernel32 -mwindows

x86_64-w64-mingw32-gcc -IInclude src/peb-lookup.c -c -o build/peb-lookup.o
x86_64-w64-mingw32-gcc -IInclude -o build/main.o -c src/main.tpl.c

x86_64-w64-mingw32-gcc -Iinclude build/main.o build/peb-lookup.o -o build/caca.exe -fno-stack-protector \
  -Wl,--disable-nxcompat \
  -Wl,--disable-dynamicbase \
  -lkernel32