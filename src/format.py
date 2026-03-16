from pathlib import Path
from typing import List
from random import randint
import sys

OUTPUT_PATH = "build/main.c"
TEMPLATE_PATH = "src/main.tpl.c"

KEY_LENGTH = 16

def main(argv : List[str])->None:
    filename = Path(argv[1])

    if not filename.is_file():
        print(f"ERROR: the file {filename} does not exist")
        sys.exit(1)

    with filename.open("rb") as f:
        buffer = f.read()

    key = [randint(0,255) for _ in range(KEY_LENGTH)]
    print(f"generating a random key")

    print("formatting the c-array")

    # formatting the c array
    c_array = "{\n        "
    counter = 0
    for byte in buffer:
        c_array += f"{hex(byte ^ key[counter])},"
        counter += 1
        if counter == KEY_LENGTH:
            c_array += "\n        "
            counter = 0
    
    c_array = c_array[:-1] + "\n    }"

    # formating the key array
    key_array = "{"
    for byte in key:
        key_array += f"{hex(byte)},"

    key_array = key_array[:-1] + "}"

    # replacing the placeholders with the actual values in the template
    print("building the runner source file")
    with open(TEMPLATE_PATH,"r") as f:
        template = f.read()
    

    content = template.replace("SET_BYTECODE_SIZE",str(len(buffer)))
    content = content.replace("SET_BYTECODE_ARRAY",c_array)
    content = content.replace("SET_KEY_ARRAY",key_array)
    content = content.replace("SET_KEY_SIZE",str(KEY_LENGTH))

    with open(OUTPUT_PATH,"w") as f:
        f.write(content)

    print("done")
    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
