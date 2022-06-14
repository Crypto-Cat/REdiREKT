import sys

if len(sys.argv) != 4:
    print('python remove_rows.py target_word input.csv output.csv')
    exit(0)

# We open the source file and get its lines
with open(str(sys.argv[2]), 'r') as inp:
    lines = inp.readlines()

# We open the target file in write-mode
with open(str(sys.argv[3]), 'w') as out:
    for line in lines:
        # Remove any lines that contain target_word
        if not str(sys.argv[1]) in line:
            out.write(line)