
import os
import re


files = os.listdir('/Users/chris/freeradius')

for f in files:
    if f:
        n = "dictionary/%s" % f.split('.')[1]
        print(f, n)
        f = "/Users/chris/freeradius/%s" % f
        with open(f, 'r') as read:
            new = []
            lines = read.readlines()
            for line in lines:
                line = line.strip()
                if line == '':
                    continue
                line = line.replace('\t', ' ')
                line = re.sub(' +', ' ', line)
                if not line.startswith('#'):
                    new.append(line)
            print(f)
            new = "\n".join(new)
        with open(n, 'w') as write:
            write.write(new)
