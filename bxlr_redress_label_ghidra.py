import json
from ghidra.program.model.symbol.SourceType import *

def main():
    fm = currentProgram.getFunctionManager()
    json_file_path = askFile('FILE', 'Choose R2 JSON output file')
    with open('json_file_path', 'r') as fd:
        data = fd.read()
    print('Loaded JSON file {}'.format(json_file_path))
    jdata = json.loads(data)
    for item in jdata:
        offset = item.get('offset', None)
        fname = item.get('name', None)
        if offset and fname:
            address = toAddr(offset)
            func = fm.getFunctionAt(address)
            if func is not None:
                old_name = func.getName()
                func.setName(fname, USER_DEFINED)
                print('Renamed function {} to {}'.format(old_name, fname))
            else:
                func = createFunction(address, fname)
                print('Created function {} at {}'.format(fname, address))

if __name__ == '__main__':
    main()
