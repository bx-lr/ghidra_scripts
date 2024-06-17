from xml.etree import cElementTree as ElementTree
from ghidra.program.model.data import PointerDataType

def get_pointer_type():
    ptype = PointerDataType(None, currentProgram.getDefaultPointerSize())
    return ptype

def set_data_type(addr, ptype):
    createData(addr, ptype)
    return

def main(xml_file):
    print('Loading source file: {}'.format(xml_file))
    tree = ElementTree.parse(str(xml_file))
    root = tree.getroot()
    ptype = get_pointer_type()
    start = int(root.attrib['iat_rva'], 16)
    for iat_entry in root.iter('import_valid'):
        rva_str = iat_entry.attrib['iat_rva']
        iat_entry_name = iat_entry.attrib['name']
        print('Labeling location: {} as {}'.format(rva_str, iat_entry_name))
        loc = ((int(rva_str, 16) & 0x0000FFFF) + start)
        addr = toAddr(loc)
        try:
            set_data_type(addr, ptype)
        except:
            pass
        createLabel(addr, iat_entry_name, 1)


if __name__ == '__main__':
    xml_file = None

    try:
        xml_file = askFile('FILE', 'Choose Scillia IAT XML Dump File from x64dbg')
    except CancelledException as e:
        print('Cancelled: {}'.format(str(e)))
    if xml_file:
        main(xml_file)

