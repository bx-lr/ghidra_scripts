import struct
import subprocess
import traceback
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

sm = currentProgram.getSymbolTable()
symb = sm.getExternalSymbol('CoCreateInstance')
refs = symb.getReferences()


def get_uuid_loc(line):
    tmp = line.split('&')[1]
    tmp = tmp.split(',')[0]
    return toAddr(tmp)


def get_iid_loc(line):
    tmp = line.split(',')[3]
    tmp = tmp.split('&')[1]
    return toAddr(tmp)


def get_guid_loc(line, char1, p1, char2, p2):
    #print('line:', line)
    #print(char1, p1)
    #print(char2, p2)
    tmp = line.split(char1)[p1]
    tmp = tmp.split(char2)[p2]
    return toAddr(tmp)


def get_guid_str(byte_arr):
    data1 = struct.unpack('<I', byte_arr[0:4])[0]
    data2 = struct.unpack('<H', byte_arr[4:6])[0]
    data3 = struct.unpack('<H', byte_arr[6:8])[0]
    data4 = struct.unpack('>H', byte_arr[8:10])[0]
    data5 = struct.unpack('6c', byte_arr[10:])
    uuid_str = '%08x-%04x-%04x-%04x-%s-%s' % (data1,
                                              data2,
                                              data3,
                                              data4,
                                              ''.join('%02x' % ord(x) for x in data5[0:2]),
                                              ''.join('%02x' % ord(x) for x in data5[2:]))
    uuid_str = '%08x-' % data1
    uuid_str += '%04x-' % data2
    uuid_str += '%04x-' % data3
    uuid_str += '%04x-' % data4
    uuid_str += ''.join('%02x' % ord(x) for x in data5[0:2])
    uuid_str += '-'
    uuid_str += ''.join('%02x' % ord(x) for x in data5[2:])
    return uuid_str


for ref in refs:
    external_address = ref.toAddress
    fun = getFunctionContaining(ref.getFromAddress())
    if not fun:
        continue
    res = ifc.decompileFunction(fun, 60, monitor)
    high_func = res.getHighFunction()
    if high_func:
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()
        opiter = high_func.getPcodeOps()
        while opiter.hasNext():
            op = opiter.next()
            mnemonic = str(op.getMnemonic())
            if mnemonic == 'CALL':
                inputs = op.getInputs()
                addr = inputs[0].getAddress()
                args = inputs[1:]
                inst_refs = getReferencesFrom(addr)
                for inst_ref in inst_refs:
                    if inst_ref.toAddress == external_address:
                        c_code = res.decompiledFunction.getC().split(';')
                        for line in c_code:
                            if line.find('CoCreateInstance(') > -1:
                                try:
                                    uuid_loc = get_guid_loc(line, '&', 1, ',', 0)
                                    uuid_bytes = getBytes(uuid_loc, 16)
                                    uuid_str = get_guid_str(uuid_bytes)

                                    iid_loc = get_guid_loc(line, ',', 3, '&', 1)
                                    iid_bytes = getBytes(iid_loc, 16)
                                    iid_str = get_guid_str(iid_bytes)
                                except Exception as e:
                                    print(e)
                                    print(traceback.format_exc())
                                    print('Exception: unable to process call to {} at {} with arguments {}'.format(addr, op.getSeqnum().getTarget(), len(args), args))
                                    print('-' * 80)
                                    continue
                                print('\nCOM object creation at {}'.format(op.getSeqnum().getTarget()))
                                print('uuid: ', uuid_str)
                                print('iid: ', iid_str)
                                # todo: look up guid with https://www.mangnumdb.com/search?q=%s % uuid_str
                                # todo: check registry for clsid:
                                # powershell -nop -c  &Get-Item 'Microsoft.PowerShell.Core\\Registry::HKCR\\\CLSID\\{%s} % uuid_str
