import json, argparse, re

indirectTemplate = '''    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;

        sub RSP, 0X28;
        mov ECX, {hash};
        call getSyscallJmpAddr;
        add RSP, 0X28;
        mov R11, RAX;

        sub RSP, 0x28;
        mov ECX, {hash};
        call getSyscallNumber;              
        add RSP, 0x28;

        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        jmp R11;              
        ret;

    }'''

directTemplate = '''    asm {
        naked;
        mov [RSP +8], RCX;         
        mov [RSP+16], RDX;
        mov [RSP+24], R8;
        mov [RSP+32], R9;
        sub RSP, 0x28;
        mov ECX, {hash};
        call getSyscallNumber;              
        add RSP, 0x28;
        mov RCX, [RSP+8];                      
        mov RDX, [RSP+16];
        mov R8, [RSP+24];
        mov R9, [RSP+32];
        mov R10, RCX;
        syscall;              
        ret;

    }'''

def djb2(s):                                                                                                                                
    hash = 0x25636360
    for x in s:
        hash = (( hash << 5 ) + hash) + ord(x)
    return hash & 0xFFFFFFFF


class Generator:
    def __init__(self, syscallType) -> None:
        self.syscallType = syscallType

    def get_fn_args(self, params) -> str:
        finalArgs = []

        for param in params:
            argType = param['type']
            argName = param['name']

            finalArgs.append(f'\t{argType} {argName},\n')

        return ''.join(finalArgs)
    
    def gen_d_func_def(self, fnName, fnObj) -> str:
        returnType = fnObj['type']
        params = fnObj['params']
        fnDef = f'extern(Windows) {returnType} {fnName}(\n{self.get_fn_args(params)})'
        return fnDef
    
    def get_fn_hash(self, fnName: str) -> str:
        return hex(djb2(fnName))

    def gen_d_func_stub(self, fnName) -> str:
        fnTemplate = indirectTemplate if self.syscallType.lower() == 'indirect' else directTemplate
        return fnTemplate.replace('{hash}', self.get_fn_hash(fnName))
    
    def gen_d_func(self, fnName, fnDef) -> str:
        fnStub = self.gen_d_func_stub(fnName)
        
        final = f'{fnDef}'
        final += ' {\n\n' + fnStub + '\n\n}'
        return final

    

parser = argparse.ArgumentParser(
    prog = 'DLangWhispers',
    description = 'System Call D Module Generator.'
)

parser.add_argument('-t', '--type', help = 'Type Of System Call')
parser.add_argument('-f','--functions', help = 'Target Functions To Be Put In Stubs')
parser.add_argument('-o', '--output', help = 'Ouput File')

args = parser.parse_args()

syscallType = args.type
functions = args.functions.split(',')
output = args.output

if not syscallType.lower() in ['direct', 'indirect']:
    print('[-] Choose A Valid System Call Type!')
    quit(0)

gen = Generator(syscallType = syscallType)

fnPrototypes = json.load(open('./data/prototypes.json', 'r', errors = 'ignore'))
outputFile = open(output, 'w')

for fnName, fn in fnPrototypes.items():
    if fnName in functions:
        fn = gen.gen_d_func(fnName, gen.gen_d_func_def(fnName, fn))
        outputFile.write(fn + '\n')


outputFile.close()
