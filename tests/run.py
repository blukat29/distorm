import subprocess
import sys
import re
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
re_hex = '[0-9a-fA-F]+'
re_distorm = re.compile('('+re_hex+')' + ' \((\d+)\) ' + re_hex + '\s+(\w+) ?.*')

def do_run(cmd):
    try:
        return subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print ' '.join(cmd)
        raise e

def run_distorm(target, bits=64, offset=0x400000):
    cmd = (os.path.join(SCRIPT_DIR, 'disasm'),)
    if bits == 64:
        cmd += ('-b64',)
    elif bits == 16:
        cmd += ('-b16',)
    cmd += (target,)
    if offset:
        cmd += (hex(offset),)
    out = do_run(cmd)
    return out

def run_objdump(target, bits=64, offset=0x400000):
    cmd = ('objdump', '-D', '-b', 'binary', '-M', 'intel',)
    if bits == 64:
        cmd += ('-mi386:x86-64',)
    elif bits == 32:
        cmd += ('-mi386',)
    elif bits == 16:
        cmd += ('-mi8086',)
    if offset:
        cmd += ('--adjust-vma=' + hex(offset),)
    cmd += (target,)
    out = do_run(cmd)
    return out

def parse_distorm(out):
    i = 0
    res = ''
    for line in out.splitlines():
        i += 1
        if i <= 4:
            continue
        m = re_distorm.match(line)
        if m:
            offset = int(m.group(1), 16)
            size = int(m.group(2), 16)
            opcode = m.group(3).lower()
            res += '%016x %02d %s\n' % (offset, size, opcode)
    return res

def parse_objdump(out):
    i = 0
    insts = []
    for line in out.splitlines():
        i += 1
        if i <= 7:
            continue
        if line.startswith('\t...'):
            continue
        tokens = line.split('\t')
        if len(tokens) == 3:
            offset, raw, asm = tokens
            offset = int(offset.rstrip(':'), 16)
            size = len(raw.strip().split())
            opcode = asm.split()[0]
            insts.append([offset, size, opcode])
        elif len(tokens) == 2:
            offset, raw = tokens
            size = len(raw.strip().split())
            insts[-1][1] += size
    res = ''
    for inst in insts:
        offset, size, opcode = inst
        res += '%016x %02d %s\n' % (offset, size, opcode)
    return res

def check(target):
    x = run_distorm(target)
    x = parse_distorm(x)
    fx = os.path.join(SCRIPT_DIR, 'distorm.txt')
    with open(fx, 'w') as f:
        f.write(x)

    y = run_objdump(target)
    y = parse_objdump(y)
    fy = os.path.join(SCRIPT_DIR, 'objdump.txt')
    with open(fy, 'w') as f:
        f.write(y)

    if x != y:
        print "NO"
    else:
        print "OK"

if __name__ == '__main__':
    target = sys.argv[1]
    check(target)
