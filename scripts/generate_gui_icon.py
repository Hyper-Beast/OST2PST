"""Deterministic original application icon, generated using only the Python standard library."""
from pathlib import Path
import struct
import zlib

def png(size):
    def color(x, y):
        x, y = x / size, y / size
        # Rounded blue tile, white document and an arrow pointing to its destination.
        dx, dy = max(.12-x, 0, x-.88), max(.12-y, 0, y-.88)
        if dx*dx+dy*dy > .12*.12:
            return (0,0,0,0)
        if .26 < x < .65 and .20 < y < .80 and not (x > .52 and y < .33 and x-y > .32):
            if .34 < x < .55 and (.39 < y < .43 or .49 < y < .53 or .59 < y < .63):
                return (40,91,215,255)
            return (255,255,255,255)
        if .60 < x < .84 and abs(y-.65) < .035 or .73 < x < .87 and abs(y-.65) < .87-x:
            return (255,255,255,255)
        return (40,91,215,255)
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            samples = [color(x+(i+.5)/3,y+(j+.5)/3) for i in range(3) for j in range(3)]
            raw.extend(round(sum(c[k] for c in samples)/9) for k in range(4))
    def chunk(name, data):
        return struct.pack('>I',len(data))+name+data+struct.pack('>I',zlib.crc32(name+data))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',size,size,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(raw,9))+chunk(b'IEND',b'')

if __name__ == '__main__':
    images = [(n,png(n)) for n in (16,32,48,256)]
    offset = 6+16*len(images)
    out = struct.pack('<HHH',0,1,len(images))
    for n,data in images:
        out += struct.pack('<BBBBHHII',n%256,n%256,0,0,1,32,len(data),offset)
        offset += len(data)
    out += b''.join(data for _,data in images)
    (Path(__file__).resolve().parents[1]/'resources/gui/app.ico').write_bytes(out)
