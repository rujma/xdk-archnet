import msgpack

with open("test_pack.bin", "rb") as fp:
    a = fp.read()
    l = msgpack.unpackb(a.split(b'\0',1)[0])
    print(l)