_PTR_PREFIX = 0b1100

class DnsName:

    def __init__(self):
        self.sections = None

    def load(self, byte_iter):
        self.sections = list(self.__sections(byte_iter))

    def dump(self):
        return list(self)

    def __iter__(self):
        for section in self.sections:
            
            if type(section) == int:
                yield section | _PTR_PREFIX
                # ptr must be the last section and we don't
                # need the ending 0 if section ends with ptr
                return
            
            length = len(section)
            yield length // 0x100
            yield length % 0x100
            yield from section

        # yield the ending 0
        yield 0

        
    def __sections(self, byte_iter):

        first = next(byte_iter)
        second = next(byte_iter)
        
        while True:
            if first & _PTR_PREFIX == _PTR_PREFIX:
                # this is a pointer
                ptr = (first - _PTR_PREFIX) * 0x100 + second
                yield ptr
                # pointer must be the last section
                return
            
            # otherwise...
            length = first * 0x100 + second
            
            if length == 0:
                # end of sections
                return

            # this is a label
            yield [ next(byte_iter) for _ in range(length) ]
        

class DnsRecord:

    def __init__(self):

        self.name = None
        self.type = None
        self.cls = None
        self.ttl = None
        self.rddata = None

    def load(self, byte_iter):

        self.name = DnsName()
        self.name.load(byte_iter)
        
        self.type = next(byte_iter) * 0x100 + next(byte_iter)
        self.cls = next(byte_iter) * 0x100 + next(byte_iter)
        self.ttl = (next(byte_iter) << 24) + (next(byte_iter) << 16) + (next(byte_iter) << 8) + next(byte_iter)

        length =  next(byte_iter) * 0x100 + next(byte_iter)
        self.rddata = [ next(byte_iter) for _ in range(length) ]

    def dump(self):
        return list(self)
    
    def __iter__(self):
        yield from self.name
        yield self.type // 0x100
        yield self.type % 0x100
        yield self.cls // 0x100
        yield self.cls % 0x100
        yield self.ttl >> 24
        yield (self.ttl >> 16) % 0x100
        yield (self.ttl >> 8) % 0x100
        yield self.ttl % 0x100
        length = len(self.rddata)
        yield length // 0x100
        yield length % 0x100
        yield from self.rddata

class DnsHead:

    def __init__(self):
    
        self.is_query = False
        self.opcode = 0
        self.authoritative = False
        self.truncation = False
        self.recursion_desired = True
        self.recursion_available = True
        self.Z = 0
        self.rcode = 0

    def load(self, byte_iter):
        first = next(byte_iter)
        second = next(byte_iter)

        self.is_query = (first & 0x80) == 0x80
        self.opcode = (first & 0b01111000) >> 3
        self.authoritative = (first & 0b00000100) == 0b00000100
        self.truncation = (first & 0b00000010) == 0b00000010
        self.recursion_desired = (first & 0x01) == 0x01
        self.recursion_available = (second & 0x80) == 0x80
        self.Z = (second & 0x01110000) >> 4
        self.rcode = second % 0x10000
    
    def dump(self):
        return list(self)

    def __iter__(self):
        yield (0 if self.is_query else 0x80) +       \
              (self.opcode << 3) +                   \
              (0b100 if self.authoritative else 0) + \
              (0b10 if self.truncation else 0) +     \
              (1 if self.recursion_desired else 0)
        yield (0x80 if self.recursion_available else 0) + \
              (self.Z << 4) +                             \
              self.rcode

class DnsQuery:

    def __init__(self):
        self.name = DnsName()
        self.type = None
        self.cls  = None

    def load(self, byte_iter):
        
        self.name.load(byte_iter)
        self.type = next(byte_iter) * 0x100 + next(byte_iter)
        self.cls = next(byte_iter) * 0x100 + next(byte_iter)

    def dump(self):
        return list(self)

    def __iter__(self):
        yield from self.name
        yield self.type // 0x100
        yield self.type % 0x100
        yield self.cls // 0x100
        yield self.cls % 0x100

class DnsMessage:

    def __init__(self):
    
        self.head = DnsHead()

        self.query = []
        self.answer = []
        self.ns = []
        self.additional = []

    def load(self, byte_iter):
        
        self.head.load(byte_iter)

        qdcount = next(byte_iter) * 0x100 + next(byte_iter)
        ancount = next(byte_iter) * 0x100 + next(byte_iter)
        nscount = next(byte_iter) * 0x100 + next(byte_iter)
        arcount = next(byte_iter) * 0x100 + next(byte_iter)

        self.query = [ DnsQuery() for _ in range(qdcount) ]
        for r in self.query:
            r.load(byte_iter)

        self.answer = [ DnsRecord() for _ in range(ancount) ]
        for r in self.answer:
            r.load(byte_iter)

        self.ns = [ DnsRecord() for _ in range(nscount) ]
        for r in self.ns:
            r.load(byte_iter)
        
        self.additional = [ DnsRecord() for _ in range(arcount) ]
        for r in self.additional:
            r.load(byte_iter)

    def dump(self):
        return list(self)

    def __iter__(self):
        
        yield from self.head

        qdcount = len(self.query)
        ancount = len(self.answer)
        nscount = len(self.ns)
        arcount = len(self.additional)

        yield qdcount // 0x100
        yield qdcount % 0x100
        yield ancount // 0x100
        yield ancount % 0x100
        yield nscount // 0x100
        yield nscount % 0x100
        yield arcount // 0x100
        yield arcount % 0x100

        for s in [ self.query, self.answer, self.ns, self.additional ]:
            for r in s:
                yield from r

    def human_readable_name(self, name):
        
        return "".join(chr(ch) for ch in self.dereference_name(name))

    
    def dereference_name(self, name, raw_blob = None):

        if raw_blob == None:
            raw_blob = self.dump()

        for section in name.sections:
            if type(section) == list:
                yield from section
            else:
                sub_name = DnsName()
                sub_name.load(iter(raw_blob[section:]))
                yield from self.dereference_name(sub_name, raw_blob)

    
