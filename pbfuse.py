import llfuse
import stat
import errno

from urllib import parse
from dateutil.parser import parse as dt_parse
import requests

class PBSession(requests.Session):
    def request(self, method, url, **kwargs):
        headers = {
            'Accept': 'application/json'
        }

        return super().request(method, url, headers=headers, **kwargs)

    def report(self, url, **kwargs):
        return self.request('REPORT', url, **kwargs)

class Client():
    url = 'https://ptpb.pw/'

    def __init__(self):
        self.session = PBSession()

    def get(self, name):
        url = parse.urljoin(self.url, name)
        res = self.session.get(url)
        return res

    def report(self, name):
        url = parse.urljoin(self.url, name)
        res = self.session.report(url)
        return res.json()

class Operations(llfuse.Operations):
    def __init__(self):
        super().__init__()

        self.client = Client()
        self._inodes = 1
        self._table = {}
        self._names = {}
        self._cache = {}

    def opendir(self, inode):
        return inode

    def lookup(self, inode_p, name):
        if name in self._names:
            return self.getattr(self._names[name])

        res = self.client.report(name.decode('utf-8'))
        if res['status'] != 'found':
            raise llfuse.FUSEError(errno.ENOENT)

        self._inodes += 1
        self._table[self._inodes] = res
        self._names[name] = self._inodes

        return self.getattr(self._inodes)

    def readdir(self, inode, off):
        if off == 0:
            off = -1

            for name, inode in self._names.items():
                yield (name, self.getattr(inode), -1)

    def getattr(self, inode):
        entry = llfuse.EntryAttributes()

        entry.st_ino = inode

        if inode == 1:
            entry.st_mode = stat.S_IFDIR | 0o755
            return entry

        entry.st_mode = stat.S_IFREG | 0o644

        dt = int(dt_parse(self._table[inode]['date']).timestamp() * 1e9)
        entry.st_mtime_ns = dt
        entry.st_ctime_ns = dt
        entry.st_atime_ns = dt

        if inode not in self._cache:
            # mega hack
            self.read(inode, 0, 0)
        entry.st_size = len(self._cache[inode])

        return entry

    def open(self, inode, flags):
        return inode # is fh

    def read(self, fh, offset, length):
        print(offset, length)
        if fh in self._cache:
            print('cache hit')
            return self._cache[fh][offset:offset+length]

        print('cache miss')

        uri = self._table[fh]['digest']
        res = self.client.get(uri)
        self._cache[fh] = res.content

        print('content', res.content)
        print('content2', res.content[offset:offset+length])
        return res.content[offset:offset+length]

if __name__ == '__main__':
    operations = Operations()

    llfuse.init(operations, '/tmp/lol', [])
    try:
        llfuse.main(single=True)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()
