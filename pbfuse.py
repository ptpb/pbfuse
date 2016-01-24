import llfuse
import stat
import errno
import sys

from urllib import parse
from dateutil.parser import parse as dt_parse
from itertools import count
from collections import defaultdict
from datetime import datetime
from time import monotonic
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

    def post(self, filename, content):
        files = {
            'content': (filename, content)
        }
        res = self.session.post(self.url, files=files)
        return res.json()

    def create(self, filename):
        content = '{}-{}'.format(datetime.utcnow().timestamp(), monotonic()).encode('utf-8')
        return self.post(filename, content)

    def put(self, uuid, content):
        url = parse.urljoin(self.url, uuid)
        files = {
            'content': ('', content)
        }
        res = self.session.put(url, files=files)
        return res.json()

INO_CUR = 2
INO_NEW = 3

class Operations(llfuse.Operations):
    def __init__(self):
        super().__init__()

        self.client = Client()

        self._inodes = count(4)

        self._cache = {}

        self._lookup = defaultdict(dict)
        self._lookup.update({
            1: {b'cur': INO_CUR, b'new': INO_NEW}
        })

        self._metadata = {}

        self._stat = {
            1: stat.S_IFDIR | 0o555,
            INO_CUR: stat.S_IFDIR | 0o555,
            INO_NEW: stat.S_IFDIR | 0o755
        }

        self._link = {}

        self._session = count(3)
        self._sessions = defaultdict(dict)

    def create(self, inode_p, name, mode, flags, ctx):
        if inode_p != INO_NEW:
            raise llfuse.FUSEError(errno.EPERM)

        try:
            res = self.client.create(name.decode('utf-8'))
        except Exception as e:
            raise llfuse.FUSEError(errno.EIO)

        inode_r = next(self._inodes)
        self._metadata[inode_r] = res
        self._lookup[INO_CUR][res['short'].encode('utf-8')] = inode_r

        inode = next(self._inodes)
        self._lookup[INO_NEW][name] = inode
        self._stat[inode] = stat.S_IFLNK | 0o444
        self._link[inode] = '../cur/{}'.format(res['short']).encode('utf-8')

        return self.open(inode_r, None), self.getattr(inode_r)

    def readlink(self, inode):
        return self._link[inode]

    def opendir(self, inode):
        return inode

    def lookup(self, inode_p, name):
        try:
            return self.getattr(self._lookup[inode_p][name])
        except KeyError:
            pass

        if inode_p != INO_CUR:
            raise llfuse.FUSEError(errno.ENOENT)

        try:
            res = self.client.report(name.decode('utf-8'))
        except:
            raise llfuse.FUSEError(errno.ENOENT)
        if res['status'] != 'found':
            raise llfuse.FUSEError(errno.ENOENT)

        inode = next(self._inodes)

        self._metadata[inode] = res
        self._lookup[inode_p][name] = inode

        return self.getattr(inode)

    def readdir(self, inode, off):
        if off != 0:
            raise StopIteration

        off = -1

        for name, cinode in self._lookup[inode].items():
            llfuse.invalidate_entry(inode, name)
            yield (name, self.getattr(cinode), -1)

    def getattr(self, inode):
        entry = llfuse.EntryAttributes()

        entry.st_ino = inode

        entry.st_mode = self._stat.get(inode, stat.S_IFREG | 0o444)

        if inode <= 3 or (stat.S_IFLNK & entry.st_mode) == stat.S_IFLNK:
            return entry

        if 'uuid' in self._metadata[inode]:
            entry.st_mode |= 0o644

        dt = int(dt_parse(self._metadata[inode]['date']).timestamp() * 1e9)
        entry.st_mtime_ns = dt
        entry.st_ctime_ns = dt
        entry.st_atime_ns = dt

        entry.st_size = self._metadata[inode]['size']

        return entry

    def open(self, inode, flags):
        fh = next(self._session)

        self._sessions[fh]['inode'] = inode

        return fh

    def release(self, fh):
        if 'buf' in self._sessions[fh]:
            inode = self._sessions[fh]['inode']
            uuid = self._metadata[inode]['uuid']
            buf = self._sessions[fh]['buf']
            res = self.client.put(uuid, buf)
            if res['status'] != 'updated':
                raise llfuse.FUSEError(errno.EIO)

            self._cache[inode] = buf

            self._lookup[INO_CUR][res['short'].encode('utf-8')] = inode

            short = self._metadata[inode]['short'].encode('utf-8')
            for key, value in self._link.items():
                if short in value:
                    self._link[key] = '../cur/{}'.format(res['short']).encode('utf-8')

            del self._lookup[INO_CUR][short]
            self._metadata[inode].update(res)

        del self._sessions[fh]

    def setattr(self, inode, attr):
        return self.getattr(inode)

    def read(self, fh, offset, length):
        inode = self._sessions[fh]['inode']

        if inode in self._cache:
            return self._cache[inode][offset:offset+length]

        uri = self._metadata[inode]['digest']
        res = self.client.get(uri)
        self._cache[inode] = res.content

        return res.content[offset:offset+length]

    def write(self, fh, offset, buf):
        if fh not in self._sessions:
            fh = self.open(fh, None)
        inode = self._sessions[fh]['inode']

        if 'buf' not in self._sessions[fh]:
            self._sessions[fh]['buf'] = b''

        self._sessions[fh]['buf'] += buf

        return len(buf)

if __name__ == '__main__':
    operations = Operations()

    llfuse.init(operations, sys.argv[1], [])
    try:
        llfuse.main(single=True)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()
