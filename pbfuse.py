import llfuse
import stat
import errno
import sys

from urllib import parse
from dateutil.parser import parse as dt_parse
from itertools import count
from collections import defaultdict
from enum import IntEnum
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

class Inode(IntEnum):
    root = 1
    cur = 2
    new = 3

class Operations(llfuse.Operations):
    def __init__(self):
        super().__init__()

        self.client = Client()

        self._state = {
            '_inodes': count(4),            # global inode counter
            '_session': count(3),           # global session counter
            '_sessions': defaultdict(dict), # maps [fh]            -> ['inode'], ['buf']
            '_lookup': defaultdict(dict),   # maps [inode_p][name] -> inode
            '_content': {},                 # maps [inode]         -> paste_content
            '_metadata': {},                # maps [inode]         -> paste_meta
            '_stat': {},                    # maps [inode]         -> st_mode
            '_link': {},                    # maps [inode]         -> link destination
        }

        self._stat.update({
            Inode.root: stat.S_IFDIR | 0o555,
            Inode.cur: stat.S_IFDIR | 0o555,
            Inode.new: stat.S_IFDIR | 0o755
        })

        self._lookup.update({
            Inode.root: {b'cur': Inode.cur, b'new': Inode.new}
        })

    def __getattr__(self, name):
        try:
            return self._state[name]
        except KeyError:
            return super().__getattr__(name)

    def create(self, inode_p, name, mode, flags, ctx):

        if inode_p != Inode.new:
            raise llfuse.FUSEError(errno.EPERM)

        try:
            res = self.client.create(name.decode('utf-8'))
        except Exception as e:
            raise llfuse.FUSEError(errno.EIO)

        inode_r = next(self._inodes)
        self._metadata[inode_r] = res
        self._lookup[Inode.cur][res['short'].encode('utf-8')] = inode_r

        inode = next(self._inodes)
        self._lookup[Inode.new][name] = inode
        self._stat[inode] = stat.S_IFLNK | 0o444
        self._link[inode] = '../cur/{}'.format(res['short']).encode('utf-8')

        return self.open(inode_r, None), self.getattr(inode_r)

    def readlink(self, inode):
        return self._link[inode]

    def opendir(self, inode):
        return inode

    def lookup(self, inode_p, name):
        try:
            print(inode_p, name)
            return self.getattr(self._lookup[inode_p][name])
        except KeyError:
            pass

        if inode_p != Inode.cur:
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

        # fixme
        off = -1

        for name, cinode in self._lookup[inode].items():
            if inode == Inode.new:
                # we tell lies in create(), which the kernel caches
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

    def _resymlink(self, old_target, new_target):
        for inode, target in self._link.items():
            if old_target in target:
                self._link[inode] = '../cur/{}'.format(new_target.decode('utf-8')).encode('utf-8')

    def release(self, fh):
        if 'buf' in self._sessions[fh]:
            inode, buf = [self._sessions[fh][k] for k in ('inode', 'buf')]
            buf = bytes(buf)
            uuid = self._metadata[inode]['uuid']
            res = self.client.put(uuid, buf)
            if res['status'] != 'updated':
                del self._sessions[fh]
                raise llfuse.FUSEError(errno.EIO)

            # create new dirent
            new_name = res['short'].encode('utf-8')
            self._lookup[Inode.cur][new_name] = inode

            # remove old dirent
            old_name = self._metadata[inode]['short'].encode('utf-8')
            del self._lookup[Inode.cur][old_name]

            # update symlinks
            self._resymlink(old_name, new_name)

            # update metadata and content caches
            self._content[inode] = buf
            self._metadata[inode].update(res)

        del self._sessions[fh]

    def setattr(self, inode, attr):
        # no-op
        return self.getattr(inode)

    def read(self, fh, offset, length):
        inode = self._sessions[fh]['inode']

        if inode in self._content:
            return self._content[inode][offset:offset+length]

        uri = self._metadata[inode]['digest']
        res = self.client.get(uri)
        self._content[inode] = res.content

        return res.content[offset:offset+length]

    def write(self, fh, offset, ibuf):
        if fh not in self._sessions:
            fh = self.open(fh, None)

        if 'buf' not in self._sessions[fh]:
            self._sessions[fh]['buf'] = bytearray()

        buf = self._sessions[fh]['buf']
        buf[offset:offset+len(ibuf)] = ibuf

        return len(buf)

if __name__ == '__main__':
    operations = Operations()

    llfuse.init(operations, sys.argv[1], ['debug'])
    try:
        llfuse.main(single=True)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()
