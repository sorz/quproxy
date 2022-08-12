use std::{
    fmt,
    io::{self, ErrorKind},
    marker::PhantomPinned,
    mem,
    net::SocketAddr,
    os::unix::prelude::AsRawFd,
    pin::Pin,
    ptr,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::ready;
use libc::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, IP_RECVORIGDSTADDR};
use nix::errno::Errno;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{io::unix::AsyncFd, net::UdpSocket};

pub(crate) struct AsyncUdpSocket {
    inner: AsyncFd<Socket>,
}

impl AsyncUdpSocket {
    fn bind(sock: Socket, addr: &SocketAddr) -> io::Result<Self> {
        sock.bind(&(*addr).into())?;
        Ok(Self {
            inner: AsyncFd::new(sock)?,
        })
    }

    pub(crate) fn bind_tproxy(addr: &SocketAddr) -> io::Result<Self> {
        let sock = new_socket(addr)?;
        // Set IP_TRANSPARENT for TPROXY, CAP_NET_ADMIN required.
        sock.set_ip_transparent(true)?;
        sock.set_ip_recv_orig_dst_addr(true)?;
        AsyncUdpSocket::bind(sock, addr)
    }

    pub(crate) fn bind_nonlocal(addr: &SocketAddr) -> io::Result<Self> {
        let sock = new_socket(addr)?;
        sock.set_ip_transparent(true)?;
        AsyncUdpSocket::bind(sock, addr)
    }

    pub(crate) async fn batch_send<const N: usize>(
        &self,
        buf: &mut MsgArrayWriteBuffer<N>,
    ) -> io::Result<(usize, usize)> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| send_mmsg(inner, buf)) {
                Ok(result) => break result,
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) async fn batch_recv<const N: usize, const M: usize>(
        &self,
        buf: &mut Pin<Box<MsgArrayReadBuffer<N, M>>>,
    ) -> io::Result<()> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recv_mmsg(inner, buf)) {
                Ok(result) => break result,
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) fn poll_batch_recv<const N: usize, const M: usize>(
        &self,
        cx: &mut Context<'_>,
        buf: &mut Pin<Box<MsgArrayReadBuffer<N, M>>>,
    ) -> Poll<io::Result<()>> {
        loop {
            match ready!(self.inner.poll_read_ready(cx)) {
                Err(err) => break Poll::Ready(Err(err)),
                Ok(mut guard) => match guard.try_io(|inner| recv_mmsg(inner, buf)) {
                    Ok(result) => break Poll::Ready(result),
                    Err(_would_block) => continue,
                },
            }
        }
    }
}

impl TryFrom<UdpSocket> for AsyncUdpSocket {
    type Error = io::Error;

    fn try_from(value: UdpSocket) -> Result<Self, Self::Error> {
        let socket = value.into_std()?.into();
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }
}

fn new_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let domain = Domain::for_address(*addr);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    Ok(sock)
}

struct WriteMsg<const N: usize> {
    addr: Option<SockAddr>,
    iovecs: [libc::iovec; N],
    bufs: [Bytes; N],
}

#[derive(Default)]
pub(crate) struct MsgArrayWriteBuffer<const N: usize> {
    pos: usize,
    msgs: Vec<WriteMsg<N>>,
    hdrs: Vec<libc::mmsghdr>, // may contain ptr to element of `msgs`
}

impl<const N: usize> MsgArrayWriteBuffer<N> {
    pub(crate) fn with_capacity(len: usize) -> Self {
        Self {
            pos: 0,
            msgs: Vec::with_capacity(len),
            hdrs: Vec::with_capacity(len),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.pos = 0;
        self.msgs.clear();
        self.hdrs.clear();
    }

    pub(crate) fn push(&mut self, bufs: [Bytes; N], dest: Option<SocketAddr>) {
        self.msgs.push(WriteMsg {
            addr: dest.map(|s| s.into()),
            // `iovec` will be initialized on `prepare_hdrs()`
            iovecs: unsafe { mem::zeroed() },
            bufs,
        })
    }

    fn prepare_hdrs(&mut self) -> &mut [libc::mmsghdr] {
        self.hdrs.resize(self.msgs.len(), unsafe { mem::zeroed() });
        self.hdrs
            .iter_mut()
            .skip(self.pos)
            .zip(self.msgs.iter_mut().skip(self.pos))
            .for_each(|(hdr, msg)| {
                msg.iovecs
                    .iter_mut()
                    .zip(msg.bufs.iter())
                    .for_each(|(iovec, buf)| {
                        *iovec = libc::iovec {
                            iov_base: buf.as_ptr() as *mut _,
                            iov_len: buf.len(),
                        };
                    });
                hdr.msg_len = 0; // return value
                hdr.msg_hdr = libc::msghdr {
                    msg_name: msg
                        .addr
                        .as_ref()
                        .map(|a| a.as_ptr() as *mut _)
                        .unwrap_or(ptr::null_mut()),
                    msg_namelen: msg.addr.as_ref().map(|a| a.len()).unwrap_or(0),
                    msg_iov: &mut msg.iovecs as *mut _,
                    msg_iovlen: msg.iovecs.len(),
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
            });
        &mut self.hdrs[self.pos..]
    }

    pub(crate) fn advance(&mut self, len: usize) {
        self.pos += len;
        assert!(self.pos <= self.msgs.len());
    }

    pub(crate) fn has_remaining(&self) -> bool {
        self.pos < self.msgs.len()
    }
}

// Safety: all raw pointers are self-referential.
unsafe impl<const N: usize> Send for MsgArrayWriteBuffer<N> {}
// Safety: no interior mutability
unsafe impl<const N: usize> Sync for MsgArrayWriteBuffer<N> {}

pub(crate) struct MsgArrayReadBuffer<const N: usize, const M: usize> {
    msg_cnt: usize,
    msgs: [libc::mmsghdr; N], // contains ptr to `addrs`, `ctrls`, and `iovecs`
    addrs: [libc::sockaddr_storage; N],
    ctrls: [[u8; 128]; N],
    iovecs: [libc::iovec; N], // contains ptr to `bufs`
    bufs: [[u8; M]; N],
    _pin: PhantomPinned,
}

// Safety: all raw pointers are self-referential.
unsafe impl<const N: usize, const M: usize> Send for MsgArrayReadBuffer<N, M> {}
// Safety: no interior mutability
unsafe impl<const N: usize, const M: usize> Sync for MsgArrayReadBuffer<N, M> {}

#[derive(Debug)]
pub(crate) struct Message<'a> {
    pub(crate) src_addr: Option<SocketAddr>,
    pub(crate) dst_addr: Option<SocketAddr>,
    pub(crate) buf: &'a [u8],
}

impl fmt::Display for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Message ({}B", self.buf.len())?;
        match (self.src_addr, self.dst_addr) {
            (Some(src), Some(dst)) => write!(f, " {} => {})", src, dst),
            (Some(src), None) => write!(f, " {} => ?)", src),
            (None, Some(dst)) => write!(f, " ? => {})", dst),
            (None, None) => write!(f, ")"),
        }
    }
}

impl<const N: usize, const M: usize> MsgArrayReadBuffer<N, M> {
    pub(crate) fn new() -> Pin<Box<Self>> {
        unsafe {
            // Safety: there is no references (except raw pointers);
            // [u8] and libc types allow zeros.
            let mut boxed = Box::pin(mem::zeroed());
            let mut_pin: Pin<&mut Self> = Pin::as_mut(&mut boxed);
            let mut_ref = mut_pin.get_unchecked_mut();
            for i in 0..N {
                mut_ref.iovecs[i] = libc::iovec {
                    iov_base: &mut mut_ref.bufs[i] as *mut _ as *mut _,
                    iov_len: mut_ref.bufs[i].len(),
                };
                mut_ref.msgs[i].msg_hdr = libc::msghdr {
                    msg_name: &mut mut_ref.addrs[i] as *mut _ as *mut _,
                    msg_namelen: mem::size_of_val(&mut_ref.addrs[i]) as libc::socklen_t,
                    msg_iov: &mut mut_ref.iovecs[i] as *mut _ as *mut _,
                    msg_iovlen: 1,
                    msg_control: &mut mut_ref.ctrls[i] as *mut _ as *mut _,
                    msg_controllen: mut_ref.ctrls[i].len(),
                    msg_flags: 0,
                };
            }
            boxed
        }
    }

    pub(crate) fn iter<'a>(self: &'a Pin<Box<Self>>) -> impl ExactSizeIterator<Item = Message<'a>> {
        (0..self.msg_cnt).map(|i| self.get(i))
    }

    pub(crate) fn clear(self: &mut Pin<Box<Self>>) {
        let mut_pin = Pin::as_mut(self);
        unsafe {
            mut_pin.get_unchecked_mut().msg_cnt = 0;
        }
    }

    pub(crate) fn len(self: &Pin<Box<Self>>) -> usize {
        self.msg_cnt
    }

    pub(crate) fn get<'a>(self: &'a Pin<Box<Self>>, idx: usize) -> Message<'a> {
        if idx >= self.msg_cnt {
            panic!("out of index");
        }
        let src_addr =
            unsafe { SockAddr::new(self.addrs[idx], self.msgs[idx].msg_hdr.msg_namelen) };
        let dst_addr = parse_dest_addr_from_cmsg(&self.msgs[idx].msg_hdr).ok();
        Message {
            src_addr: src_addr.as_socket(),
            dst_addr: dst_addr.and_then(|d| d.as_socket()),
            buf: &self.bufs[idx][..self.msgs[idx].msg_len as usize],
        }
    }
}

fn send_mmsg<T, const N: usize>(
    fd: &T,
    buf: &mut MsgArrayWriteBuffer<N>,
) -> io::Result<(usize, usize)>
where
    T: AsRawFd,
{
    let hdrs = buf.prepare_hdrs();
    let vlen = hdrs.len();
    let ret = unsafe {
        libc::sendmmsg(
            fd.as_raw_fd(),
            hdrs.as_mut_ptr(),
            vlen.try_into().unwrap(),
            0,
        )
    };
    let msg_cnt = Errno::result(ret)? as usize;
    let bytes_cnt = hdrs.iter().fold(0usize, |n, hdr| n + hdr.msg_len as usize);
    Ok((msg_cnt, bytes_cnt))
}

fn recv_mmsg<const N: usize, const M: usize, T>(
    fd: &T,
    buf: &mut Pin<Box<MsgArrayReadBuffer<N, M>>>,
) -> io::Result<()>
where
    T: AsRawFd,
{
    let mut_pin = Pin::as_mut(buf);
    unsafe {
        let mut_ref = mut_pin.get_unchecked_mut();
        mut_ref.msg_cnt = 0;
        let ret = libc::recvmmsg(
            fd.as_raw_fd(),
            mut_ref.msgs.as_mut_ptr(),
            mut_ref.msgs.len().try_into().unwrap(),
            0,
            ptr::null_mut(),
        );
        mut_ref.msg_cnt = Errno::result(ret)? as usize;
    };
    Ok(())
}

fn parse_dest_addr_from_cmsg(msghdr: &libc::msghdr) -> io::Result<SockAddr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msghdr) };
    while !cmsg.is_null() {
        let size = match unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) } {
            (IPPROTO_IP, libc::IP_RECVORIGDSTADDR) => Some(mem::size_of::<libc::sockaddr_in>()),
            (IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
                Some(mem::size_of::<libc::sockaddr_in6>())
            }
            _ => None,
        };
        if let Some(size) = size {
            let (_, addr) = unsafe {
                SockAddr::init(|addr_storage, len| {
                    let data = libc::CMSG_DATA(cmsg);
                    ptr::copy_nonoverlapping(data, addr_storage as *mut _, size);
                    *len = size as libc::socklen_t;
                    Ok(())
                })
            }?;
            return Ok(addr);
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msghdr, cmsg) };
    }
    Err(io::Error::new(
        ErrorKind::NotFound,
        "missing dest addr on msghdr",
    ))
}

pub trait SocketExt {
    fn set_ip_recv_orig_dst_addr(&self, enable: bool) -> io::Result<()>;
}

impl SocketExt for Socket {
    fn set_ip_recv_orig_dst_addr(&self, enable: bool) -> io::Result<()> {
        setsockopt_bool(self, IPPROTO_IP, IP_RECVORIGDSTADDR, enable)?;
        if matches!(self.domain()?, Domain::IPV6) {
            setsockopt_bool(self, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, enable)?;
        }
        Ok(())
    }
}

fn setsockopt_bool<T: AsRawFd>(
    sock: &T,
    level: libc::c_int,
    name: libc::c_int,
    val: bool,
) -> io::Result<()> {
    let val: libc::c_int = if val { 1 } else { 0 };
    let ret = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            &val as *const _ as *const _,
            mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    Errno::result(ret)?;
    Ok(())
}
