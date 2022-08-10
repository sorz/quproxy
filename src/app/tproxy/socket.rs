use std::{
    io::{self, ErrorKind},
    marker::PhantomPinned,
    mem,
    net::SocketAddr,
    os::unix::prelude::AsRawFd,
    pin::Pin,
    ptr,
};

use libc::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, IP_RECVORIGDSTADDR};
use nix::errno::Errno;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::app::types::ClientAddr;

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

    pub(crate) async fn batch_recv<const N: usize, const M: usize>(
        &self,
        buf: &mut Pin<Box<MsgArrayBuffer<N, M>>>,
    ) -> io::Result<()> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recv_mmsg(inner, buf)) {
                Ok(result) => break result,
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) async fn send_to(&self, buf: &[u8], target: ClientAddr) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| send_to(inner, buf, target.0)) {
                Ok(result) => break result,
                Err(_would_block) => continue,
            }
        }
    }
}

fn new_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let domain = Domain::for_address(*addr);
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    Ok(sock)
}

fn send_to<T: AsRawFd>(fd: &T, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
    let target: SockAddr = target.into();
    let ret = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            0,
            target.as_ptr(),
            target.len(),
        )
    };
    let len = Errno::result(ret)? as usize;
    Ok(len)
}

pub(crate) struct MsgArrayBuffer<const N: usize, const M: usize> {
    msg_cnt: usize,
    msgs: [libc::mmsghdr; N], // contains ptr to `addrs`, `ctrls`, and `iovecs`
    addrs: [libc::sockaddr_storage; N],
    ctrls: [[u8; 128]; N],
    iovecs: [libc::iovec; N], // contains ptr to `bufs`
    bufs: [[u8; M]; N],
    _pin: PhantomPinned,
}

// Safety: all raw pointers are self-referential.
unsafe impl<const N: usize, const M: usize> Send for MsgArrayBuffer<N, M> {}
// Safety: no interior mutability
unsafe impl<const N: usize, const M: usize> Sync for MsgArrayBuffer<N, M> {}

pub(crate) struct Message<'a> {
    pub(crate) src_addr: Option<SocketAddr>,
    pub(crate) dst_addr: Option<SocketAddr>,
    pub(crate) buf: &'a [u8],
}

impl<const N: usize, const M: usize> MsgArrayBuffer<N, M> {
    pub(crate) fn new() -> Pin<Box<Self>> {
        unsafe {
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
        (0..self.msg_cnt).map(|i| {
            let src_addr =
                unsafe { SockAddr::new(self.addrs[i], self.msgs[i].msg_hdr.msg_namelen) };
            let dst_addr = parse_dest_addr_from_cmsg(&self.msgs[i].msg_hdr).ok();
            Message {
                src_addr: src_addr.as_socket(),
                dst_addr: dst_addr.and_then(|d| d.as_socket()),
                buf: &self.bufs[i][..self.msgs[i].msg_len as usize],
            }
        })
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
}

fn recv_mmsg<const N: usize, const M: usize, T>(
    fd: &T,
    buf: &mut Pin<Box<MsgArrayBuffer<N, M>>>,
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
