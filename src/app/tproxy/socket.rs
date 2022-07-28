use std::{
    io::{self, ErrorKind, IoSliceMut},
    mem,
    net::SocketAddr,
    os::unix::prelude::AsRawFd,
    ptr,
};

use libc::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, IP_RECVORIGDSTADDR};
use nix::errno::Errno;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::app::types::{ClientAddr, RemoteAddr};

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

    pub(crate) async fn recv_msg(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, ClientAddr, RemoteAddr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recv_msg(inner, buf)) {
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

fn recv_msg<T: AsRawFd>(fd: &T, buf: &mut [u8]) -> io::Result<(usize, ClientAddr, RemoteAddr)> {
    let iov = [IoSliceMut::new(buf)];
    let mut ctrl_buf = [0u8; 128];

    let mut src_sockaddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut msghdr = libc::msghdr {
        msg_name: &mut src_sockaddr as *mut _ as *mut _,
        msg_namelen: mem::size_of_val(&src_sockaddr) as libc::socklen_t,
        msg_iov: iov.as_ref().as_ptr() as *mut libc::iovec,
        msg_iovlen: iov.as_ref().len() as libc::size_t,
        msg_control: ctrl_buf.as_mut_ptr() as *mut _,
        msg_controllen: ctrl_buf.len() as libc::size_t,
        msg_flags: 0,
    };

    let ret = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msghdr, 0) };
    let len = Errno::result(ret)? as usize;

    let src_addr = unsafe { SockAddr::new(src_sockaddr, msghdr.msg_namelen) };
    let dst_addr = parse_dest_addr_from_cmsg(&msghdr)?;
    match (src_addr.as_socket(), dst_addr.as_socket()) {
        (Some(src), Some(dst)) => Ok((len, src.into(), dst.into())),
        _ => Err(io::Error::new(
            ErrorKind::NotFound,
            "missing ip/ip6 address",
        )),
    }
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
