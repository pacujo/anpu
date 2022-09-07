#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use std::io::{Result, Error, ErrorKind, Read, Write};
use std::sync::Arc;
use std::cell::RefCell;
use std::rc::{Rc, Weak};

use aten::{Disk, Downgradable, Link, UID, Action, DECLARE_LINKS, IMPL_STREAM};
use aten::error;
use aten::stream::{ByteStream, ByteStreamBody, DebuggableByteStreamBody};
use aten::stream::{ByteStreamPair, ByteStreamPairBody};
use aten::stream::{DebuggableByteStreamPairBody, base, dry, queue};
use r3::{TRACE, Traceable};

pub struct TlsClientConfig(Arc<rustls::ClientConfig>);

impl TlsClientConfig {
    pub fn clone(&self) -> TlsClientConfig {
        TlsClientConfig(Arc::clone(&self.0))
    }
} // impl TlsClientConfig

struct TlsConnectionBody {
    base: base::StreamBody,
    weak_self: Weak<RefCell<TlsConnectionBody>>,
    conn: rustls::Connection,
    notify: Action,
    plain_callback: Action,
    plain_egress: ByteStream,
    encrypted_ingress: ByteStream,
    encrypted_egress: Option<queue::Stream>,
}

impl TlsConnectionBody {
    fn tie_knot(&mut self, disk: &Disk, pair: &ByteStreamPair) {
        let egress = queue::Stream::new(
            disk, Some(self.weak_self.upgrade().unwrap()));
        pair.set_egress(egress.as_bytestream());
        self.encrypted_egress = Some(egress);
        let uid = self.base.get_uid();
        let weak_self = self.weak_self.clone();
        self.notify = Action::new(move || {
            match weak_self.upgrade() {
                Some(body) => {
                    body.borrow().base.invoke_callback();
                }
                None => {
                    TRACE!(ANPU_TLSCONN_PROBE_UPPED_MISS { CONN: uid });
                }
            }
        });
        self.encrypted_ingress.register_callback(self.notify.clone());
    }

    fn read_nontrivial(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if self.conn.wants_read() {
                match self.conn.read_tls(&mut self.encrypted_ingress) {
                    Ok(_) => {
                        self.conn.process_new_packets().unwrap();
                        let result = self.conn.reader().read(buf);
                        match result {
                            Err(err) if error::is_again(&err) => {
                                TRACE!(ANPU_TLSCONN_READTLS_MORE { CONN: self });
                                continue;
                            }
                            _ => {
                                return result;
                            }
                        }
                    }
                    Err(err) => {
                        TRACE!(ANPU_TLSCONN_READTLS_FAIL {
                            CONN: self, ERR: r3::errsym(&err)
                        });
                        if !error::is_again(&err) {
                            return Err(err);
                        }
                    }
                }
            } else {
                TRACE!(ANPU_TLSCONN_NO_READTLS { CONN: self });
            }
            if self.conn.wants_write() {
                match self.conn.write_tls(
                    self.encrypted_egress.as_mut().unwrap()) {
                    Ok(0) => {
                        TRACE!(ANPU_TLSCONN_WRITETLS_NONE { CONN: self });
                    }
                    Ok(count) => {
                        TRACE!(ANPU_TLSCONN_WRITETLS {
                            CONN: self, COUNT: count
                        });
                        continue;
                    }
                    Err(err) => {
                        TRACE!(ANPU_TLSCONN_WRITETLS_FAIL {
                            CONN: self, ERR: r3::errsym(&err)
                        });
                        if !error::is_again(&err) {
                            return Err(err);
                        }
                    }
                }
            } else {
                TRACE!(ANPU_TLSCONN_NO_WRITETLS { CONN: self });
            }
            return self.resupply();
        }
    }

    fn resupply(&mut self) -> Result<usize> {
        let mut buffer = [0u8; 10000];
        match self.plain_egress.read(&mut buffer) {
            Ok(count) => {
                TRACE!(ANPU_TLSCONN_RESUPPLY { CONN: self, COUNT: count });
                if count > 0 {
                    self.conn.writer().write(&buffer[..count]).unwrap();
                }
            }
            Err(err) => {
                TRACE!(ANPU_TLSCONN_RESUPPLY_FAIL {
                    CONN: self, ERR: r3::errsym(&err)
                });
            }
        }
        Err(error::again())
    }
}

impl ByteStreamPairBody for TlsConnectionBody {
    fn get_ingress(&self) -> Option<ByteStream> {
        self.weak_self.upgrade().map(|s| ByteStream::new(self.base.get_uid(), s))
    }

    fn set_egress(&mut self, egress: ByteStream) {
        TRACE!(ANPU_TLSCONN_SET_EGRESS { CONN: self, EGRESS: egress });
        egress.register_callback(self.notify.clone());
        self.plain_egress = egress;
    }
} // impl ByteStreamPairBody for TlsConnectionBody

impl queue::Supplier for TlsConnectionBody {}

impl std::fmt::Debug for TlsConnectionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TlsConnectionBody")
            .field("uid", &self.base.get_uid())
            .finish()
    }
} // impl std::fmt::Debug for TlsConnectionBody

impl Drop for TlsConnectionBody {
    fn drop(&mut self) {
        TRACE!(ANPU_TLSCONN_DROP { CONN: self });
    }
} // impl Drop for EventBody

impl DebuggableByteStreamPairBody for TlsConnectionBody {}

impl ByteStreamBody for TlsConnectionBody {
    fn register_callback(&mut self, callback: Action) {
        TRACE!(ANPU_TLSCONN_REGISTER_CALLBACK {
            STREAM: self, ACTION: &callback
        });
        self.base.register_callback(callback);
    }

    fn unregister_callback(&mut self) {
        TRACE!(ANPU_TLSCONN_UNREGISTER_CALLBACK { STREAM: self });
        self.base.unregister_callback();
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Ok(_) = self.base.read(buf) {
            TRACE!(ANPU_TLSCONN_READ_TRIVIAL { STREAM: self, WANT: buf.len() });
            return Ok(0);
        }
        match self.read_nontrivial(buf) {
            Ok(count) => {
                TRACE!(ANPU_TLSCONN_READ {
                    STREAM: self, WANT: buf.len(), GOT: count
                });
                TRACE!(ANPU_TLSCONN_READ_DUMP {
                    STREAM: self, DATA: r3::octets(&buf[..count])
                });
                Ok(count)
            }
            Err(err) => {
                TRACE!(ANPU_TLSCONN_READ_FAIL {
                    STREAM: self, WANT: buf.len(), ERR: r3::errsym(&err)
                });
                Err(err)
            }
        }
    }
}

impl std::fmt::Display for TlsConnectionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.base)
    }
}

impl DebuggableByteStreamBody for TlsConnectionBody {}

impl TlsConnection {
    IMPL_STREAM!();

    pub fn new_client_config() -> TlsClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject, ta.spki, ta.name_constraints,
                )
            })
        );
        TlsClientConfig(Arc::new(
            rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()))
    }

    pub fn new_client(disk: &Disk, pair: &ByteStreamPair,
                      config: TlsClientConfig, server_name: String)
                      -> Result<TlsConnection> {
        match rustls::ClientConnection::new(
            config.0, server_name.as_str().try_into().unwrap()) {
            Ok(conn) => {
                let uid = UID::new();
                let body = Rc::new_cyclic(
                    |weak_self| RefCell::new(
                        TlsConnectionBody {
                            base: base::StreamBody::new(disk.downgrade(), uid),
                            weak_self: weak_self.clone(),
                            conn: rustls::Connection::Client(conn),
                            notify: Action::noop(),
                            plain_callback: Action::noop(),
                            plain_egress: dry::Stream::new(disk).as_bytestream(),
                            encrypted_ingress: pair.get_ingress().unwrap(),
                            encrypted_egress: None,
                        }
                    ));
                body.borrow_mut().tie_knot(disk, pair);
                TRACE!(ANPU_TLSCONN_CREATE { DISK: disk, CONN: uid });
                Ok(TlsConnection(Link {
                    uid: uid,
                    body: body,
                }))
            }
            Err(err) => {
                Err(Error::new(ErrorKind::Other, err))
            }
        }
    }

    pub fn get_ingress(&self) -> Option<ByteStream> {
        self.0.body.borrow().get_ingress()
    }

    pub fn set_egress(&self, egress: ByteStream) {
        self.0.body.borrow_mut().set_egress(egress);
    }

    pub fn as_bytestream_pair(&self) -> ByteStreamPair {
        ByteStreamPair::new(self.0.uid, self.0.body.clone())
    }
}

DECLARE_LINKS!(TlsConnection, WeakTlsConnection, TlsConnectionBody,
               ANPU_TLSCONN_UPPED_MISS, CONN);
