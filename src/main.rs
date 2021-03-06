extern crate syslog;
#[macro_use]
extern crate log;
extern crate popol;
use std::collections::VecDeque;
use std::fs::{File, ReadDir};
use std::io;
use std::io::{Read, Write};
use std::time::Duration;

use log::{LevelFilter, SetLoggerError};
use popol::Sources;
use std::collections::HashMap;
use syslog::{BasicLogger, Facility, Formatter3164};

fn deq_get_u64(ideq: &mut VecDeque<u8>) -> Option<u64> {
    let mut out: u64 = 0;
    for _i in 0..8 {
        out = out << 8;
        let nxt = ideq.pop_front();
        if nxt.is_none() {
            return None;
        }
        out = out + (nxt.unwrap() as u64);
    }
    Some(out)
}

fn deq_get_u32(ideq: &mut VecDeque<u8>) -> Option<u32> {
    let mut out: u32 = 0;
    for _i in 0..4 {
        out = out << 8;
        let nxt = ideq.pop_front();
        if nxt.is_none() {
            return None;
        }
        out = out + (nxt.unwrap() as u32);
    }
    Some(out)
}

fn deq_peek_u32(ideq: &mut VecDeque<u8>) -> Option<u32> {
    let mut out: u32 = 0;
    for i in 0..4 {
        out = out << 8;
        let nxt = ideq.get(i);
        if nxt.is_none() {
            return None;
        }
        out = out + (*nxt.unwrap() as u32);
    }
    Some(out)
}

fn deq_get_u16(ideq: &mut VecDeque<u8>) -> Option<u16> {
    let mut out: u16 = 0;
    for _i in 0..2 {
        out = out << 8;
        let nxt = ideq.pop_front();
        if nxt.is_none() {
            return None;
        }
        out = out + (nxt.unwrap() as u16);
    }
    Some(out)
}

fn deq_get_u8(ideq: &mut VecDeque<u8>) -> Option<u8> {
    ideq.pop_front()
}

fn deq_get_cstring(ideq: &mut VecDeque<u8>) -> Option<String> {
    let str_len = deq_get_u32(ideq)? as usize;
    let mut out = String::with_capacity(str_len);
    for _i in 0..str_len {
        out.push(ideq.pop_front()? as char);
    }
    Some(out)
}

fn deq_get_string(ideq: &mut VecDeque<u8>) -> Option<Vec<u8>> {
    let str_len = deq_get_u32(ideq)? as usize;
    let mut out = Vec::<u8>::with_capacity(str_len);
    for _i in 0..str_len {
        out.push(ideq.pop_front()?);
    }
    Some(out)
}

fn deq_get_handle(ideq: &mut VecDeque<u8>) -> Option<u32> {
    let str_len = deq_get_u32(ideq)? as usize;
    if str_len != 4 {
        return None;
    };
    deq_get_u32(ideq)
}

fn deq_put_u8(odeq: &mut VecDeque<u8>, val: u8) {
    odeq.push_back(val);
}

fn deq_put_u32(odeq: &mut VecDeque<u8>, val: u32) {
    let mut val = val;
    for _i in 0..4 {
        odeq.push_back((val >> 24) as u8);
        val = (val & 0xffffff) << 8;
    }
}

fn deq_put_u64(odeq: &mut VecDeque<u8>, val: u64) {
    let mut val = val;
    for _i in 0..8 {
        odeq.push_back((val >> (24 + 32)) as u8);
        val = (val & 0xffffffffffffff) << 8;
    }
}

fn deq_put_cstring(odeq: &mut VecDeque<u8>, str: &str) {
    let b = str.as_bytes();
    deq_put_u32(odeq, b.len() as u32);
    for i in 0..b.len() {
        deq_put_u8(odeq, b[i]);
    }
}

/* attributes */
const SSH2_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
const SSH2_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
const SSH2_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
const SSH2_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
const SSH2_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

/* portable open modes */
const SSH2_FXF_READ: u32 = 0x00000001;
const SSH2_FXF_WRITE: u32 = 0x00000002;
const SSH2_FXF_APPEND: u32 = 0x00000004;
const SSH2_FXF_CREAT: u32 = 0x00000008;
const SSH2_FXF_TRUNC: u32 = 0x00000010;
const SSH2_FXF_EXCL: u32 = 0x00000020;

fn decode_attrib(ideq: &mut VecDeque<u8>) -> Option<Attrib> {
    let mut a = Attrib {
        ..Default::default()
    };
    a.flags = deq_get_u32(ideq)?;
    if a.flags & SSH2_FILEXFER_ATTR_SIZE != 0 {
        a.size = deq_get_u64(ideq)?;
    }
    if a.flags & SSH2_FILEXFER_ATTR_UIDGID != 0 {
        a.uid = deq_get_u32(ideq)?;
        a.gid = deq_get_u32(ideq)?;
    }
    if a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS != 0 {
        a.perm = deq_get_u32(ideq)?;
    }
    if a.flags & SSH2_FILEXFER_ATTR_ACMODTIME != 0 {
        a.atime = deq_get_u32(ideq)?;
        a.mtime = deq_get_u32(ideq)?;
    }

    if a.flags & SSH2_FILEXFER_ATTR_EXTENDED != 0 {
        let count = deq_get_u32(ideq)?;
        for i in 0..count {
            let atype = deq_get_cstring(ideq)?;
            let adata = deq_get_string(ideq)?;
        }
    }
    Some(a)
}

fn encode_attrib(odeq: &mut VecDeque<u8>, a: &Attrib) {
    deq_put_u32(odeq, a.flags);
    if a.flags & SSH2_FILEXFER_ATTR_SIZE != 0 {
        deq_put_u64(odeq, a.size);
    }
    if a.flags & SSH2_FILEXFER_ATTR_UIDGID != 0 {
        deq_put_u32(odeq, a.uid);
        deq_put_u32(odeq, a.gid);
    }
    if a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS != 0 {
        deq_put_u32(odeq, a.perm);
    }
    if a.flags & SSH2_FILEXFER_ATTR_ACMODTIME != 0 {
        deq_put_u32(odeq, a.atime);
        deq_put_u32(odeq, a.mtime);
    }
}

fn deq_put_deq(odeq: &mut VecDeque<u8>, ideq: &mut VecDeque<u8>) {
    let len = ideq.len() as u32;
    deq_put_u32(odeq, len);
    while ideq.len() > 0 {
        odeq.push_back(ideq.pop_front().unwrap());
    }
}

fn deq_consume(ideq: &mut VecDeque<u8>, count: usize) {
    for _i in 0..count {
        ideq.pop_front().unwrap();
    }
}

const SFTP_MAX_MSG_LENGTH: usize = 256 * 1024;

const SSH2_FILEXFER_VERSION: u32 = 3;

/* client to server */
const SSH2_FXP_INIT: u8 = 1;
const SSH2_FXP_OPEN: u8 = 3;
const SSH2_FXP_CLOSE: u8 = 4;
const SSH2_FXP_READ: u8 = 5;
const SSH2_FXP_WRITE: u8 = 6;
const SSH2_FXP_LSTAT: u8 = 7;
const SSH2_FXP_STAT_VERSION_0: u8 = 7;
const SSH2_FXP_FSTAT: u8 = 8;
const SSH2_FXP_SETSTAT: u8 = 9;
const SSH2_FXP_FSETSTAT: u8 = 10;
const SSH2_FXP_OPENDIR: u8 = 11;
const SSH2_FXP_READDIR: u8 = 12;
const SSH2_FXP_REMOVE: u8 = 13;
const SSH2_FXP_MKDIR: u8 = 14;
const SSH2_FXP_RMDIR: u8 = 15;
const SSH2_FXP_REALPATH: u8 = 16;
const SSH2_FXP_STAT: u8 = 17;
const SSH2_FXP_RENAME: u8 = 18;
const SSH2_FXP_READLINK: u8 = 19;
const SSH2_FXP_SYMLINK: u8 = 20;

/* server to client */
const SSH2_FXP_VERSION: u8 = 2;
const SSH2_FXP_STATUS: u8 = 101;
const SSH2_FXP_HANDLE: u8 = 102;
const SSH2_FXP_DATA: u8 = 103;
const SSH2_FXP_NAME: u8 = 104;
const SSH2_FXP_ATTRS: u8 = 105;

const SSH2_FXP_EXTENDED: u8 = 200;
const SSH2_FXP_EXTENDED_REPLY: u8 = 201;

/* status messages */
const SSH2_FX_OK: u32 = 0;
const SSH2_FX_EOF: u32 = 1;
const SSH2_FX_NO_SUCH_FILE: u32 = 2;
const SSH2_FX_PERMISSION_DENIED: u32 = 3;
const SSH2_FX_FAILURE: u32 = 4;
const SSH2_FX_BAD_MESSAGE: u32 = 5;
const SSH2_FX_NO_CONNECTION: u32 = 6;
const SSH2_FX_CONNECTION_LOST: u32 = 7;
const SSH2_FX_OP_UNSUPPORTED: u32 = 8;
const SSH2_FX_MAX: u32 = 8;

enum HandleObj {
    File(File),
    ReadDir(ReadDir),
    None,
}

struct ScpHandle {
    obj: HandleObj,
    pflags: u32,
    path: String,
}

#[derive(Default, Debug)]
struct Attrib {
    flags: u32,
    size: u64,
    uid: u32,
    gid: u32,
    perm: u32,
    atime: u32,
    mtime: u32,
}

#[derive(Default, Debug)]
struct Stat {
    name: String,
    long_name: String,
    attrib: Attrib,
}

struct SftpSession {
    ideq: VecDeque<u8>,
    odeq: VecDeque<u8>,
    init_done: bool,
    odeq_registered: bool,
    sources: Sources<String>,
    is_readonly: bool,
    client_version: u32,
    next_handle_id: u32,
    handles: HashMap<u32, ScpHandle>,
}

impl SftpSession {
    fn new() -> Self {
        info!("This is a test");
        let env_conn = std::env::var("SSH_CONNECTION");
        if let Ok(ref conn) = env_conn {
            info!("Connection from {}", &conn);
        }
        // Create a registry to hold I/O sources.
        let mut sources: Sources<String> = popol::Sources::with_capacity(2);

        // Register the program's standard input as a source of "read" readiness events.
        // The first parameter is the key we want to associate with the source. Since
        // we only have one source in this example, we just pass in the unit type.
        sources.register("stdin".to_string(), &io::stdin(), popol::interest::READ);

        SftpSession {
            ideq: VecDeque::new(),
            odeq: VecDeque::new(),
            init_done: false,
            odeq_registered: false,
            sources,
            client_version: 0,
            is_readonly: false,
            next_handle_id: 1,
            handles: HashMap::new(),
        }
    }

    fn process_init(&mut self) {
        let mut tdeq = VecDeque::<u8>::new();
        self.client_version = deq_get_u32(&mut self.ideq).expect("version parse");
        info!("Received client version: {}", self.client_version);
        deq_put_u8(&mut tdeq, SSH2_FXP_VERSION);
        deq_put_u32(&mut tdeq, SSH2_FILEXFER_VERSION);

        deq_put_cstring(&mut tdeq, "posix-rename@openssh.com");
        deq_put_cstring(&mut tdeq, "1");

        deq_put_cstring(&mut tdeq, "statvfs@openssh.com");
        deq_put_cstring(&mut tdeq, "2");

        deq_put_cstring(&mut tdeq, "fstatvfs@openssh.com");
        deq_put_cstring(&mut tdeq, "2");

        deq_put_cstring(&mut tdeq, "hardlink@openssh.com");
        deq_put_cstring(&mut tdeq, "1");

        deq_put_cstring(&mut tdeq, "fsync@openssh.com");
        deq_put_cstring(&mut tdeq, "1");

        deq_put_cstring(&mut tdeq, "lsetstat@openssh.com");
        deq_put_cstring(&mut tdeq, "1");

        deq_put_deq(&mut self.odeq, &mut tdeq);
    }

    fn process_extended(&mut self, extended_id: u32) {}

    fn status_to_message(&mut self, status: u32) -> &'static str {
        return "some status";
    }

    fn send_status(&mut self, id: u32, status: u32) {
        let mut tdeq = VecDeque::<u8>::new();
        deq_put_u8(&mut tdeq, SSH2_FXP_STATUS);
        deq_put_u32(&mut tdeq, id);
        deq_put_u32(&mut tdeq, status);
        if self.client_version >= 3 {
            deq_put_cstring(&mut tdeq, self.status_to_message(status));
            deq_put_cstring(&mut tdeq, "");
        }
        deq_put_deq(&mut self.odeq, &mut tdeq);
    }

    fn send_names(&mut self, id: u32, names: &Vec<Stat>) {
        let mut tdeq = VecDeque::<u8>::new();
        deq_put_u8(&mut tdeq, SSH2_FXP_NAME);
        deq_put_u32(&mut tdeq, id);
        deq_put_u32(&mut tdeq, names.len() as u32);

        for name in names {
            deq_put_cstring(&mut tdeq, &name.name);
            deq_put_cstring(&mut tdeq, &name.long_name);
            encode_attrib(&mut tdeq, &name.attrib);
        }

        deq_put_deq(&mut self.odeq, &mut tdeq);
    }

    fn send_attrib(&mut self, id: u32, a: &Attrib) {
        let mut tdeq = VecDeque::<u8>::new();
        deq_put_u8(&mut tdeq, SSH2_FXP_ATTRS);
        deq_put_u32(&mut tdeq, id);
        encode_attrib(&mut tdeq, a);

        deq_put_deq(&mut self.odeq, &mut tdeq);
    }

    fn send_handle(&mut self, id: u32, h: u32) {
        let mut tdeq = VecDeque::<u8>::new();
        deq_put_u8(&mut tdeq, SSH2_FXP_HANDLE);
        deq_put_u32(&mut tdeq, id);
        deq_put_u32(&mut tdeq, 4);
        deq_put_u32(&mut tdeq, h);

        deq_put_deq(&mut self.odeq, &mut tdeq);
    }

    fn process_stat(&mut self, id: u32) {
        let mut path = deq_get_cstring(&mut self.ideq).expect("parse cstring");
        info!("process_stat {}", &path);
        match std::fs::metadata(&path) {
            Ok(meta) => {
                use std::time::SystemTime;
                let mut a = Attrib {
                    ..Default::default()
                };
                /* FIXME - fill attrib */
                a.flags = SSH2_FILEXFER_ATTR_SIZE
                    | SSH2_FILEXFER_ATTR_UIDGID
                    | SSH2_FILEXFER_ATTR_PERMISSIONS
                    | SSH2_FILEXFER_ATTR_ACMODTIME;
                a.size = meta.len();
                a.uid = 0; // FIXME
                a.gid = 0; // FIXME
                if meta.is_file() {
                    a.perm = 0x8000;
                } else if meta.is_dir() {
                    a.perm = 0x4000;
                }
                a.mtime = meta
                    .modified()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32;
                a.atime = meta
                    .accessed()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32;
                self.send_attrib(id, &a);
            }
            Err(err) => {
                self.send_status(id, SSH2_FX_FAILURE);
            }
        }
    }
    fn process_lstat(&mut self, id: u32) {
        // FIXME: put the actual lstat
        self.process_stat(id);
    }

    fn process_close(&mut self, id: u32) {
        let handle = deq_get_handle(&mut self.ideq).expect("handle");
        info!("process_close handle {}", &handle);

        let mut status = SSH2_FX_OK;

        match self.handles.get_mut(&handle) {
            None => {
                info!("Handle {} not found", handle);
                self.send_status(id, SSH2_FX_FAILURE);
            }
            Some(h) => match h.obj {
                HandleObj::File(ref mut f) => {
                    if let Err(err) = f.sync_all() {
                        info!("Error closing handle: {:?}", &err);
                        status = SSH2_FX_FAILURE;
                    }
                }
                HandleObj::ReadDir(ref mut rd) => {
                    info!("Closing directory {:?}", rd);
                }
                _ => {
                    info!("not a file handle");
                    status = SSH2_FX_FAILURE;
                }
            },
        }
        self.handles.remove(&handle);
        self.send_status(id, status);
    }

    fn process_write(&mut self, id: u32) {
        let handle = deq_get_handle(&mut self.ideq).expect("handle");
        let off = deq_get_u64(&mut self.ideq).expect("offset");
        let data = deq_get_string(&mut self.ideq).expect("data");

        info!(
            "process_write handle {} off {} data len {} bytes",
            &handle,
            &off,
            &data.len()
        );

        match self.handles.get_mut(&handle) {
            None => {
                info!("Handle {} not found", handle);
                self.send_status(id, SSH2_FX_FAILURE);
            }
            Some(h) => match h.obj {
                HandleObj::File(ref mut f) => {
                    if h.pflags & SSH2_FXF_APPEND != 0 {
                        use std::io::{Seek, SeekFrom};
                        match f.seek(SeekFrom::End(0)) {
                            Ok(pos) => {
                                info!("seek ok to pos {}", pos);
                                match f.write(&data[..]) {
                                    Ok(n) => {
                                        self.send_status(id, SSH2_FX_OK);
                                    }
                                    Err(err) => {
                                        info!("error writing: {:?}", err);
                                        self.send_status(id, SSH2_FX_FAILURE);
                                    }
                                }
                            }
                            Err(err) => {
                                info!("seek failed");
                                self.send_status(id, SSH2_FX_FAILURE);
                            }
                        }
                    } else {
                        match f.write(&data[..]) {
                            Ok(n) => {
                                self.send_status(id, SSH2_FX_OK);
                            }
                            Err(err) => {
                                info!("error writing: {:?}", err);
                                self.send_status(id, SSH2_FX_FAILURE);
                            }
                        }
                    }
                }
                _ => {
                    info!("Not a file object");
                    self.send_status(id, SSH2_FX_FAILURE);
                }
            },
        }
    }

    fn insert_new_handle(&mut self, handle: ScpHandle) -> u32 {
        let my_handle_id = self.next_handle_id;
        self.next_handle_id = self.next_handle_id + 1;
        self.handles.insert(my_handle_id, handle);
        info!("Handle: {}", my_handle_id);
        return my_handle_id;
    }

    fn dir_entry_to_stat(ent: std::fs::DirEntry) -> Option<Stat> {
        match ent.file_name().to_str() {
            Some(real_path) => {
                let name = real_path.to_string();
                Some(Stat {
                    name: name.clone(),
                    long_name: name.clone(), // FIXME: this needs to be long output
                    ..Default::default()
                })
            }
            None => None,
        }
    }

    fn process_readdir(&mut self, id: u32) {
        let handle = deq_get_handle(&mut self.ideq).expect("handle");
        info!("process_readdir handle {}", &handle);

        let mut status = SSH2_FX_OK;
        let mut names: Vec<Stat> = vec![];

        match self.handles.get_mut(&handle) {
            None => {
                info!("Handle {} not found", handle);
                self.send_status(id, SSH2_FX_FAILURE);
                return;
            }
            Some(h) => match h.obj {
                HandleObj::File(ref mut f) => {
                    info!("Attempting a readdir on file handle: {:?}", &f);
                    self.send_status(id, SSH2_FX_FAILURE);
                    return;
                }
                HandleObj::ReadDir(ref mut rd) => {
                    info!("Reading directory {:?}", rd);
                    while names.len() < 100 {
                        match rd.next() {
                            None => break,
                            Some(entry) => match entry {
                                Err(e) => info!("Error {:?} while readdir", e),
                                Ok(ent) => match Self::dir_entry_to_stat(ent) {
                                    Some(st) => {
                                        names.push(st);
                                    }
                                    None => {}
                                },
                            },
                        }
                    }
                }
                _ => {
                    info!("not a file handle");
                    self.send_status(id, SSH2_FX_FAILURE);
                    return;
                }
            },
        }

        if names.len() > 0 {
            self.send_names(id, &names);
        } else {
            self.send_status(id, SSH2_FX_EOF);
        }
    }

    fn process_opendir(&mut self, id: u32) {
        let mut path = deq_get_cstring(&mut self.ideq).expect("parse cstring");
        info!("Request {} opendir {}", id, &path);
        match std::fs::read_dir(&path) {
            Ok(rd) => {
                let handle = ScpHandle {
                    obj: HandleObj::ReadDir(rd),
                    path: path.clone(),
                    pflags: 0,
                };
                let my_handle_id = self.insert_new_handle(handle);
                self.send_handle(id, my_handle_id);
            }
            Err(err) => {
                info!("Error opening {} : {:?}", &path, &err);
                self.send_status(id, SSH2_FX_PERMISSION_DENIED);
            }
        }
    }

    fn process_open(&mut self, id: u32) {
        let mut path = deq_get_cstring(&mut self.ideq).expect("parse cstring");
        let pflags = deq_get_u32(&mut self.ideq).expect("parse flags");
        let a = decode_attrib(&mut self.ideq).expect("parse attrib");

        info!(
            "process_open '{}' flags 0x{:08x} attr: {:?}",
            &path, pflags, &a
        );
        // FIXME: add the actual open

        use std::fs::OpenOptions;

        let file_res = OpenOptions::new()
            .read(pflags & SSH2_FXF_READ != 0)
            .write(pflags & SSH2_FXF_WRITE != 0)
            .create(pflags & SSH2_FXF_CREAT != 0)
            .append(pflags & SSH2_FXF_APPEND != 0)
            .truncate(pflags & SSH2_FXF_TRUNC != 0)
            .open(&path);
        match file_res {
            Ok(file) => {
                let handle = ScpHandle {
                    obj: HandleObj::File(file),
                    path: path.clone(),
                    pflags: pflags,
                };
                let my_handle_id = self.insert_new_handle(handle);
                self.send_handle(id, my_handle_id);
            }
            Err(err) => {
                info!("Error opening {} : {:?}", &path, &err);
                self.send_status(id, SSH2_FX_PERMISSION_DENIED);
            }
        }
    }

    fn process_realpath(&mut self, id: u32) {
        let mut path = deq_get_cstring(&mut self.ideq).expect("parse cstring");
        info!("process_realpath {}", &path);

        if path == "" {
            path = ".".to_string();
        }

        match std::fs::canonicalize(&path) {
            Ok(real_path) => {
                let real_path = real_path.to_str().unwrap().to_string();
                let names = vec![Stat {
                    name: real_path.clone(),
                    long_name: real_path.clone(),
                    ..Default::default()
                }];
                self.send_names(id, &names);
            }
            Err(err) => {
                /* FIXME  - errno to portable */
                self.send_status(id, 42);
            }
        }
    }

    fn process(&mut self) {
        self.ideq.make_contiguous();
        info!("processing ideq len: {}", self.ideq.len());
        for i in 0..self.ideq.len() {
            info!("ideq[{}] = {}", i, self.ideq[i]);
        }
        let buf_len = self.ideq.len();
        if buf_len < 5 {
            /* incomplete message */
            return;
        }
        let msg_len = deq_peek_u32(&mut self.ideq).unwrap() as usize;
        if msg_len > SFTP_MAX_MSG_LENGTH {
            info!("SSH message length {} > {}", msg_len, SFTP_MAX_MSG_LENGTH);
            panic!("SSH message length {} > {}", msg_len, SFTP_MAX_MSG_LENGTH);
        }
        let buf_len = buf_len - 4;

        if buf_len < msg_len {
            info!("buf_len {} < {}, incomplete", buf_len, msg_len);
            /* incomplete message */
            return;
        }
        let msg_len = deq_get_u32(&mut self.ideq).unwrap() as usize;

        let msg_type = deq_get_u8(&mut self.ideq).unwrap();
        info!("Process message type: {}", &msg_type);

        match msg_type {
            SSH2_FXP_INIT => {
                self.process_init();
                self.init_done = true;
            }
            SSH2_FXP_EXTENDED => {
                if !self.init_done {
                    panic!("Received extended request before init");
                }
                let id = deq_get_u32(&mut self.ideq).expect("Could not parse extended ID");
                self.process_extended(id);
            }
            other_type => {
                if !self.init_done {
                    panic!("Received {} request before init", other_type);
                }
                let id = deq_get_u32(&mut self.ideq).expect("Could not parse ID");
                let does_write = match msg_type {
                    SSH2_FXP_OPEN | SSH2_FXP_CLOSE | SSH2_FXP_READ | SSH2_FXP_LSTAT
                    | SSH2_FXP_FSTAT | SSH2_FXP_OPENDIR | SSH2_FXP_READDIR | SSH2_FXP_REALPATH
                    | SSH2_FXP_STAT | SSH2_FXP_READLINK => false,
                    _ => true, /* be conservative */
                };
                if self.is_readonly && does_write {
                    self.send_status(id, SSH2_FX_PERMISSION_DENIED);
                } else {
                    match msg_type {
                        SSH2_FXP_REALPATH => self.process_realpath(id),
                        SSH2_FXP_STAT => self.process_stat(id),
                        SSH2_FXP_LSTAT => self.process_lstat(id),
                        SSH2_FXP_OPEN => self.process_open(id),
                        SSH2_FXP_OPENDIR => self.process_opendir(id),
                        SSH2_FXP_READDIR => self.process_readdir(id),
                        SSH2_FXP_WRITE => self.process_write(id),
                        SSH2_FXP_CLOSE => self.process_close(id),
                        _ => self.send_status(id, SSH2_FX_PERMISSION_DENIED),
                    }
                }
            }
        }

        if buf_len < self.ideq.len() {
            info!("unexpected growth of the input buffer");
            panic!("Unexpected growth of the input buffer");
        }
        let consumed = buf_len - self.ideq.len();
        if msg_len < consumed {
            info!("msg_len {} < consumed {}", msg_len, consumed);
            panic!("msg_len {} < consumed {}", msg_len, consumed);
        }
        if msg_len > consumed {
            info!("Consume: {}", msg_len - consumed);
            deq_consume(&mut self.ideq, msg_len - consumed);
        }
        info!("after process ideq: {:?}", &self.ideq.len());
    }

    fn odeq_set_events(&mut self) {
        if self.odeq.len() > 0 {
            if !self.odeq_registered {
                self.odeq_registered = true;
                self.sources
                    .register("stdout".to_string(), &io::stdout(), popol::interest::WRITE);
            }
        } else {
            if self.odeq_registered {
                self.odeq_registered = false;
                self.sources.unregister(&"stdout".to_string());
            }
        }
    }

    fn run_loop(&mut self) {
        // Create an events buffer to hold readiness events.
        let mut events = popol::Events::with_capacity(1);

        loop {
            self.odeq_set_events();
            // Wait on our event sources for at most 6 seconds. If an event source is
            // ready before then, process its events. Otherwise, timeout.
            match self
                .sources
                .wait_timeout(&mut events, Duration::from_secs(30))
            {
                Ok(()) => { /* nothing */ }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    eprintln!("time out...");
                    // info!("timeout. ideq len: {}", self.ideq.len());
                    // info!("---");
                    continue;
                }
                Err(err) => {
                    eprintln!("Error: {:?}", err);
                    std::process::exit(1);
                }
            }

            // Iterate over source events. Since we only have one source
            // registered, this will only iterate once.
            for (key, event) in events.iter() {
                // The standard input has data ready to be read.
                if event.readable || event.hangup {
                    let mut buf = [0u8; 16384];

                    // Read what we can from standard input
                    match io::stdin().read(&mut buf[..]) {
                        Ok(n) => {
                            // self.ideq.reserve(n);
                            let mut i = 0;
                            for c in &buf[..n] {
                                // info!("push #{} into ideq: {} ('{}')", i, *c, *c as char);
                                i = i + 1;
                                self.ideq.push_back(*c);
                            }

                            /* echo */
                            // io::stdout().write_all(&buf[..n]).unwrap();
                        }
                        Err(err) => panic!(err),
                    }
                    if event.hangup {
                        std::process::exit(0);
                    }
                }
                if event.writable {
                    self.odeq.make_contiguous();
                    // let maxlen = self.odeq.len();
                    // info!("Writing odeq: {:?}", &self.odeq);
                    match io::stdout().write(&self.odeq.as_slices().0) {
                        Ok(n) => {
                            /* this was written, get rid of it */
                            for _i in 0..n {
                                self.odeq.pop_front();
                            }
                            io::stdout().flush();
                        }
                        Err(err) => {
                            info!("Error writing odeq: {:?}", err);
                        }
                    }
                }
                self.process();
            }
        }
    }
}

fn ssh_server_main() {
    let mut sess = SftpSession::new();
    sess.run_loop();
}

fn main() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "flex-sftp-server".into(),
        pid: std::process::id() as i32,
    };

    let logger = syslog::unix(formatter).expect("could not connect to syslog");
    log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
        .map(|()| log::set_max_level(LevelFilter::Debug));

    info!("hello world");
    debug!("This is a debug");
    ssh_server_main();
}
