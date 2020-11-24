extern crate syslog;
#[macro_use]
extern crate log;
extern crate popol;
use std::collections::VecDeque;
use std::io;
use std::io::{Read, Write};
use std::time::Duration;

use log::{LevelFilter, SetLoggerError};
use popol::Sources;
use syslog::{BasicLogger, Facility, Formatter3164};

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

fn deq_put_cstring(odeq: &mut VecDeque<u8>, str: &str) {
    let b = str.as_bytes();
    deq_put_u32(odeq, b.len() as u32);
    for i in 0..b.len() {
        deq_put_u8(odeq, b[i]);
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

/* server to client */
const SSH2_FXP_VERSION: u8 = 2;

const SSH2_FXP_STATUS: u8 = 101;

const SSH2_FXP_EXTENDED: u8 = 200;
const SSH2_FXP_EXTENDED_REPLY: u8 = 201;

const SSH2_FX_PERMISSION_DENIED: u32 = 3;

struct SftpSession {
    ideq: VecDeque<u8>,
    odeq: VecDeque<u8>,
    init_done: bool,
    odeq_registered: bool,
    sources: Sources<String>,
    client_version: u32,
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

    fn process(&mut self) {
        info!("process ideq: {:?}", &self.ideq);
        let buf_len = self.ideq.len();
        if buf_len < 5 {
            /* incomplete message */
            info!("incomplete message 0");
            return;
        }
        let msg_len = deq_get_u32(&mut self.ideq).unwrap() as usize;
        info!("process ideq after get32: {:?}", &self.ideq);
        if msg_len > SFTP_MAX_MSG_LENGTH {
            panic!("SSH message length {} > {}", msg_len, SFTP_MAX_MSG_LENGTH);
        }

        if buf_len < msg_len + 4 {
            info!("incomplete message");
            /* incomplete message */
            return;
        }

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
                self.send_status(id, SSH2_FX_PERMISSION_DENIED);
            }
        }

        if buf_len < self.ideq.len() {
            panic!("Unexpected growth of the input buffer");
        }
        let consumed = buf_len - self.ideq.len();
        if msg_len < consumed {
            panic!("msg_len {} < consumed {}", msg_len, consumed);
        }
        if msg_len > consumed {
            deq_consume(&mut self.ideq, msg_len - consumed);
        }
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
                .wait_timeout(&mut events, Duration::from_secs(1))
            {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    eprintln!("time out...");
                    info!("ideq: {:?}", &self.ideq);
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
                eprintln!("key: {:?} Ev: {:?}", &key, &event);
                info!(
                    "Ideq free capacity: {}",
                    self.ideq.capacity() - self.ideq.len()
                );
                // The standard input has data ready to be read.
                if event.readable || event.hangup {
                    let mut buf = [0u8; 16384];

                    // Read what we can from standard input
                    match io::stdin().read(&mut buf[..]) {
                        Ok(n) => {
                            self.ideq.reserve(n);
                            for c in &buf[..n] {
                                self.ideq.push_back(*c);
                            }

                            /* echo */
                            // io::stdout().write_all(&buf[..n]).unwrap();
                        }
                        Err(err) => panic!(err),
                    }
                    if event.hangup {
                        std::process::exit(42);
                    }
                }
                if event.writable {
                    self.odeq.make_contiguous();
                    // let maxlen = self.odeq.len();
                    info!("Writing odeq: {:?}", &self.odeq);
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
