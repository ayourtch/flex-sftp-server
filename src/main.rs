extern crate syslog;
#[macro_use]
extern crate log;

use log::{LevelFilter, SetLoggerError};
use syslog::{BasicLogger, Facility, Formatter3164};

fn test() {
    info!("This is a test");
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
    test();
}
