//! Log lines on standard error, where systemd and Docker collect them.
//!
//! Messages are written by our own code with values we chose to include. Secrets can't be among
//! them by accident: `Secret` has no `Display`.

use std::fmt;
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Error,
    Warn,
    Info,
}

impl Level {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.name() == name)
    }

    const ALL: [Self; 3] = [Self::Error, Self::Warn, Self::Info];

    const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
        }
    }
}

static MAX_RANK: AtomicU8 = AtomicU8::new(Level::Info.rank());

pub(crate) fn set_level(level: Level) {
    MAX_RANK.store(level.rank(), Ordering::Relaxed);
}

pub(crate) fn write(level: Level, message: fmt::Arguments<'_>) {
    if level.rank() > MAX_RANK.load(Ordering::Relaxed) {
        return;
    }
    let line = format!(
        "{} {:<5} {message}\n",
        crate::time::format_utc(crate::time::now()),
        level.name()
    );
    // If standard error is gone there is nowhere left to report that.
    drop(std::io::stderr().write_all(line.as_bytes()));
}

macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*)) };
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, format_args!($($arg)*)) };
}

pub(crate) use {error, info, warning};
