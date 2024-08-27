//! Common WAN error type

use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub struct WanError {
    kind: WanErrorKind,
    context: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum WanErrorKind {
    #[error("{0}")]
    Other(Box<dyn Error>),
}

impl<E> From<E> for WanError
where
    E: Error + 'static,
{
    fn from(value: E) -> Self {
        Self {
            kind: WanErrorKind::Other(Box::new(value)),
            context: None,
        }
    }
}

impl Display for WanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.context.as_ref() {
            Some(context) => write!(f, "{context} (caused by: {})", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

impl WanError {
    /// Creates a new WAN error wrapping a different error
    ///
    /// ### Arguments
    /// * `error` - Error to wrap
    pub fn other<E: Error + 'static>(error: E) -> Self {
        Self {
            kind: WanErrorKind::Other(Box::new(error)),
            context: None,
        }
    }

    /// Creates a new error message from a string
    ///
    /// ### Arguments
    /// * `msg` - Error message to convert into string
    pub fn with_message<S: Into<String>>(msg: S) -> Self {
        Self {
            kind: WanErrorKind::Other(msg.into().into()),
            context: None,
        }
    }
}
