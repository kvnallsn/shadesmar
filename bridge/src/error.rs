//! bridge error type

use std::{error::Error as StdError, fmt::Display, sync::Arc};

#[derive(Debug)]
pub struct Error {
    error: Arc<dyn StdError + Send + Sync>,
}

impl<E> From<E> for Error
where
    E: StdError + Send + Sync + 'static,
{
    fn from(value: E) -> Self {
        Self {
            error: Arc::new(value),
        }
    }
}

impl Error {
    pub fn new<S: Into<String>>(msg: S) -> Self {
        let msg: String = msg.into();
        let error: Box<dyn StdError + Send + Sync> = msg.into();
        let error = Arc::from(error);
        Self { error }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl From<Error> for anyhow::Error {
    fn from(error: Error) -> Self {
        anyhow::Error::new(error.error)
    }
}
