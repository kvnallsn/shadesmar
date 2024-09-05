use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};
use shadesmar_core::{
    plugins::{WanCallback, WanPluginConfig},
    types::buffers::{PacketBuffer, PacketBufferPool},
};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
pub struct BlackholeConfig {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    ty: String,
}

pub struct BlackholeDevice {
    id: Uuid,
}

pub struct BlackholeInstance {
    channel: flume::Receiver<BlackholeMessage>,
}

pub struct BlackholeHandle {
    id: Uuid,
    channel: flume::Sender<BlackholeMessage>,
    thread: JoinHandle<()>,
}

pub enum BlackholeMessage {
    Quit,
    Data(PacketBuffer),
}

shadesmar_core::define_wan_plugin!(
    "blackhole",
    BlackholeConfig,
    BlackholeDevice,
    BlackholeHandle
);

impl BlackholeDevice {
    pub fn new(cfg: WanPluginConfig<BlackholeConfig>) -> anyhow::Result<Self> {
        Ok(BlackholeDevice { id: cfg.id })
    }

    pub fn run(&self, _cb: WanCallback) -> anyhow::Result<BlackholeHandle> {
        let (tx, rx) = flume::unbounded();
        let instance = BlackholeInstance::new(rx)?;

        let thread = std::thread::Builder::new()
            .name(String::from("wan-blackhole"))
            .spawn(move || match instance.run() {
                Ok(_) => (),
                Err(_error) => (),
            })?;

        Ok(BlackholeHandle {
            id: self.id,
            channel: tx,
            thread,
        })
    }
}

impl BlackholeInstance {
    pub fn new(rx: flume::Receiver<BlackholeMessage>) -> anyhow::Result<Self> {
        Ok(Self { channel: rx })
    }

    pub fn run(self) -> anyhow::Result<()> {
        while let Ok(msg) = self.channel.recv() {
            match msg {
                BlackholeMessage::Quit => break,
                BlackholeMessage::Data(data) => {
                    tracing::debug!("[blackhole] dropping {} byte packet", data.len());
                }
            }
        }

        Ok(())
    }
}

impl BlackholeHandle {
    pub fn write(&self, data: &[u8]) {
        let _span = tracing::info_span!("blackhole handle write", wan_id = %self.id).entered();

        let mut buffer = PacketBufferPool::get();
        buffer.extend_from_slice(data);
        self.channel.send(BlackholeMessage::Data(buffer)).ok();
    }

    pub fn stop(self) -> anyhow::Result<()> {
        let _span = tracing::info_span!("blackhole handle stop", wan_id = %self.id).entered();

        self.channel.send(BlackholeMessage::Quit).ok();
        self.thread.join().ok();
        Ok(())
    }
}
