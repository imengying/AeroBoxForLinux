use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{Read, Seek},
    process::{Command, Stdio},
    time::Duration,
};

pub fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("Start {command:?}"))?;
    ensure!(status.success(), "{command:?}: {status}");
    Ok(())
}

/// Files avoid waiting on a launched GUI that inherits a pipe after gio exits.
pub fn capture(
    command: &mut Command,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, String, String)> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .stdin(Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("{command:?}: timed out after {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    fn text(file: &mut File) -> Result<String> {
        file.rewind()?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    }
    Ok((status, text(&mut stdout)?, text(&mut stderr)?))
}

pub fn output(command: &mut Command) -> Result<String> {
    let (status, stdout, stderr) = capture(command, Duration::from_secs(15))?;
    ensure!(status.success(), "{command:?}: {status}\n{stderr}");
    Ok(stdout)
}
