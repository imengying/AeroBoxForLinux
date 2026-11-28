use crate::{peer::digest, process};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

static PAYLOAD: [u8; 65536] = [0x5a; 65536];

fn transfer(stream: &mut (impl Read + Write), mut count: u64, send: bool) -> Result<()> {
    let mut buffer = [0; PAYLOAD.len()];
    while count > 0 {
        let size = count.min(PAYLOAD.len() as u64) as usize;
        if send {
            stream.write_all(&PAYLOAD[..size])?;
        } else {
            stream.read_exact(&mut buffer[..size])?;
            ensure!(buffer[..size] == PAYLOAD[..size], "Payload corruption");
        }
        count -= size as u64;
    }
    Ok(())
}

fn socket(stream: &TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    stream.set_nodelay(true)?;
    Ok(())
}

pub fn origin() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    println!("{}", json!({"port": listener.local_addr()?.port()}));
    io::stdout().flush()?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            thread::spawn(move || {
                if let Err(error) = serve(stream?) {
                    eprintln!("origin: {error:#}");
                }
                Ok::<_, io::Error>(())
            });
        }
    });
    io::stdin().read_line(&mut String::new())?;
    Ok(())
}

fn serve(mut stream: TcpStream) -> Result<()> {
    socket(&stream)?;
    let mut header = [0; 9];
    stream.read_exact(&mut header)?;
    let count = u64::from_be_bytes(header[1..].try_into().unwrap());
    match header[0] {
        b'D' => transfer(&mut stream, count, true)?,
        b'U' => {
            transfer(&mut stream, count, false)?;
            stream.write_all(b"OK")?;
        }
        b'E' => {
            for _ in 0..count {
                let mut message = [0; 64];
                stream.read_exact(&mut message)?;
                stream.write_all(&message)?;
            }
        }
        _ => bail!("Unknown origin command"),
    }
    Ok(())
}

struct Service(Child);

impl Service {
    fn start(command: &[OsString], log: &Path, cpus: Option<&str>) -> Result<Self> {
        let mut process = if let Some(cpus) = cpus {
            let mut process = Command::new("taskset");
            process.args(["-c", cpus]).args(command);
            process
        } else {
            let mut process = Command::new(&command[0]);
            process.args(&command[1..]);
            process
        };
        Ok(Self(
            process
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(File::create_new(log)?)
                .spawn()?,
        ))
    }

    fn ready(&mut self) -> Result<Value> {
        let output = self.0.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = (|| {
                for line in BufReader::new(output.take(16384)).lines() {
                    if let Ok(value) = serde_json::from_str::<Value>(&line?)
                        && value["port"].as_u64().is_some()
                    {
                        return Ok(value);
                    }
                }
                bail!("Service exited without a startup response");
            })();
            let _ = sender.send(result);
        });
        receiver
            .recv_timeout(Duration::from_secs(20))
            .context("Benchmark service readiness timed out")?
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(mut input) = self.0.stdin.take() {
            let _ = input.write_all(b"quit\n");
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.0.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn counters(pid: u32, ticks: f64) -> Result<Value> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("Missing process comm")?
        .1
        .split_whitespace()
        .collect();
    let mut value = json!({"cpu_seconds": (fields[11].parse::<u64>()? + fields[12].parse::<u64>()?) as f64 / ticks});
    for line in fs::read_to_string(format!("/proc/{pid}/status"))?.lines() {
        let mut fields = line.split_whitespace();
        let name = match fields.next() {
            Some("VmRSS:") => "rss_bytes",
            Some("VmHWM:") => "peak_rss_bytes",
            _ => continue,
        };
        value[name] = json!(
            fields
                .next()
                .context("Missing memory count")?
                .parse::<u64>()?
                * 1024
        );
    }
    Ok(value)
}

fn connect(proxy: u16, origin: u16) -> Result<TcpStream> {
    let mut stream =
        TcpStream::connect_timeout(&([127, 0, 0, 1], proxy).into(), Duration::from_secs(20))?;
    socket(&stream)?;
    stream.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    stream.read_exact(&mut method)?;
    ensure!(method == [5, 0], "SOCKS method rejected");
    stream.write_all(&[5, 1, 0, 1, 127, 0, 0, 1])?;
    stream.write_all(&origin.to_be_bytes())?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply)?;
    ensure!(reply[..3] == [5, 0, 0], "SOCKS connect rejected: {reply:?}");
    let count = match reply[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut size = [0];
            stream.read_exact(&mut size)?;
            usize::from(size[0]) + 2
        }
        _ => bail!("Invalid SOCKS reply address"),
    };
    stream.read_exact(&mut vec![0; count])?;
    Ok(stream)
}

fn request(stream: &mut TcpStream, action: u8, count: u64) -> Result<()> {
    let mut header = [action; 9];
    header[1..].copy_from_slice(&count.to_be_bytes());
    stream.write_all(&header)?;
    Ok(())
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn workload(proxy: u16, origin: u16, name: &str, count: u64) -> Result<Value> {
    let mut durations = Vec::new();
    let began = Instant::now();
    match name {
        "download" | "upload" => {
            let mut stream = connect(proxy, origin)?;
            let upload = name == "upload";
            request(&mut stream, if upload { b'U' } else { b'D' }, count)?;
            transfer(&mut stream, count, upload)?;
            if upload {
                let mut response = [0; 2];
                stream.read_exact(&mut response)?;
                ensure!(&response == b"OK", "Origin did not acknowledge upload");
            }
        }
        "latency" => {
            let mut stream = connect(proxy, origin)?;
            request(&mut stream, b'E', count)?;
            for _ in 0..count {
                let start = Instant::now();
                stream.write_all(&PAYLOAD[..64])?;
                transfer(&mut stream, 64, false)?;
                durations.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        "connections" => {
            for _ in 0..count {
                let start = Instant::now();
                let mut stream = connect(proxy, origin)?;
                request(&mut stream, b'D', 1)?;
                transfer(&mut stream, 1, false)?;
                durations.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        _ => bail!("Unknown workload: {name}"),
    }
    let mut value = json!({"seconds": began.elapsed().as_secs_f64(), "units": count});
    if !durations.is_empty() {
        value["p50_ms"] = json!(median(&mut durations));
        value["p99_ms"] = json!(durations[(durations.len() * 99).div_ceil(100) - 1]);
    }
    Ok(value)
}

struct Options {
    candidate: PathBuf,
    baseline: Option<PathBuf>,
    sing_box: Option<PathBuf>,
    output: PathBuf,
    rounds: u64,
    mib: u64,
    operations: u64,
    core_cpus: Option<String>,
    server_cpus: Option<String>,
    smoke: bool,
}

impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self> {
        let mut opts = Self {
            candidate: PathBuf::new(),
            baseline: None,
            sing_box: None,
            output: PathBuf::new(),
            rounds: 5,
            mib: 64,
            operations: 500,
            core_cpus: None,
            server_cpus: None,
            smoke: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            if arg == "--smoke" {
                opts.smoke = true;
                continue;
            }
            let value = args
                .next()
                .with_context(|| format!("Missing value for {}", arg.to_string_lossy()))?;
            match arg.to_str() {
                Some("--candidate") => opts.candidate = value.into(),
                Some("--baseline") => opts.baseline = Some(value.into()),
                Some("--sing-box") => opts.sing_box = Some(value.into()),
                Some("--output") => opts.output = value.into(),
                Some("--core-cpus") => {
                    opts.core_cpus = Some(
                        value
                            .into_string()
                            .map_err(|_| anyhow::anyhow!("Invalid CPU list"))?,
                    )
                }
                Some("--server-cpus") => {
                    opts.server_cpus = Some(
                        value
                            .into_string()
                            .map_err(|_| anyhow::anyhow!("Invalid CPU list"))?,
                    )
                }
                Some("--rounds" | "--mib" | "--operations") => {
                    let number = value.to_str().context("Invalid number")?.parse()?;
                    ensure!(number > 0, "{} must be positive", arg.to_string_lossy());
                    match arg.to_str().unwrap() {
                        "--rounds" => opts.rounds = number,
                        "--mib" => opts.mib = number,
                        _ => opts.operations = number,
                    }
                }
                _ => bail!("Unknown benchmark option: {}", arg.to_string_lossy()),
            }
        }
        ensure!(
            !opts.candidate.as_os_str().is_empty() && !opts.output.as_os_str().is_empty(),
            "--candidate and --output are required; see cargo xtask bench --help"
        );
        ensure!(opts.mib <= u64::MAX / (1024 * 1024), "--mib is too large");
        Ok(opts)
    }
}

fn binary(path: &Path) -> Result<Value> {
    let path = path.canonicalize()?;
    Ok(json!({"path": path, "sha256": digest(&path)?}))
}

pub fn run(args: Vec<OsString>) -> Result<()> {
    if args == [OsString::from("--help")] {
        println!(
            "cargo xtask bench --candidate FILE --output NEW_DIRECTORY [--baseline FILE] [--sing-box FILE]\n    [--rounds 5] [--mib 64] [--operations 500] [--core-cpus LIST] [--server-cpus LIST] [--smoke]"
        );
        return Ok(());
    }
    let opts = Options::parse(args)?;
    let mut binaries = json!({"candidate": binary(&opts.candidate)?});
    if let Some(path) = &opts.baseline {
        binaries["baseline"] = binary(path)?;
    }
    if let Some(parent) = opts
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(&opts.output).context("Use a new benchmark output directory")?;
    // SAFETY: sysconf with this constant has no pointer arguments or side effects.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(ticks > 0, "Cannot read process clock resolution");
    let affinity = fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Cpus_allowed_list:")
                .map(|v| v.trim().to_owned())
        });
    let cases = if opts.sing_box.is_some() {
        vec!["direct", "ss-aes128"]
    } else {
        vec!["direct"]
    };
    let mut data = json!({"platform": process::output(Command::new("uname").arg("-a"))?.trim(), "machine": std::env::consts::ARCH,
        "clock_ticks_per_second": ticks, "load_affinity": affinity, "core_cpus": opts.core_cpus, "server_cpus": opts.server_cpus,
        "rounds": opts.rounds, "binaries": binaries, "cases": cases, "samples": [], "completed": false,
        "smoke_only": opts.smoke, "mib": opts.mib, "operations": opts.operations});
    let result = measure(&opts, &mut data, ticks as f64);
    match &result {
        Ok(()) => data["completed"] = json!(true),
        Err(error) => data["error"] = json!(format!("{error:#}")),
    }
    fs::write(
        opts.output.join("results.json"),
        serde_json::to_vec_pretty(&data)?,
    )?;
    fs::write(opts.output.join("report.md"), report(&data))?;
    result
}

fn measure(opts: &Options, data: &mut Value, ticks: f64) -> Result<()> {
    let mut origin = Service::start(
        &[std::env::current_exe()?.into(), "bench-origin".into()],
        &opts.output.join("origin.log"),
        opts.server_cpus.as_deref(),
    )?;
    let origin_port = origin.ready()?["port"]
        .as_u64()
        .context("Missing origin port")? as u16;
    let mut peer = None;
    let mut peer_port = 0;
    if let Some(path) = &opts.sing_box {
        data["peer"] = binary(path)?;
        data["peer"]["version"] = json!(process::output(
            Command::new(path.canonicalize()?).arg("version")
        )?);
        peer_port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let config = opts.output.join("peer.json");
        fs::write(
            &config,
            serde_json::to_vec(
                &json!({"log": {"level": "error"}, "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": peer_port, "method": "aes-128-gcm", "password": "aerobox-loopback-benchmark"}], "outbounds": [{"type": "direct"}]}),
            )?,
        )?;
        peer = Some(Service::start(
            &[
                path.canonicalize()?.into(),
                "run".into(),
                "-c".into(),
                config.canonicalize()?.into(),
            ],
            &opts.output.join("peer.log"),
            opts.server_cpus.as_deref(),
        )?);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            ensure!(
                peer.as_mut().unwrap().0.try_wait()?.is_none(),
                "Independent peer exited; see peer.log"
            );
            if TcpStream::connect_timeout(
                &([127, 0, 0, 1], peer_port).into(),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                break;
            }
            ensure!(Instant::now() < deadline, "Independent peer did not listen");
            thread::sleep(Duration::from_millis(20));
        }
    }
    for round in 0..opts.rounds {
        let mut sides = vec!["candidate"];
        if opts.baseline.is_some() {
            sides.push("baseline");
        }
        if round % 2 != 0 {
            sides.reverse();
        }
        let cases = data["cases"].as_array().unwrap().clone();
        for case in &cases {
            let case = case.as_str().unwrap();
            for side in &sides {
                let label = format!("{round}-{case}-{side}");
                let mut command = vec![
                    OsString::from(data["binaries"][side]["path"].as_str().unwrap()),
                    case.into(),
                ];
                if case != "direct" {
                    command.push(peer_port.to_string().into());
                }
                let mut service = Service::start(
                    &command,
                    &opts.output.join(format!("{label}.log")),
                    opts.core_cpus.as_deref(),
                )?;
                let hello = service.ready()?;
                ensure!(
                    hello["debug"] == false || opts.smoke,
                    "Benchmark needs a release helper; use --smoke for tool validation"
                );
                ensure!(hello["case"] == case, "Helper started wrong protocol");
                let port = hello["port"].as_u64().context("Missing service port")? as u16;
                workload(port, origin_port, "download", 1024 * 1024)?;
                let idle = counters(service.0.id(), ticks)?["rss_bytes"].clone();
                for name in ["download", "upload", "latency", "connections"] {
                    let count = if matches!(name, "download" | "upload") {
                        opts.mib * 1024 * 1024
                    } else {
                        opts.operations
                    };
                    let before = counters(service.0.id(), ticks)?;
                    let mut sample = workload(port, origin_port, name, count)?;
                    let after = counters(service.0.id(), ticks)?;
                    sample.as_object_mut().unwrap().extend(json!({"round": round, "side": side, "case": case, "workload": name,
                        "cpu_seconds": after["cpu_seconds"].as_f64().unwrap() - before["cpu_seconds"].as_f64().unwrap(),
                        "rss_bytes": after["rss_bytes"], "peak_rss_bytes": after["peak_rss_bytes"], "idle_rss_bytes": idle,
                        "debug": hello["debug"], "version": hello["version"]}).as_object().unwrap().clone());
                    data["samples"].as_array_mut().unwrap().push(sample);
                }
                println!("completed {label}");
            }
        }
    }
    drop(peer);
    Ok(())
}

fn report(data: &Value) -> String {
    use std::fmt::Write;
    let status = if data["completed"] == true {
        "complete"
    } else {
        "INCOMPLETE — do not compare these results"
    };
    let mut report = format!(
        "# AeroBox network benchmark\n\nLoopback SOCKS ingress; application service only. GTK, TUN and public network are not measured. CPU excludes the origin and load generator.\n\nStatus: {status}\n\n| Build | Protocol | Workload | Samples | Median rate | Median CPU s/unit | Peak RSS MiB |\n|---|---|---|---:|---:|---:|---:|\n"
    );
    for side in data["binaries"].as_object().unwrap().keys() {
        for case in data["cases"].as_array().unwrap() {
            for name in ["download", "upload", "latency", "connections"] {
                let samples: Vec<_> = data["samples"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|s| s["side"] == *side && s["case"] == *case && s["workload"] == name)
                    .collect();
                if samples.is_empty() {
                    continue;
                }
                let bulk = matches!(name, "download" | "upload");
                let divisor = if bulk { 1048576.0 } else { 1.0 };
                let mut rates: Vec<_> = samples
                    .iter()
                    .map(|s| {
                        s["units"].as_f64().unwrap() / divisor / s["seconds"].as_f64().unwrap()
                    })
                    .collect();
                let mut cpus: Vec<_> = samples
                    .iter()
                    .map(|s| {
                        s["cpu_seconds"].as_f64().unwrap()
                            / (s["units"].as_f64().unwrap() / divisor)
                    })
                    .collect();
                let peak = samples
                    .iter()
                    .map(|s| s["peak_rss_bytes"].as_f64().unwrap())
                    .fold(0.0, f64::max)
                    / 1048576.0;
                writeln!(
                    report,
                    "| {side} | {} | {name} | {} | {:.2} {} | {:.6} | {peak:.2} |",
                    case.as_str().unwrap(),
                    samples.len(),
                    median(&mut rates),
                    if bulk { "MiB/s" } else { "ops/s" },
                    median(&mut cpus)
                )
                .unwrap();
            }
        }
    }
    report.push_str("\nCPU unit is MiB for bulk transfers and operation otherwise. Peak RSS accumulates within each round. Raw samples include p50/p99 latency, idle RSS, binary hashes, affinity and clock resolution. Zero CPU deltas can be below process clock resolution.\n\nUse release builds, multiple rounds and an idle machine; retain results.json and logs. This report makes no significance or speedup claim.\n");
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn truncated_and_corrupted_transfers_fail() {
        for payload in [vec![], vec![b'x']] {
            assert!(transfer(&mut io::Cursor::new(payload), 1, false).is_err());
        }
    }
    #[test]
    fn incomplete_report_is_not_a_valid_comparison() {
        assert!(
            report(&json!({"completed": false, "binaries": {}, "cases": [], "samples": []}))
                .contains("INCOMPLETE")
        );
    }
    #[test]
    fn rejected_socks_connection_is_closed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            socket(&stream).unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(&[5, 255]).unwrap();
            assert_eq!(stream.read(&mut greeting).unwrap(), 0);
        });
        assert!(connect(port, 1).is_err());
        server.join().unwrap();
    }
}
