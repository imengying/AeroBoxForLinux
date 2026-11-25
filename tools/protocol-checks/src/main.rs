mod task_owner;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "all".into());
    let root = args
        .next()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
    if args.next().is_some() || !matches!(command.as_str(), "all" | "tasks" | "vision") {
        eprintln!("Usage: protocol-checks [all|tasks|vision] [repository]");
        return std::process::ExitCode::from(2);
    }
    if command != "vision" {
        match task_owner::check(&root.join("vendor/shoes/src/lib.rs")) {
            Ok(files) => println!("Task ownership: {files} production modules checked"),
            Err(error) => {
                eprintln!("{error}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
    if command != "tasks" {
        aerobox_protocol_checks::vision::smoke();
        println!("Vision state machine: deterministic smoke passed");
    }
    std::process::ExitCode::SUCCESS
}
