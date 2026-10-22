use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use globset::{Glob, GlobSetBuilder};
use std::path::{Path, PathBuf};
use std::process::Command;

use trustsweep::feed::{self, Feed};
use trustsweep::report::Report;
use trustsweep::scan::Scanner;

#[derive(Parser)]
#[command(version, about = "Find CA bundles inside artifacts that still trust a revoked CA")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan files and directories (archives such as .whl, .jar and .tgz are opened in memory)
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Scan a container image layer by layer: a `docker save` tarball, or an image ref passed to `docker save`
    Image {
        image: String,
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Manage the distrust feed
    Feed {
        #[command(subcommand)]
        cmd: FeedCmd,
    },
}

#[derive(Subcommand)]
enum FeedCmd {
    /// Rebuild the feed from the incident JSON and Mozilla OneCRL
    Update {
        /// Where to write the feed (default: the user cache file, used automatically by later scans)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Feed whose fix table is carried over (default: active feed)
        #[arg(long)]
        feed: Option<PathBuf>,
        #[arg(long, default_value = feed::INCIDENT_BASE)]
        incident_base: String,
        #[arg(long, default_value = feed::ONECRL_URL)]
        onecrl_url: String,
    },
    /// Print which feed is active
    Show {
        #[arg(long)]
        feed: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Args)]
struct ScanOpts {
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Feed file (default: cache from `feed update` if present, else built-in)
    #[arg(long)]
    feed: Option<PathBuf>,
    /// Skip paths matching this glob (repeatable), e.g. '**/tests/**'
    #[arg(long)]
    exclude: Vec<String>,
    /// Files and archive entries larger than this are reported as errors and skipped
    #[arg(long, default_value_t = 1 << 30)]
    max_file_bytes: u64,
    /// Also list every CA bundle found
    #[arg(short, long)]
    verbose: bool,
    /// Write the report here instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn run_scan(opts: &ScanOpts, scan: impl FnOnce(&mut Scanner) -> Result<()>) -> Result<i32> {
    let (feed, origin) = Feed::load(opts.feed.as_deref())?;
    let matcher = feed.compile(origin)?;
    let mut globs = GlobSetBuilder::new();
    for g in &opts.exclude {
        globs.add(Glob::new(g).with_context(|| format!("bad --exclude glob {g}"))?);
    }
    let mut scanner = Scanner::new(&matcher, globs.build()?, opts.max_file_bytes)?;
    scan(&mut scanner)?;
    let report = Report::build(scanner);
    let out = match opts.format {
        Format::Text => report.text(opts.verbose),
        Format::Json => serde_json::to_string_pretty(&report)? + "\n",
        Format::Sarif => serde_json::to_string_pretty(&report.sarif())? + "\n",
    };
    match &opts.output {
        Some(p) => std::fs::write(p, out).with_context(|| format!("writing {}", p.display()))?,
        None => print!("{out}"),
    }
    Ok(report.exit_code())
}

fn docker_save(image: &str, dir: &Path) -> Result<PathBuf> {
    let out = dir.join("image.tar");
    let status = Command::new("docker")
        .args(["save", "-o"])
        .arg(&out)
        .arg(image)
        .status()
        .context("running `docker save` (is docker installed?)")?;
    if !status.success() {
        bail!("`docker save {image}` failed with {status}");
    }
    Ok(out)
}

fn main() {
    let code = match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("trustsweep: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.cmd {
        Cmd::Scan { paths, opts } => run_scan(&opts, |s| {
            for p in &paths {
                if !p.exists() {
                    bail!("{} does not exist", p.display());
                }
                s.scan_path(p);
            }
            Ok(())
        }),
        Cmd::Image { image, opts } => {
            let path = PathBuf::from(&image);
            let tmp = tempfile::tempdir()?;
            let tarball = if path.is_file() { path } else { docker_save(&image, tmp.path())? };
            run_scan(&opts, |s| s.scan_image(&tarball))
        }
        Cmd::Feed { cmd: FeedCmd::Update { out, feed, incident_base, onecrl_url } } => {
            let (base, _) = Feed::load(feed.as_deref())?;
            let new = feed::update(&base, &incident_base, &onecrl_url, now_utc())?;
            new.compile("update".into()).context("refusing to write a feed that does not compile")?;
            let out = match out {
                Some(p) => p,
                None => Feed::cache_path().context("cannot determine cache directory; pass --out")?,
            };
            if let Some(dir) = out.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&out, serde_json::to_string_pretty(&new)? + "\n")?;
            eprintln!("wrote {} ({} certs, {} OneCRL entries)", out.display(), new.certs.len(), new.onecrl.len());
            Ok(0)
        }
        Cmd::Feed { cmd: FeedCmd::Show { feed } } => {
            let (f, origin) = Feed::load(feed.as_deref())?;
            let m = f.compile(origin)?;
            println!("{}", serde_json::to_string_pretty(&m.info)?);
            Ok(0)
        }
    }
}
