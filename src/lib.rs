#![recursion_limit = "128"]

use cargo_metadata::{Metadata, Package, PackageId, Target};
use derive_more::{Deref, Display, From, FromStr, Into};
use failure::{Backtrace, Fail, ResultExt as _};
use filetime::FileTime;
use fixedbitset::FixedBitSet;
use if_chain::if_chain;
use indexmap::indexmap;
use itertools::Itertools as _;
use log::info;
use maplit::btreeset;
use once_cell::sync::Lazy;
use opaque_typedef_macros::{OpaqueTypedef, OpaqueTypedefUnsized};
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use structopt::StructOpt;
use strum_macros::{EnumString, IntoStaticStr};

use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, ReadDir};
use std::ops::{Deref, Range};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::str::{FromStr, SplitWhitespace};
use std::time::SystemTime;
use std::{cmp, env};

macro_rules! lazy_regex {
    ($regex:expr $(,)?) => {
        ::once_cell::sync::Lazy::new(|| ::regex::Regex::new($regex).unwrap())
    };
}

pub type Result<T> = std::result::Result<T, crate::Error>;

#[derive(Display, Debug, From)]
#[display(fmt = "{}", _0)]
pub struct Error(failure::Context<ErrorKind>);

impl From<ErrorKind> for Error {
    fn from(kind: crate::ErrorKind) -> Self {
        Self(kind.into())
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.0.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.0.backtrace()
    }
}

#[derive(Display, Debug, Fail)]
enum ErrorKind {
    #[display(fmt = "Could not find the root workspace")]
    RootWorkspaceNotFound,
    #[display(fmt = "{}: Missing `license`", _0)]
    MissingLicense(String),
    #[display(fmt = "{}: Unsupported `license`: {:?}", _0, _1)]
    UnsupportedLicense(String, String),
    #[display(fmt = "{}: Missing crates.io registry or repository", _0)]
    MissingCratesIoRegistryOrRepository(String),
    #[display(fmt = "No such package ID: {:?}", _0)]
    NoSuchPackageId(String),
    #[display(fmt = "No such target: {:?}", _0)]
    NoSuchTarget(Vec<String>),
    #[display(fmt = "Failed to parse command line arguments")]
    ParseCommandArguments,
    #[display(fmt = "Failed to get the current directory")]
    Getcwd,
    #[display(fmt = "Failed to read {}", path)]
    Read { path: String },
    #[display(fmt = "Failed to touch {}", path)]
    Touch { path: String },
    #[display(fmt = "stream did not contain valid UTF-8")]
    Utf8,
    #[display(fmt = "Failed to execute {:?}", _0)]
    StartProcess(String),
    #[display(
        fmt = "{:?} exited {}",
        arg0,
        r#"match status.code() {
               None => "without code".to_owned(),
               Some(code) => format!("with {}", code),
           }"#
    )]
    ExitedAbnormally { arg0: String, status: ExitStatus },
    #[display(fmt = "Could not read ${}", _0)]
    EnvVar(&'static str),
    #[display(fmt = "{:?} does not match {:?}", text, regex)]
    Regex { text: String, regex: &'static str },
    #[display(fmt = "Failed to deserialize {}", what)]
    DeserializeJson { what: &'static str },
}

#[derive(StructOpt, Debug)]
#[structopt(bin_name = "cargo")]
pub enum Opt {
    #[structopt(name = "copyright")]
    Copyright(OptCopyright),
}

#[derive(StructOpt, Debug)]
pub struct OptCopyright {
    #[structopt(
        long = "exclude-unused",
        help = "Exclude unused crates",
        raw(display_order = "1")
    )]
    exclude_unused: bool,
    #[structopt(
        long = "prefer-links",
        help = "Always emits URLs even if `LICENSE` files found",
        raw(display_order = "2")
    )]
    prefer_links: bool,
    #[structopt(
        long = "cargo-command",
        value_name = "COMMAND",
        help = "Cargo command for `exclude-unused`",
        raw(
            display_order = "1",
            default_value = "<&str>::from(CargoCommand::default())",
            possible_values = "&CargoCommand::variants()"
        )
    )]
    cargo_command: CargoCommand,
    #[structopt(
        long = "format",
        value_name = "FORMAT",
        help = "Format",
        raw(
            display_order = "2",
            default_value = "<&str>::from(Format::default())",
            possible_values = "&Format::variants()"
        )
    )]
    format: Format,
    #[structopt(
        long = "bin",
        value_name = "STRING",
        help = "Target `bin`",
        raw(display_order = "3")
    )]
    bin: Option<String>,
    #[structopt(
        long = "manifest-path",
        value_name = "STRING",
        help = "Path to Cargo.toml",
        raw(display_order = "4")
    )]
    manifest_path: Option<Utf8PathBuf>,
    #[structopt(
        long = "color",
        value_name = "WHEN",
        help = "Coloring",
        raw(
            display_order = "5",
            default_value = "<&str>::from(ColorChoice::default())",
            possible_values = "&ColorChoice::variants()"
        )
    )]
    pub color: ColorChoice,
}

#[derive(Debug, EnumString, IntoStaticStr, Clone, Copy, PartialEq)]
#[strum(serialize_all = "kebab_case")]
enum Format {
    Markdown,
}

impl Default for Format {
    fn default() -> Self {
        Format::Markdown
    }
}

impl Format {
    fn variants() -> [&'static str; 1] {
        ["markdown"]
    }
}

#[derive(Debug, EnumString, IntoStaticStr, Clone, Copy)]
#[strum(serialize_all = "kebab_case")]
enum CargoCommand {
    Clippy,
    Check,
}

impl Default for CargoCommand {
    fn default() -> Self {
        CargoCommand::Clippy
    }
}

impl CargoCommand {
    fn variants() -> [&'static str; 2] {
        ["clippy", "check"]
    }
}

#[derive(Debug, Clone, Copy, EnumString, IntoStaticStr)]
#[strum(serialize_all = "kebab_case")]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl Default for ColorChoice {
    fn default() -> Self {
        ColorChoice::Auto
    }
}

impl ColorChoice {
    fn variants() -> [&'static str; 3] {
        ["auto", "always", "never"]
    }

    pub fn stderr(self) -> (termcolor::ColorChoice, env_logger::WriteStyle) {
        #[cfg(windows)]
        static BLACKLIST: &[&str] = &["cygwin", "dumb"];

        #[cfg(not(windows))]
        static BLACKLIST: &[&str] = &["dumb"];

        let always = (
            termcolor::ColorChoice::Always,
            env_logger::WriteStyle::Always,
        );
        let never = (termcolor::ColorChoice::Never, env_logger::WriteStyle::Never);

        match self {
            ColorChoice::Auto
                if atty::is(atty::Stream::Stderr)
                    && env::var("TERM")
                        .ok()
                        .map_or(false, |v| !BLACKLIST.contains(&v.as_ref())) =>
            {
                always
            }
            ColorChoice::Auto | ColorChoice::Always => always,
            ColorChoice::Never => never,
        }
    }
}

#[derive(Debug)]
pub struct App {
    process_ctx: ProcessContext,
}

impl App {
    pub fn try_new() -> crate::Result<Self> {
        let wd = env::current_dir().with_context(|_| crate::ErrorKind::Getcwd)?;
        Ok(App {
            process_ctx: ProcessContext { wd },
        })
    }

    pub fn run(&mut self, opt: &OptCopyright) -> crate::Result<String> {
        struct OrderedPackage<'a>(&'a Package);

        impl<'a> PartialEq for OrderedPackage<'a> {
            fn eq(&self, other: &OrderedPackage<'a>) -> bool {
                (&self.0.name, &self.0.version, &self.0.id)
                    == (&other.0.name, &other.0.version, &other.0.id)
            }
        }

        impl<'a> Eq for OrderedPackage<'a> {}

        impl<'a> PartialOrd for OrderedPackage<'a> {
            fn partial_cmp(&self, other: &OrderedPackage<'a>) -> Option<cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl<'a> Ord for OrderedPackage<'a> {
            fn cmp(&self, other: &OrderedPackage<'a>) -> cmp::Ordering {
                self.0
                    .name
                    .cmp(&other.0.name)
                    .then_with(|| self.0.version.cmp(&other.0.version))
                    .then_with(|| self.0.id.cmp(&other.0.id))
            }
        }

        let cargo =
            Utf8PathBuf(env::var("CARGO").with_context(|_| crate::ErrorKind::EnvVar("CARGO"))?);

        let metadata = {
            let mut args = vec!["metadata", "--format-version", "1"];
            if let Some(manifest_path) = &opt.manifest_path {
                args.push("--manifest-path");
                args.push(manifest_path.as_ref());
            }
            let stdout = self.process_ctx.check_stdout(cargo.as_ref(), &args)?;
            from_json::<Metadata>(&stdout, "`cargo metadata` output")?
        };

        let targets = targets(&metadata, opt.bin.as_ref().map(Deref::deref))?;
        let mut used_packages = btreeset!();
        if opt.exclude_unused {
            let process_ctx = ProcessContext {
                wd: metadata.workspace_root.clone(),
            };
            for (package, cmd) in clippy_or_rustc_cmds(
                &targets,
                &cargo,
                opt.cargo_command,
                opt.bin.as_ref().map(Deref::deref),
                opt.manifest_path.as_ref().map(Deref::deref),
                &process_ctx,
            )? {
                for package in exclude_unused_crates(&metadata, package, &cmd)? {
                    used_packages.insert(OrderedPackage(package));
                }
            }
        } else {
            let packages = targets
                .iter()
                .map(|(p, _)| (&p.id, p))
                .collect::<HashMap<_, _>>();
            for (_, package) in packages {
                for dependency in dependencies(&metadata, &package.id)? {
                    used_packages.insert(OrderedPackage(dependency));
                }
            }
        }
        for (package, _) in &targets {
            used_packages.remove(&OrderedPackage(package));
        }

        let mut emitter = Emitter::new(opt.prefer_links);
        for OrderedPackage(used_package) in used_packages {
            let notice = Notice::read_from_package(used_package)?;
            emitter.push(used_package, notice)?;
        }
        Ok(emitter.emit_markdown())
    }
}

fn targets<'a>(
    metadata: &'a Metadata,
    bin: Option<&str>,
) -> crate::Result<Vec<(&'a Package, &'a Target)>> {
    let root = metadata
        .resolve
        .as_ref()
        .and_then(|r| r.root.as_ref())
        .and_then(|r| metadata.packages.iter().find(|p| p.id == *r))
        .ok_or(crate::ErrorKind::RootWorkspaceNotFound)?;

    let bin = if let Some(bin) = bin {
        root.targets
            .iter()
            .find(|t| t.name == bin && t.kind.contains(&"bin".to_owned()))
            .ok_or_else(|| crate::ErrorKind::NoSuchTarget(vec![bin.to_owned()]))
    } else {
        root.targets
            .iter()
            .find(|t| {
                [&root.name, "main"].contains(&t.name.as_ref())
                    && t.kind.contains(&"bin".to_owned())
            })
            .ok_or_else(|| {
                crate::ErrorKind::NoSuchTarget(vec![root.name.clone(), "main".to_owned()])
            })
    }?;
    let bin = (root, bin);

    let libs = metadata
        .workspace_members
        .iter()
        .flat_map(|m| metadata.packages.iter().find(|p| p.id == *m))
        .flat_map(|package| {
            package
                .targets
                .iter()
                .filter(|target| {
                    target
                        .kind
                        .iter()
                        .any(|k| ["lib", "proc-macro"].contains(&k.deref()))
                })
                .map(move |t| (package, t))
        });

    let mut targets = vec![bin];
    targets.extend(libs);
    Ok(targets)
}

fn clippy_or_rustc_cmds<'a>(
    targets: &[(&'a Package, &'a Target)],
    cargo: &Utf8PathBuf,
    cargo_cmd: CargoCommand,
    bin: Option<&str>,
    manifest_path: Option<&Utf8Path>,
    process_ctx: &ProcessContext,
) -> crate::Result<Vec<(&'a Package, ClippyDriverOrRustc)>> {
    for (_, Target { src_path, .. }) in targets {
        let src_path = src_path.to_str().expect("this is from a JSON");
        let now = FileTime::from(SystemTime::now());
        filetime::set_file_times(src_path, now, now).with_context(|_| crate::ErrorKind::Touch {
            path: src_path.to_owned(),
        })?;
        info!("Touched {}", src_path);
    }

    let stderr = {
        let mut args = vec![
            <&str>::from(cargo_cmd),
            "--verbose",
            "--message-format",
            "json",
            "--color",
            "never",
        ];
        if let Some(bin) = bin {
            args.extend_from_slice(&["--bin", bin]);
        }
        if let Some(manifest_path) = manifest_path {
            args.extend_from_slice(&["--manifest-path", manifest_path.as_ref()]);
        }
        process_ctx.check_stderr(cargo.as_ref(), &args)?
    };

    static RUNNING: Lazy<Regex> = lazy_regex!(r" *Running +`([a-zA-Z0-9=/,_\-\. ]+)`");
    RUNNING
        .captures_iter(&stderr)
        .map(|caps| {
            let args = caps[1].split_whitespace();
            let cmd = ClippyDriverOrRustc::try_new(args, process_ctx.clone(), cargo)?;
            let targets = targets
                .iter()
                .cloned()
                .filter(|(_, target)| {
                    if let (Some(crate_name), Some(crate_type)) =
                        (&cmd.rustc_opts.crate_name, &cmd.rustc_opts.crate_type)
                    {
                        crate_name.replace('-', "_") == target.name.replace('-', "_")
                            && *crate_type == target.crate_types
                    } else {
                        false
                    }
                })
                .collect::<Vec<_>>();
            if targets.len() != 1 {
                unimplemented!()
            }
            let (package, _) = targets[0];
            Ok((package, cmd))
        })
        .collect()
}

fn exclude_unused_crates<'a>(
    metadata: &'a Metadata,
    package: &'a Package,
    cmd: &ClippyDriverOrRustc,
) -> crate::Result<Vec<&'a Package>> {
    #[derive(Deserialize)]
    struct ErrorMessage {
        message: String,
        code: Option<ErrorMessageCode>,
    }

    #[derive(Deserialize)]
    struct ErrorMessageCode {
        code: String,
    }

    let mut exclude = FixedBitSet::with_capacity(cmd.rustc_opts.r#extern.len());
    exclude.insert_range(0..cmd.rustc_opts.r#extern.len());

    let something_wrong = loop {
        static E0432: Lazy<Regex> = lazy_regex!(r"\Aunresolved import `([a-zA-Z0-9_]+)`\z");
        static E0433: Lazy<Regex> =
            lazy_regex!(r"\Afailed to resolve: [a-z ]+`([a-zA-Z0-9_]+)`( in `\{\{root\}\}`)?\z",);

        if let Err(stderr) = cmd.stderr(&exclude)? {
            let mut updated = false;
            let mut num_e0432 = 0;
            let mut num_e0433 = 0;
            let mut num_others = 0;

            for line in stderr.lines() {
                let msg = from_json::<ErrorMessage>(line, "an error message")?;

                if_chain! {
                    if let Some(code) = &msg.code;
                    if let Some(regex) = match code.code.as_ref() {
                        "E0432" => {
                            num_e0432 += 1;
                            Some(&E0432)
                        }
                        "E0433" => {
                            num_e0433 += 1;
                            Some(&E0433)
                        }
                        _ => {
                            num_others += 1;
                            None
                        }
                    };
                    let caps = regex.captures(&msg.message) .ok_or_else(|| {
                        let (text, regex) = (msg.message.clone(), regex.as_str());
                        crate::ErrorKind::Regex {text, regex}
                    })?;
                    if let Some(pos) = cmd.rustc_opts
                        .r#extern
                        .iter()
                        .position(|e| *e.name() == caps[1]);
                    then {
                        updated |= exclude[pos];
                        exclude.set(pos, false);
                    }
                }
            }

            info!(
                "E0432: {}, E0433: {}, other error(s): {}",
                num_e0432, num_e0433, num_others,
            );

            if !updated {
                break true;
            }
        } else {
            break false;
        }
    };

    if something_wrong {
        info!("Something is wrong. Trying to exclude crates one by one");
        let mut exclude_1by1 = FixedBitSet::with_capacity(cmd.rustc_opts.r#extern.len());
        for i in 0..cmd.rustc_opts.r#extern.len() {
            exclude_1by1.insert(i);
            exclude_1by1.set(i, cmd.success(&exclude_1by1)?);
        }
        exclude = exclude_1by1;
    }

    let exclude = cmd
        .rustc_opts
        .r#extern
        .iter()
        .enumerate()
        .filter(|&(i, _)| !exclude[i])
        .map(|(_, e)| e.name())
        .collect::<HashSet<_>>();

    let dependencies = dependencies(metadata, &package.id)?;
    Ok(dependencies
        .iter()
        .cloned()
        .filter(|package| {
            package.targets.iter().any(|target| {
                (target.kind.contains(&"lib".to_owned())
                    || target.kind.contains(&"proc-macro".to_owned()))
                    && exclude.contains(&target.name.replace('-', "_").as_ref())
            })
        })
        .collect())
}

fn dependencies<'a>(metadata: &'a Metadata, id: &'a PackageId) -> crate::Result<Vec<&'a Package>> {
    let dependencies = metadata
        .resolve
        .as_ref()
        .and_then(|r| r.nodes.iter().find(|n| n.id == *id))
        .map(|n| &n.dependencies[..])
        .unwrap_or_default();
    dependencies
        .iter()
        .map(|id| {
            metadata
                .packages
                .iter()
                .find(|p| p.id == *id)
                .ok_or_else(|| crate::ErrorKind::NoSuchPackageId(id.repr.clone()).into())
        })
        .collect()
}

#[derive(Debug)]
struct ClippyDriverOrRustc {
    arg0: String,
    rustc_subcommand: bool,
    rustc_opts: Rustc,
    ctx: ProcessContext,
}

impl ClippyDriverOrRustc {
    fn try_new(
        args: SplitWhitespace,
        ctx: ProcessContext,
        cargo: &Utf8Path,
    ) -> crate::Result<Self> {
        let args = args.collect::<Vec<_>>();
        match args.get(0).cloned() {
            Some(arg0) if arg0.ends_with("clippy-driver") => {
                let arg0 = arg0.to_owned();
                let ClippyDriver::Rustc(rustc_opts) = ClippyDriver::from_iter_safe(args)
                    .with_context(|_| crate::ErrorKind::ParseCommandArguments)?;
                Ok(Self {
                    arg0,
                    rustc_subcommand: true,
                    rustc_opts,
                    ctx,
                })
            }
            Some("rustc") => {
                let arg0 = cargo.with_file_name("rustc").into();
                let rustc_opts = Rustc::from_iter_safe(args)
                    .with_context(|_| crate::ErrorKind::ParseCommandArguments)?;
                Ok(Self {
                    arg0,
                    rustc_subcommand: false,
                    rustc_opts,
                    ctx,
                })
            }
            _ => Err(crate::ErrorKind::ParseCommandArguments.into()),
        }
    }

    fn success(&self, exclude: &FixedBitSet) -> crate::Result<bool> {
        let status = self.ctx.status(&self.arg0, &self.args(exclude))?;
        Ok(status.success())
    }

    fn stderr(&self, exclude: &FixedBitSet) -> crate::Result<std::result::Result<(), String>> {
        let (status, stderr) = self.ctx.stderr(&self.arg0, &self.args(exclude))?;
        Ok(if status.success() {
            Ok(())
        } else {
            Err(stderr)
        })
    }

    #[allow(clippy::cognitive_complexity)]
    fn args(&self, exclude: &FixedBitSet) -> Vec<&str> {
        let mut args = if self.rustc_subcommand {
            vec!["rustc"]
        } else {
            vec![]
        };

        for cfg in &self.rustc_opts.cfg {
            args.push("--cfg");
            args.push(cfg);
        }
        for l in &self.rustc_opts.link_path {
            args.push("-L");
            args.push(l);
        }
        for l in &self.rustc_opts.link_crate {
            args.push("-l");
            args.push(l);
        }
        if let Some(crate_type) = &self.rustc_opts.crate_type {
            args.push("--crate-type");
            args.push(crate_type);
        }
        if let Some(crate_name) = &self.rustc_opts.crate_name {
            args.push("--crate-name");
            args.push(crate_name);
        }
        if let Some(edition) = &self.rustc_opts.edition {
            args.push("--edition");
            args.push(edition);
        }
        if let Some(emit) = &self.rustc_opts.emit {
            args.push("--emit");
            args.push(emit);
        }
        if let Some(print) = &self.rustc_opts.print {
            args.push("--print");
            args.push(print);
        }
        if self.rustc_opts.debuginfo_2 {
            args.push("-g");
        }
        if self.rustc_opts.opt_level_2 {
            args.push("-O");
        }
        if let Some(o) = &self.rustc_opts.output {
            args.push("-o");
            args.push(o);
        }
        if let Some(out_dir) = &self.rustc_opts.out_dir {
            args.push("--out-dir");
            args.push(out_dir);
        }
        for explain in &self.rustc_opts.explain {
            args.push("--explain");
            args.push(explain);
        }
        if self.rustc_opts.test {
            args.push("--test");
        }
        if let Some(target) = &self.rustc_opts.target {
            args.push("--target");
            args.push(target);
        }
        for warn in &self.rustc_opts.warn {
            args.push("--warn");
            args.push(warn);
        }
        for allow in &self.rustc_opts.allow {
            args.push("--allow");
            args.push(allow);
        }
        for deny in &self.rustc_opts.deny {
            args.push("--deny");
            args.push(deny);
        }
        for forbid in &self.rustc_opts.forbid {
            args.push("--forbid");
            args.push(forbid);
        }
        if let Some(cap_lints) = &self.rustc_opts.cap_lints {
            args.push("--cap-lints");
            args.push(cap_lints);
        }
        for codegen in &self.rustc_opts.codegen {
            args.push("--codegen");
            args.push(codegen);
        }
        if self.rustc_opts.verbose {
            args.push("--verbose");
        }
        for (i, r#extern) in self.rustc_opts.r#extern.iter().enumerate() {
            if !exclude[i] {
                args.push("--extern");
                args.push(r#extern);
            }
        }
        for extern_private in &self.rustc_opts.extern_private {
            args.push("--extern-private");
            args.push(extern_private);
        }
        if let Some(sysroot) = &self.rustc_opts.sysroot {
            args.push("--sysroot");
            args.push(sysroot);
        }
        if let Some(error_format) = &self.rustc_opts.error_format {
            args.push("--error-format");
            args.push(error_format);
        }
        if let Some(color) = &self.rustc_opts.color {
            args.push("--color");
            args.push(color);
        }
        if let Some(remap_path_prefix) = &self.rustc_opts.remap_path_prefix {
            args.push("--remap-path-prefix");
            args.push(remap_path_prefix);
        }
        args.push(&self.rustc_opts.input);

        args
    }
}

#[derive(Debug, StructOpt)]
enum ClippyDriver {
    #[structopt(name = "rustc")]
    Rustc(Rustc),
}

#[derive(Debug, StructOpt)]
struct Rustc {
    #[structopt(long = "cfg")]
    cfg: Vec<String>,
    #[structopt(short = "L")]
    link_path: Vec<String>,
    #[structopt(short = "l")]
    link_crate: Vec<String>,
    #[structopt(long = "crate-type")]
    crate_type: Option<CrateType>,
    #[structopt(long = "crate-name")]
    crate_name: Option<String>,
    #[structopt(long = "edition")]
    edition: Option<String>,
    #[structopt(long = "emit")]
    emit: Option<String>,
    #[structopt(long = "print")]
    print: Option<String>,
    #[structopt(short = "g")]
    debuginfo_2: bool,
    #[structopt(short = "O")]
    opt_level_2: bool,
    #[structopt(short = "o")]
    output: Option<String>,
    #[structopt(long = "test")]
    test: bool,
    #[structopt(long = "out-dir")]
    out_dir: Option<String>,
    #[structopt(long = "explain")]
    explain: Vec<String>,
    #[structopt(long = "target")]
    target: Option<String>,
    #[structopt(short = "W", long = "warn")]
    warn: Vec<String>,
    #[structopt(short = "A", long = "allow")]
    allow: Vec<String>,
    #[structopt(short = "D", long = "deny")]
    deny: Vec<String>,
    #[structopt(short = "F", long = "forbid")]
    forbid: Vec<String>,
    #[structopt(long = "cap-lints")]
    cap_lints: Option<String>,
    #[structopt(short = "C", long = "codegen")]
    codegen: Vec<String>,
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
    #[structopt(long = "extern")]
    r#extern: Vec<Extern>,
    #[structopt(long = "extern-private")]
    extern_private: Vec<String>,
    #[structopt(long = "sysroot")]
    sysroot: Option<String>,
    #[structopt(long = "error-format")]
    error_format: Option<String>,
    #[structopt(long = "color")]
    color: Option<String>,
    #[structopt(long = "remap-path-prefix")]
    remap_path_prefix: Option<String>,
    input: String,
}

#[derive(Debug, FromStr, Deref)]
struct CrateType(String);

impl PartialEq<Vec<String>> for CrateType {
    fn eq(&self, rhs: &Vec<String>) -> bool {
        let lhs = self.split(',').collect::<BTreeSet<_>>();
        let rhs = rhs.iter().map(AsRef::as_ref).collect::<BTreeSet<_>>();
        lhs == rhs
    }
}

#[derive(Display, Debug, PartialEq, Eq, Hash)]
#[display(fmt = "{}", string)]
struct Extern {
    string: String,
    name: Range<usize>,
}

impl Extern {
    fn name(&self) -> &str {
        &self.string[self.name.clone()]
    }
}

impl FromStr for Extern {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        static EXTERN: Lazy<Regex> = lazy_regex!(r"\A([a-zA-Z0-9_]+)=.*\z");

        let caps = EXTERN.captures(s).ok_or_else(|| {
            let (text, regex) = (s.to_owned(), EXTERN.as_str());
            crate::ErrorKind::Regex { text, regex }
        })?;
        Ok(Self {
            string: s.to_owned(),
            name: 0..caps[1].len(),
        })
    }
}

impl Deref for Extern {
    type Target = str;

    fn deref(&self) -> &str {
        &self.string
    }
}

#[derive(Debug)]
struct Notice {
    kind: LicenseKind,
    text: Option<Text>,
}

impl Notice {
    fn read_from_package(package: &Package) -> crate::Result<Self> {
        let license = package
            .license
            .as_ref()
            .ok_or_else(|| crate::ErrorKind::MissingLicense(package.name.clone()))?;

        let (kind, is_multiple) =
            LicenseKind::try_from_short_identifiers(license).ok_or_else(|| {
                crate::ErrorKind::UnsupportedLicense(package.name.clone(), license.clone())
            })?;

        let text = match kind {
            LicenseKind::Mit => {
                let filenames = if is_multiple {
                    &["license-mit", "license-mit.txt"][..]
                } else {
                    &["license-mit", "license-mit.txt", "license", "license.txt"][..]
                };
                Text::find(package, filenames)?
            }
            LicenseKind::Apache2_0 => {
                let filenames = if is_multiple {
                    &["license-apache", "license-apache.txt"][..]
                } else {
                    &[
                        "license-apache",
                        "license-apache.txt",
                        "license",
                        "license.txt",
                    ][..]
                };
                Text::find(package, filenames)?
            }
            LicenseKind::Bsd3Clause => {
                let filenames = if is_multiple {
                    &["license-bsd", "license-bsd.txt"][..]
                } else {
                    &["license-bsd", "license-bsd.txt", "license", "license.txt"][..]
                };
                Text::find(package, filenames)?
            }
            LicenseKind::Mpl2_0 => {
                let filenames = if is_multiple {
                    &["license-mpl", "license-mpl.txt"][..]
                } else {
                    &["license-mpl", "license-mpl.txt", "license", "license.txt"][..]
                };
                Text::find(package, filenames)?
            }
            LicenseKind::Isc => {
                let filenames = if is_multiple {
                    &["license-isc", "license-isc.txt"][..]
                } else {
                    &["license-isc", "license-isc.txt", "license", "license.txt"][..]
                };
                Text::find(package, filenames)?
            }
            LicenseKind::CC0_1_0 | LicenseKind::Unlicense | LicenseKind::Wtfpl => None,
        };
        info!(
            "{} v{}: {:?} → ({:?}, {:?})",
            package.name,
            package.version,
            license,
            kind,
            text.as_ref()
                .map(|t| t.path.file_name().unwrap_or_default()),
        );
        Ok(Self { kind, text })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum LicenseKind {
    Mit,
    Apache2_0,
    Bsd3Clause,
    Mpl2_0,
    Isc,
    CC0_1_0,
    Unlicense,
    Wtfpl,
}

impl LicenseKind {
    fn try_from_short_identifiers(identifiers: &str) -> Option<(Self, bool)> {
        fn try_from_short_identifier(short_identifier: &str) -> Option<LicenseKind> {
            match short_identifier.trim() {
                "MIT" => Some(LicenseKind::Mit),
                "Apache-2.0" => Some(LicenseKind::Apache2_0),
                "BSD-3-Clause" => Some(LicenseKind::Bsd3Clause),
                "MPL-2.0" | "MPL-2.0+" => Some(LicenseKind::Mpl2_0),
                "ISC" => Some(LicenseKind::Isc),
                "CC0-1.0" => Some(LicenseKind::CC0_1_0),
                "Unlicense" => Some(LicenseKind::Unlicense),
                "WTFPL" => Some(LicenseKind::Wtfpl),
                _ => None,
            }
        }

        fn min(identifiers: &str, pat: &str) -> Option<LicenseKind> {
            identifiers
                .split(pat)
                .map(try_from_short_identifier)
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .min()
        }

        try_from_short_identifier(identifiers)
            .map(|k| (k, false))
            .or_else(|| {
                if identifiers.contains('/') {
                    min(identifiers, "/").map(|k| (k, true))
                } else if identifiers.contains("OR") {
                    min(identifiers, "OR").map(|k| (k, true))
                } else {
                    None
                }
            })
    }

    fn full_name(self) -> &'static str {
        match self {
            LicenseKind::Mit => "MIT License",
            LicenseKind::Apache2_0 => "Apache License 2.0",
            LicenseKind::Bsd3Clause => r#"BSD 3-Clause "New" or "Revised" License"#,
            LicenseKind::Mpl2_0 => "Mozilla Public License 2.0",
            LicenseKind::Isc => "ISC License",
            LicenseKind::CC0_1_0 => "Creative Commons Zero v1.0 Universal",
            LicenseKind::Unlicense => "The Unlicense",
            LicenseKind::Wtfpl => "Do What The F*ck You Want To Public License",
        }
    }

    fn url(self) -> &'static str {
        match self {
            LicenseKind::Mit => "https://opensource.org/licenses/MIT",
            LicenseKind::Apache2_0 => "http://www.mozilla.org/MPL/2.0/",
            LicenseKind::Bsd3Clause => "https://opensource.org/licenses/BSD-3-Clause",
            LicenseKind::Mpl2_0 => "http://www.mozilla.org/MPL/2.0/",
            LicenseKind::Isc => {
                "https://www.isc.org/downloads/software-support-policy/isc-license/"
            }
            LicenseKind::CC0_1_0 => "https://creativecommons.org/publicdomain/zero/1.0/legalcode",
            LicenseKind::Unlicense => "http://unlicense.org/",
            LicenseKind::Wtfpl => "http://sam.zoy.org/wtfpl/COPYING",
        }
    }

    fn is_public_domain(self) -> bool {
        match self {
            LicenseKind::CC0_1_0 | LicenseKind::Unlicense | LicenseKind::Wtfpl => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct Text {
    path: Utf8PathBuf,
    content: String,
    copyright: Option<Range<usize>>,
}

impl Text {
    fn find(package: &Package, filenames: &[&str]) -> crate::Result<Option<Self>> {
        static COPYRIGHT: Lazy<Regex> = lazy_regex!(r"^Copyright.*");

        if_chain! {
            if let Some(dir) = package.manifest_path.parent();
            let dir = <&Utf8Path>::try_from(dir).expect("this is from JSON").to_owned();
            if let Some(path) = dir
                .read_dir()?
                .flatten()
                .filter(|entry| entry.metadata().is_ok() && {
                    let path = entry.path();
                    let file_name = path.file_name().unwrap_or_default();
                    path.is_file() && file_name.to_str().map_or(false, |file_name| {
                        filenames.iter().any(|s| s.eq_ignore_ascii_case(&file_name))
                    })
                })
                .map(|e| e.path())
                .next();
            let path = Utf8PathBuf::try_from(path)
                .expect("considered to be UTF-8 (<utf8 dir><separator><utf8 filename>)");
            let content = read_to_string(&path)?;
            then {
                let copyright = COPYRIGHT
                    .captures(&content)
                    .map(|caps| {
                        let start = (caps[0].as_ptr() as usize) - (content.as_ptr() as usize);
                        start..start + caps[0].len()
                    });
                Ok(Some(Self {
                    path,
                    content,
                    copyright,
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn copyright(&self) -> Option<&str> {
        self.copyright.clone().map(|r| &self.content[r])
    }
}

struct Emitter {
    notices: Vec<(String, String, Notice)>,
    prefer_links: bool,
}

impl Emitter {
    fn new(prefer_links: bool) -> Self {
        Self {
            notices: vec![(
                "Rust".to_owned(),
                "https://www.rust-lang.org".to_owned(),
                Notice {
                    kind: cmp::min(LicenseKind::Mit, LicenseKind::Apache2_0),
                    text: None,
                },
            )],
            prefer_links,
        }
    }

    fn push(&mut self, package: &Package, notice: Notice) -> crate::Result<()> {
        let name = format!("{} v{}", package.name, package.version);
        let url = if package.source.as_ref().map_or(false, |s| s.is_crates_io()) {
            Ok(format!(
                "https://crates.io/crates/{}/{}",
                package.name, package.version,
            ))
        } else if let Some(repository) = &package.repository {
            Ok(repository.clone())
        } else {
            Err(crate::ErrorKind::MissingCratesIoRegistryOrRepository(
                package.name.clone(),
            ))
        }?;
        self.notices.push((name, url, notice));
        Ok(())
    }

    fn emit_markdown(&self) -> String {
        let mut markdown = "# License and copyright notices\n".to_owned();
        let mut links = indexmap!();

        for (name, url, notice) in &self.notices {
            if !notice.kind.is_public_domain() {
                writeln!(markdown, "\n## [{}]({})", name, url).unwrap();
                match &notice.text {
                    Some(text) if !self.prefer_links => {
                        markdown += "```\n";
                        markdown += &text.content;
                        if !markdown.ends_with('\n') {
                            markdown += "\n";
                        }
                        markdown += "```\n";
                    }
                    _ => {
                        writeln!(markdown, "[{}]", notice.kind.full_name()).unwrap();
                        if let Some(copyright) = notice.text.as_ref().and_then(Text::copyright) {
                            writeln!(markdown, "{}", copyright).unwrap();
                        }
                        links.insert(notice.kind.full_name(), notice.kind.url());
                    }
                }
            }
        }

        if !links.is_empty() {
            markdown += "\n";
            for (full_name, url) in links {
                writeln!(markdown, "[{}]: {}", full_name, url).unwrap();
            }
        }

        markdown
    }
}

#[derive(Debug, Clone)]
struct ProcessContext {
    wd: PathBuf,
}

impl ProcessContext {
    fn status(
        &self,
        arg0: &str,
        args: &[impl AsRef<str> + AsRef<OsStr>],
    ) -> crate::Result<ExitStatus> {
        let Output { status, .. } = self.output(arg0, args, Stdio::null(), Stdio::null())?;
        Ok(status)
    }

    fn check_stdout(
        &self,
        arg0: &str,
        args: &[impl AsRef<str> + AsRef<OsStr>],
    ) -> crate::Result<String> {
        let Output { status, stdout, .. } =
            self.output(arg0, args, Stdio::piped(), Stdio::null())?;

        if status.success() {
            String::from_utf8(stdout).map_err(|e| e.context(crate::ErrorKind::Utf8).into())
        } else {
            let arg0 = arg0.to_owned();
            Err(crate::ErrorKind::ExitedAbnormally { arg0, status }.into())
        }
    }

    fn check_stderr(
        &self,
        arg0: &str,
        args: &[impl AsRef<str> + AsRef<OsStr>],
    ) -> crate::Result<String> {
        let Output { status, stderr, .. } =
            self.output(arg0, args, Stdio::null(), Stdio::piped())?;

        if status.success() {
            String::from_utf8(stderr).map_err(|e| e.context(crate::ErrorKind::Utf8).into())
        } else {
            let arg0 = arg0.to_owned();
            Err(crate::ErrorKind::ExitedAbnormally { arg0, status }.into())
        }
    }

    fn stderr(
        &self,
        arg0: &str,
        args: &[impl AsRef<str> + AsRef<OsStr>],
    ) -> crate::Result<(ExitStatus, String)> {
        let Output { status, stderr, .. } =
            self.output(arg0, args, Stdio::null(), Stdio::piped())?;
        let stderr = String::from_utf8(stderr).with_context(|_| crate::ErrorKind::Utf8)?;
        Ok((status, stderr))
    }

    fn output(
        &self,
        arg0: &str,
        args: &[impl AsRef<str> + AsRef<OsStr>],
        stdout: Stdio,
        stderr: Stdio,
    ) -> crate::Result<Output> {
        info!(
            "`{}{}` in {}",
            arg0,
            args.iter().format_with("", |s, fmt| fmt(&format_args!(
                " {}",
                AsRef::<str>::as_ref(s),
            ))),
            self.wd.display(),
        );

        let output = Command::new(arg0)
            .args(args)
            .current_dir(&self.wd)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .output()
            .with_context(|_| crate::ErrorKind::StartProcess(arg0.to_owned()))?;

        info!("{}", output.status);

        Ok(output)
    }
}

#[derive(Debug, OpaqueTypedefUnsized)]
#[opaque_typedef(derive(Display, Deref, AsRef(Inner, Deref)))]
#[opaque_typedef(deref(target = "Path", deref = "Path::new"))]
#[repr(transparent)]
struct Utf8Path(str);

impl Utf8Path {
    fn new(s: &str) -> &Self {
        unsafe { &*(s as *const str as *const Self) }
    }

    fn with_file_name(&self, file_name: &str) -> Utf8PathBuf {
        let inner = Path::new(&self.0)
            .with_file_name(file_name)
            .into_os_string()
            .into_string()
            .expect("<utf8 path><separator><utf8 filename> should be utf-8");
        Utf8PathBuf(inner)
    }

    fn file_name(&self) -> Option<&str> {
        Path::new(&self.0)
            .file_name()
            .map(|name| name.to_str().expect("the whole path is UTF-8"))
    }

    fn read_dir(&self) -> crate::Result<ReadDir> {
        Path::new(&self.0)
            .read_dir()
            .with_context(|_| crate::ErrorKind::Read {
                path: self.0.to_owned(),
            })
            .map_err(Into::into)
    }
}

impl<'a> TryFrom<&'a Path> for &'a Utf8Path {
    type Error = ();

    fn try_from(path: &'a Path) -> std::result::Result<&'a Utf8Path, ()> {
        path.to_str().map(Utf8Path::new).ok_or(())
    }
}

impl ToOwned for Utf8Path {
    type Owned = Utf8PathBuf;

    fn to_owned(&self) -> Utf8PathBuf {
        Utf8PathBuf(self.0.to_owned())
    }
}

#[derive(Debug, Clone, FromStr, Into, OpaqueTypedef)]
#[opaque_typedef(
    derive(Display, Deref),
    deref(target = "Utf8Path", deref = "Utf8Path::new")
)]
struct Utf8PathBuf(String);

impl TryFrom<PathBuf> for Utf8PathBuf {
    type Error = ();

    fn try_from(path: PathBuf) -> std::result::Result<Self, ()> {
        path.into_os_string()
            .into_string()
            .map(Self)
            .map_err(|_| ())
    }
}

impl Borrow<Utf8Path> for Utf8PathBuf {
    fn borrow(&self) -> &Utf8Path {
        &*self
    }
}

fn read_to_string(path: &Utf8Path) -> crate::Result<String> {
    fs::read_to_string(path)
        .with_context(|_| crate::ErrorKind::Read {
            path: path.to_owned().into(),
        })
        .map_err(Into::into)
}

fn from_json<T: DeserializeOwned>(json: &str, what: &'static str) -> crate::Result<T> {
    serde_json::from_str(json)
        .with_context(|_| crate::ErrorKind::DeserializeJson { what })
        .map_err(Into::into)
}
