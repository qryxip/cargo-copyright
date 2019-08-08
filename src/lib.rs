#![recursion_limit = "128"]

use cargo_metadata::{Metadata, Package, PackageId, Target};
use derive_more::{Deref, Display, From, FromStr, Into};
use failure::{Backtrace, Fail, ResultExt as _};
use filetime::FileTime;
use fixedbitset::FixedBitSet;
use if_chain::if_chain;
use indexmap::indexset;
use itertools::Itertools as _;
use log::info;
use maplit::btreeset;
use once_cell::sync::Lazy;
use opaque_typedef_macros::{OpaqueTypedef, OpaqueTypedefUnsized};
use regex::{Match, Regex};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use structopt::StructOpt;
use strum_macros::{EnumString, IntoStaticStr};
use typed_html::dom::DOMTree;
use typed_html::{html, text};

use std::borrow::{Borrow, Cow};
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
    #[structopt(long = "exclude-unused", help = "Exclude unused crates")]
    exclude_unused: bool,
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

        let mut emitter = Emitter::new();
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
    copyright: Option<String>,
}

impl Notice {
    fn read_from_package(package: &Package) -> crate::Result<Self> {
        let license = package
            .license
            .as_ref()
            .ok_or_else(|| crate::ErrorKind::MissingLicense(package.name.clone()))?;

        let kind = LicenseKind::try_from_short_identifiers(license).ok_or_else(|| {
            crate::ErrorKind::UnsupportedLicense(package.name.clone(), license.clone())
        })?;

        let path = if_chain! {
            if let Some(dir) = package.manifest_path.parent();
            let dir = <&Utf8Path>::try_from(dir).expect("this is from JSON").to_owned();
            if let Some(path) = dir
                .read_dir()?
                .flatten()
                .filter(|entry| entry.metadata().is_ok() && {
                    let path = entry.path();
                    let file_name = path.file_name().unwrap_or_default();
                    path.is_file() && file_name.to_str().map_or(false, kind.filename_pattern())
                })
                .map(|e| e.path())
                .next();
            then {
                Some(Utf8PathBuf::try_from(path)
                    .expect("<utf8 dir><separator><utf8 filename> should be UTF-8"))
            } else {
                None
            }
        };

        let copyright = path
            .as_ref()
            .map(|p| crate::read_to_string(p))
            .transpose()?
            .and_then(|s| kind.capture_copyright(&s).map(|m| m.as_str().to_owned()));

        info!(
            "{} v{}: {:?} → ({:?}, {:?})",
            package.name,
            package.version,
            license,
            kind,
            path.as_ref().map(|p| p.file_name().unwrap()),
        );
        Ok(Self { kind, copyright })
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
    fn try_from_short_identifiers(identifiers: &str) -> Option<Self> {
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

        try_from_short_identifier(identifiers).or_else(|| {
            if identifiers.contains('/') {
                min(identifiers, "/")
            } else if identifiers.contains("OR") {
                min(identifiers, "OR")
            } else {
                None
            }
        })
    }

    fn github_style_tag_id(self) -> &'static str {
        match self {
            LicenseKind::Mit => "mit-license",
            LicenseKind::Apache2_0 => "apache-license-20",
            LicenseKind::Bsd3Clause => "bsd-3-clause-new-or-revised-license",
            LicenseKind::Mpl2_0 => "mozilla-public-license-20",
            LicenseKind::Isc => "isc-license",
            LicenseKind::CC0_1_0 => "creative-commons-zero-v10-universal",
            LicenseKind::Unlicense => "the-unlicense",
            LicenseKind::Wtfpl => "do-what-the-fck-you-want-to-public-license",
        }
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
            LicenseKind::Apache2_0 => "https://www.apache.org/licenses/LICENSE-2.0",
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

    fn filename_pattern(self) -> fn(&str) -> bool {
        match self {
            LicenseKind::Mit => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-mit)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Apache2_0 => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-apache)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Bsd3Clause => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-bsd)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Mpl2_0 => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-mpl)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Isc => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-isc)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::CC0_1_0 => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-cc)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Unlicense => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-unlicense)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
            LicenseKind::Wtfpl => {
                static REGEX: Lazy<Regex> = lazy_regex!(r"\A(?i)(license(-wtfpl)?(\.txt)?)\z");
                |s| REGEX.is_match(s)
            }
        }
    }

    fn capture_copyright(self, text: &str) -> Option<Match> {
        match self {
            LicenseKind::Mit => mit_copyright(text),
            LicenseKind::Apache2_0 => apache_2_0_copyright(text),
            LicenseKind::Bsd3Clause => bsd_3_clause_copyright(text),
            LicenseKind::Mpl2_0 => None,
            LicenseKind::Isc => None,
            LicenseKind::CC0_1_0 => None,
            LicenseKind::Unlicense => None,
            LicenseKind::Wtfpl => None,
        }
    }

    fn text(self) -> &'static str {
        match self {
            LicenseKind::Mit => MIT_TEXT,
            LicenseKind::Apache2_0 => APACHE_2_0_TEXT,
            LicenseKind::Bsd3Clause => BSD_3_CLAUSE_TEXT,
            LicenseKind::Mpl2_0 => MPL_2_0_TEXT,
            LicenseKind::Isc => ISC_TEXT,
            LicenseKind::CC0_1_0 => "\n",
            LicenseKind::Unlicense => "\n",
            LicenseKind::Wtfpl => "\n",
        }
    }

    fn is_public_domain(self) -> bool {
        match self {
            LicenseKind::CC0_1_0 | LicenseKind::Unlicense | LicenseKind::Wtfpl => true,
            _ => false,
        }
    }
}

struct Emitter {
    notices: Vec<(String, String, Notice)>,
}

impl Emitter {
    fn new() -> Self {
        Self {
            notices: vec![(
                "Rust".to_owned(),
                "https://www.rust-lang.org".to_owned(),
                Notice {
                    kind: LicenseKind::Mit,
                    // https://github.com/rust-lang/rust/commit/2a8807e889a43c6b89eb6f2736907afa87ae592f
                    copyright: None,
                },
            )],
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
        let mut kinds = indexset!();

        for (name, url, notice) in &self.notices {
            if !notice.kind.is_public_domain() {
                writeln!(markdown, "\n## [{}]({})\n", name, url).unwrap();
                if let Some(copyright) = &notice.copyright {
                    writeln!(markdown, "{}\n", copyright).unwrap();
                }
                writeln!(
                    markdown,
                    "[{}](#{})",
                    notice.kind.full_name(),
                    notice.kind.github_style_tag_id(),
                )
                .unwrap();
                kinds.insert(notice.kind);
            }
        }

        if !kinds.is_empty() {
            for kind in kinds {
                let header: DOMTree<String> = html!(
                    <h2 id={ kind.github_style_tag_id() }>
                      <a href={ kind.url() }>{ text!("{}", kind.full_name()) }</a>
                    </h2>
                );
                writeln!(markdown, "\n{}\n\n```\n{}```", header, kind.text()).unwrap();
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

static MIT_TEXT: &str = r#"Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"#;

fn mit_copyright(content: &str) -> Option<Match> {
    static COPYRIGHT: Lazy<Regex> = Lazy::new(|| {
        let mut acc = "(Copyright.*)".to_owned();
        for paragraph in MIT_TEXT.split("\n\n") {
            write!(
                acc,
                "\n{{2,}}{}",
                paragraph
                    .split(' ')
                    .map(|word| {
                        let mut word = Cow::Borrowed(word.trim());
                        if word.contains('.') {
                            word = Cow::Owned(word.replace('.', "\\."));
                        }
                        if word.contains('(') {
                            word = Cow::Owned(word.replace('(', "\\("));
                        }
                        if word.contains(')') {
                            word = Cow::Owned(word.replace(')', "\\)"));
                        }
                        word
                    })
                    .format("[\\s\n]+"),
            )
            .unwrap();
        }
        Regex::new(&acc).unwrap()
    });

    COPYRIGHT.captures(content).map(|caps| caps.get(1).unwrap())
}

static APACHE_2_0_TEXT: &str = r#"Apache License

Version 2.0, January 2004

http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity. For the purposes of this definition, "control" means (i) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.

"You" (or "Your") shall mean an individual or Legal Entity exercising permissions granted by this License.

"Source" form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.

"Object" form shall mean any form resulting from mechanical transformation or translation of a Source form, including but not limited to compiled object code, generated documentation, and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or Object form, made available under the License, as indicated by a copyright notice that is included in or attached to the work (an example is provided in the Appendix below).

"Derivative Works" shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof.

"Contribution" shall mean any work of authorship, including the original version of the Work and any modifications or additions to that Work or Derivative Works thereof, that is intentionally submitted to Licensor for inclusion in the Work by the copyright owner or by an individual or Legal Entity authorized to submit on behalf of the copyright owner. For the purposes of this definition, "submitted" means any form of electronic, verbal, or written communication sent to the Licensor or its representatives, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the Licensor for the purpose of discussing and improving the Work, but excluding communication that is conspicuously marked or otherwise designated in writing by the copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal Entity on behalf of whom a Contribution has been received by Licensor and subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated in this section) patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work, where such license applies only to those patent claims licensable by such Contributor that are necessarily infringed by their Contribution(s) alone or by combination of their Contribution(s) with the Work to which such Contribution(s) was submitted. If You institute patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Work or a Contribution incorporated within the Work constitutes direct or contributory patent infringement, then any patent licenses granted to You under this License for that Work shall terminate as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the Work or Derivative Works thereof in any medium, with or without modifications, and in Source or Object form, provided that You meet the following conditions:

    You must give any other recipients of the Work or Derivative Works a copy of this License; and
    You must cause any modified files to carry prominent notices stating that You changed the files; and
    You must retain, in the Source form of any Derivative Works that You distribute, all copyright, patent, trademark, and attribution notices from the Source form of the Work, excluding those notices that do not pertain to any part of the Derivative Works; and
    If the Work includes a "NOTICE" text file as part of its distribution, then any Derivative Works that You distribute must include a readable copy of the attribution notices contained within such NOTICE file, excluding those notices that do not pertain to any part of the Derivative Works, in at least one of the following places: within a NOTICE text file distributed as part of the Derivative Works; within the Source form or documentation, if provided along with the Derivative Works; or, within a display generated by the Derivative Works, if and wherever such third-party notices normally appear. The contents of the NOTICE file are for informational purposes only and do not modify the License. You may add Your own attribution notices within Derivative Works that You distribute, alongside or as an addendum to the NOTICE text from the Work, provided that such additional attribution notices cannot be construed as modifying the License.

    You may add Your own copyright statement to Your modifications and may provide additional or different license terms and conditions for use, reproduction, or distribution of Your modifications, or for any such Derivative Works as a whole, provided Your use, reproduction, and distribution of the Work otherwise complies with the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state otherwise, any Contribution intentionally submitted for inclusion in the Work by You to the Licensor shall be under the terms and conditions of this License, without any additional terms or conditions. Notwithstanding the above, nothing herein shall supersede or modify the terms of any separate license agreement you may have executed with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall any Contributor be liable to You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this License or out of the use or inability to use the Work (including but not limited to damages for loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses), even if such Contributor has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing the Work or Derivative Works thereof, You may choose to offer, and charge a fee for, acceptance of support, warranty, indemnity, or other liability obligations and/or rights consistent with this License. However, in accepting such obligations, You may act only on Your own behalf and on Your sole responsibility, not on behalf of any other Contributor, and only if You agree to indemnify, defend, and hold each Contributor harmless for any liability incurred by, or claims asserted against, such Contributor by reason of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS

APPENDIX: How to apply the Apache License to your work.

To apply the Apache License to your work, attach the following boilerplate notice, with the fields enclosed by brackets "[]" replaced with your own identifying information. (Don't include the brackets!) The text should be enclosed in the appropriate comment syntax for the file format. We also recommend that a file or class name and description of purpose be included on the same "printed page" as the copyright notice for easier identification within third-party archives.

Copyright [yyyy] [name of copyright owner]

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
"#;

fn apache_2_0_copyright(content: &str) -> Option<Match> {
    static COPYRIGHT: Lazy<Regex> = Lazy::new(|| {
        let mut acc = r#"(Copyright\s+[0-9].*)"#.to_owned();
        let paragraphs = APACHE_2_0_TEXT
            .split("Copyright [yyyy] [name of copyright owner]\n\n")
            .nth(1)
            .unwrap();
        for paragraph in paragraphs.split("\n\n") {
            write!(
                acc,
                "\n{{2,}}{}",
                paragraph
                    .split(' ')
                    .map(|word| {
                        let mut word = Cow::Borrowed(word.trim());
                        if word.contains('.') {
                            word = Cow::Owned(word.replace('.', "\\."));
                        }
                        if word.contains('[') {
                            word = Cow::Owned(word.replace('[', "\\["));
                        }
                        if word.contains(']') {
                            word = Cow::Owned(word.replace(']', "\\]"));
                        }
                        if word.contains('(') {
                            word = Cow::Owned(word.replace('(', "\\("));
                        }
                        if word.contains(')') {
                            word = Cow::Owned(word.replace(')', "\\)"));
                        }
                        word
                    })
                    .format("[\\s\n]+"),
            )
            .unwrap();
        }
        Regex::new(&acc).unwrap()
    });

    COPYRIGHT.captures(content).map(|caps| caps.get(1).unwrap())
}

static BSD_3_CLAUSE_TEXT: &str = r#"Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"#;

fn bsd_3_clause_copyright(content: &str) -> Option<Match> {
    static COPYRIGHT: Lazy<Regex> = Lazy::new(|| {
        let mut acc = "(Copyright.*)".to_owned();
        for paragraph in BSD_3_CLAUSE_TEXT.split("\n\n") {
            write!(
                acc,
                "\n{{2,}}{}",
                paragraph
                    .split(' ')
                    .map(|word| {
                        let mut word = Cow::Borrowed(word.trim());
                        if word.contains('.') {
                            word = Cow::Owned(word.replace('.', "\\."));
                        }
                        if word.contains('(') {
                            word = Cow::Owned(word.replace('(', "\\("));
                        }
                        if word.contains(')') {
                            word = Cow::Owned(word.replace(')', "\\)"));
                        }
                        word
                    })
                    .format("[\\s\n]+"),
            )
            .unwrap();
        }
        Regex::new(&acc).unwrap()
    });

    COPYRIGHT.captures(content).map(|caps| caps.get(1).unwrap())
}

static MPL_2_0_TEXT: &str = r#"Mozilla Public License Version 2.0

    1. Definitions
        1.1. "Contributor" means each individual or legal entity that creates, contributes to the creation of, or owns Covered Software.
        1.2. "Contributor Version" means the combination of the Contributions of others (if any) used by a Contributor and that particular Contributor's Contribution.
        1.3. "Contribution" means Covered Software of a particular Contributor.
        1.4. "Covered Software" means Source Code Form to which the initial Contributor has attached the notice in Exhibit A, the Executable Form of such Source Code Form, and Modifications of such Source Code Form, in each case including portions thereof.
        1.5. "Incompatible With Secondary Licenses" means
            (a) that the initial Contributor has attached the notice described in Exhibit B to the Covered Software; or
            (b) that the Covered Software was made available under the terms of version 1.1 or earlier of the License, but not also under the terms of a Secondary License.
        1.6. "Executable Form" means any form of the work other than Source Code Form.
        1.7. "Larger Work" means a work that combines Covered Software with other material, in a separate file or files, that is not Covered Software.
        1.8. "License" means this document.
        1.9. "Licensable" means having the right to grant, to the maximum extent possible, whether at the time of the initial grant or subsequently, any and all of the rights conveyed by this License.
        1.10. "Modifications" means any of the following:
            (a) any file in Source Code Form that results from an addition to, deletion from, or modification of the contents of Covered Software; or
            (b) any new file in Source Code Form that contains any Covered Software.
        1.11. "Patent Claims" of a Contributor means any patent claim(s), including without limitation, method, process, and apparatus claims, in any patent Licensable by such Contributor that would be infringed, but for the grant of the License, by the making, using, selling, offering for sale, having made, import, or transfer of either its Contributions or its Contributor Version.
        1.12. "Secondary License" means either the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero General Public License, Version 3.0, or any later versions of those licenses.
        1.13. "Source Code Form" means the form of the work preferred for making modifications.
        1.14. "You" (or "Your") means an individual or a legal entity exercising rights under this License. For legal entities, "You" includes any entity that controls, is controlled by, or is under common control with You. For purposes of this definition, "control" means (a) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (b) ownership of more than fifty percent (50%) of the outstanding shares or beneficial ownership of such entity.
    2. License Grants and Conditions
        2.1. Grants

        Each Contributor hereby grants You a world-wide, royalty-free, non-exclusive license:
            (a) under intellectual property rights (other than patent or trademark) Licensable by such Contributor to use, reproduce, make available, modify, display, perform, distribute, and otherwise exploit its Contributions, either on an unmodified basis, with Modifications, or as part of a Larger Work; and
            (b) under Patent Claims of such Contributor to make, use, sell, offer for sale, have made, import, and otherwise transfer either its Contributions or its Contributor Version.
        2.2. Effective Date

        The licenses granted in Section 2.1 with respect to any Contribution become effective for each Contribution on the date the Contributor first distributes such Contribution.
        2.3. Limitations on Grant Scope

        The licenses granted in this Section 2 are the only rights granted under this License. No additional rights or licenses will be implied from the distribution or licensing of Covered Software under this License. Notwithstanding Section 2.1(b) above, no patent license is granted by a Contributor:
            (a) for any code that a Contributor has removed from Covered Software; or
            (b) for infringements caused by: (i) Your and any other third party's modifications of Covered Software, or (ii) the combination of its Contributions with other software (except as part of its Contributor Version); or
            (c) under Patent Claims infringed by Covered Software in the absence of its Contributions.

        This License does not grant any rights in the trademarks, service marks, or logos of any Contributor (except as may be necessary to comply with the notice requirements in Section 3.4).
        2.4. Subsequent Licenses

        No Contributor makes additional grants as a result of Your choice to distribute the Covered Software under a subsequent version of this License (see Section 10.2) or under the terms of a Secondary License (if permitted under the terms of Section 3.3).
        2.5. Representation

        Each Contributor represents that the Contributor believes its Contributions are its original creation(s) or it has sufficient rights to grant the rights to its Contributions conveyed by this License.
        2.6. Fair Use

        This License is not intended to limit any rights You have under applicable copyright doctrines of fair use, fair dealing, or other equivalents.
        2.7. Conditions

        Sections 3.1, 3.2, 3.3, and 3.4 are conditions of the licenses granted in Section 2.1.
    3. Responsibilities
        3.1. Distribution of Source Form

        All distribution of Covered Software in Source Code Form, including any Modifications that You create or to which You contribute, must be under the terms of this License. You must inform recipients that the Source Code Form of the Covered Software is governed by the terms of this License, and how they can obtain a copy of this License. You may not attempt to alter or restrict the recipients' rights in the Source Code Form.
        3.2. Distribution of Executable Form

        If You distribute Covered Software in Executable Form then:
            (a) such Covered Software must also be made available in Source Code Form, as described in Section 3.1, and You must inform recipients of the Executable Form how they can obtain a copy of such Source Code Form by reasonable means in a timely manner, at a charge no more than the cost of distribution to the recipient; and
            (b) You may distribute such Executable Form under the terms of this License, or sublicense it under different terms, provided that the license for the Executable Form does not attempt to limit or alter the recipients' rights in the Source Code Form under this License.
        3.3. Distribution of a Larger Work

        You may create and distribute a Larger Work under terms of Your choice, provided that You also comply with the requirements of this License for the Covered Software. If the Larger Work is a combination of Covered Software with a work governed by one or more Secondary Licenses, and the Covered Software is not Incompatible With Secondary Licenses, this License permits You to additionally distribute such Covered Software under the terms of such Secondary License(s), so that the recipient of the Larger Work may, at their option, further distribute the Covered Software under the terms of either this License or such Secondary License(s).
        3.4. Notices

        You may not remove or alter the substance of any license notices (including copyright notices, patent notices, disclaimers of warranty, or limitations of liability) contained within the Source Code Form of the Covered Software, except that You may alter any license notices to the extent required to remedy known factual inaccuracies.
        3.5. Application of Additional Terms

        You may choose to offer, and to charge a fee for, warranty, support, indemnity or liability obligations to one or more recipients of Covered Software. However, You may do so only on Your own behalf, and not on behalf of any Contributor. You must make it absolutely clear that any such warranty, support, indemnity, or liability obligation is offered by You alone, and You hereby agree to indemnify every Contributor for any liability incurred by such Contributor as a result of warranty, support, indemnity or liability terms You offer. You may include additional disclaimers of warranty and limitations of liability specific to any jurisdiction.
    4. Inability to Comply Due to Statute or Regulation

    If it is impossible for You to comply with any of the terms of this License with respect to some or all of the Covered Software due to statute, judicial order, or regulation then You must: (a) comply with the terms of this License to the maximum extent possible; and (b) describe the limitations and the code they affect. Such description must be placed in a text file included with all distributions of the Covered Software under this License. Except to the extent prohibited by statute or regulation, such description must be sufficiently detailed for a recipient of ordinary skill to be able to understand it.
    5. Termination
        5.1. The rights granted under this License will terminate automatically if You fail to comply with any of its terms. However, if You become compliant, then the rights granted under this License from a particular Contributor are reinstated (a) provisionally, unless and until such Contributor explicitly and finally terminates Your grants, and (b) on an ongoing basis, if such Contributor fails to notify You of the non-compliance by some reasonable means prior to 60 days after You have come back into compliance. Moreover, Your grants from a particular Contributor are reinstated on an ongoing basis if such Contributor notifies You of the non-compliance by some reasonable means, this is the first time You have received notice of non-compliance with this License from such Contributor, and You become compliant prior to 30 days after Your receipt of the notice.
        5.2. If You initiate litigation against any entity by asserting a patent infringement claim (excluding declaratory judgment actions, counter-claims, and cross-claims) alleging that a Contributor Version directly or indirectly infringes any patent, then the rights granted to You by any and all Contributors for the Covered Software under Section 2.1 of this License shall terminate.
        5.3. In the event of termination under Sections 5.1 or 5.2 above, all end user license agreements (excluding distributors and resellers) which have been validly granted by You or Your distributors under this License prior to termination shall survive termination.
    6. Disclaimer of Warranty

    Covered Software is provided under this License on an "as is" basis, without warranty of any kind, either expressed, implied, or statutory, including, without limitation, warranties that the Covered Software is free of defects, merchantable, fit for a particular purpose or non-infringing. The entire risk as to the quality and performance of the Covered Software is with You. Should any Covered Software prove defective in any respect, You (not any Contributor) assume the cost of any necessary servicing, repair, or correction. This disclaimer of warranty constitutes an essential part of this License. No use of any Covered Software is authorized under this License except under this disclaimer.
    7. Limitation of Liability

    Under no circumstances and under no legal theory, whether tort (including negligence), contract, or otherwise, shall any Contributor, or anyone who distributes Covered Software as permitted above, be liable to You for any direct, indirect, special, incidental, or consequential damages of any character including, without limitation, damages for lost profits, loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses, even if such party shall have been informed of the possibility of such damages. This limitation of liability shall not apply to liability for death or personal injury resulting from such party's negligence to the extent applicable law prohibits such limitation. Some jurisdictions do not allow the exclusion or limitation of incidental or consequential damages, so this exclusion and limitation may not apply to You.
    8. Litigation

    Any litigation relating to this License may be brought only in the courts of a jurisdiction where the defendant maintains its principal place of business and such litigation shall be governed by laws of that jurisdiction, without reference to its conflict-of-law provisions. Nothing in this Section shall prevent a party's ability to bring cross-claims or counter-claims.
    9. Miscellaneous

    This License represents the complete agreement concerning the subject matter hereof. If any provision of this License is held to be unenforceable, such provision shall be reformed only to the extent necessary to make it enforceable. Any law or regulation which provides that the language of a contract shall be construed against the drafter shall not be used to construe this License against a Contributor.
    10. Versions of the License
        10.1. New Versions

        Mozilla Foundation is the license steward. Except as provided in Section 10.3, no one other than the license steward has the right to modify or publish new versions of this License. Each version will be given a distinguishing version number.
        10.2. Effect of New Versions

        You may distribute the Covered Software under the terms of the version of the License under which You originally received the Covered Software, or under the terms of any subsequent version published by the license steward.
        10.3. Modified Versions

        If you create software not governed by this License, and you want to create a new license for such software, you may create and use a modified version of this License if you rename the license and remove any references to the name of the license steward (except to note that such modified license differs from this License).
        10.4. Distributing Source Code Form that is Incompatible With Secondary Licenses

        If You choose to distribute Source Code Form that is Incompatible With Secondary Licenses under the terms of this version of the License, the notice described in Exhibit B of this License must be attached.

Exhibit A - Source Code Form License Notice

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

If it is not possible or desirable to put the notice in a particular file, then You may include the notice in a location (such as a LICENSE file in a relevant directory) where a recipient would be likely to look for such a notice.

You may add additional accurate notices of copyright ownership.

Exhibit B - "Incompatible With Secondary Licenses" Notice

This Source Code Form is "Incompatible With Secondary Licenses", as defined by the Mozilla Public License, v. 2.0.
"#;

static ISC_TEXT: &str = r#"Copyright © 2004-2013 by Internet Systems Consortium, Inc. (“ISC”)
Copyright © 1995-2003 by Internet Software Consortium

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND ISC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"#;
