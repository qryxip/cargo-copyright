use cargo_copyright::{App, Opt};

use failure::Fail;
use log::LevelFilter;
use structopt::StructOpt as _;
use termcolor::{BufferedStandardStream, WriteColor as _};

use std::io::{self, Write as _};
use std::process;

fn main() -> io::Result<()> {
    let Opt::Copyright(opt) = Opt::from_args();
    let (termcolor_color, env_logger_color) = opt.color.stderr();

    env_logger::Builder::new()
        .filter_module("cargo_copyright", LevelFilter::Info)
        .write_style(env_logger_color)
        .format(|buf, record| {
            let mut black_intense = buf.style();
            black_intense
                .set_color(env_logger::fmt::Color::Black)
                .set_intense(true);
            writeln!(
                buf,
                "{}{}{} {}",
                black_intense.value('['),
                buf.default_styled_level(record.level()),
                black_intense.value(']'),
                record.args(),
            )
        })
        .init();

    match App::try_new().and_then(|mut app| app.run(&opt)) {
        Ok(output) => io::stdout().write_all(output.as_ref()),
        Err(err) => {
            let mut stderr = BufferedStandardStream::stderr(termcolor_color);
            writeln!(stderr)?;
            for (i, cause) in Fail::iter_chain(&err).enumerate() {
                let head = if i == 0 && err.cause().is_none() {
                    "error: "
                } else if i == 0 {
                    "    error: "
                } else {
                    "caused by: "
                };
                stderr.set_color(
                    termcolor::ColorSpec::new()
                        .set_fg(Some(termcolor::Color::Red))
                        .set_bold(true),
                )?;
                stderr.write_all(head.as_ref())?;
                stderr.reset()?;
                for (i, line) in cause.to_string().lines().enumerate() {
                    if i > 0 {
                        (0..head.len()).try_for_each(|_| stderr.write_all(b" "))?;
                    }
                    writeln!(stderr, "{}", line)?;
                }
            }
            let backtrace = err.backtrace().unwrap().to_string();
            if backtrace.is_empty() {
                stderr.write_all(
                    &b"note: Run with `RUST_BACKTRACE=1` environment varialbe to display a \
                       backtrace\n"[..],
                )?;
            } else {
                writeln!(stderr, "{}", backtrace)?;
            }
            stderr.flush()?;
            process::exit(1)
        }
    }
}
