use clap::Subcommand;
use colored::Colorize;

use ant_core::node::daemon::client;
use ant_core::node::types::DaemonConfig;

#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Launch the daemon as a detached background process
    Start,
    /// Shut down the running daemon
    Stop,
    /// Show whether the daemon is running and summary stats
    Status,
    /// Output connection details for programmatic use (always JSON)
    Info,
    /// Run the daemon in the foreground (used internally)
    #[command(hide = true)]
    Run,
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let remaining = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {remaining}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {remaining}s")
    } else if minutes > 0 {
        format!("{minutes}m {remaining}s")
    } else {
        format!("{remaining}s")
    }
}

/// Get the actual port the daemon is listening on.
///
/// The `/api/v1/status` endpoint may report port 0 when the daemon was started
/// with an OS-assigned port (the default). Fall back to reading the port file
/// via `client::info()` which always has the real bound port.
fn resolve_port(config: &DaemonConfig, status_port: Option<u16>) -> Option<u16> {
    match status_port {
        Some(p) if p != 0 => Some(p),
        _ => client::info(config).port,
    }
}

impl DaemonCommand {
    pub async fn execute(self, json_output: bool) -> anyhow::Result<()> {
        let config = DaemonConfig::default();

        match self {
            DaemonCommand::Start => {
                let result = client::start(&config).await?;
                if json_output {
                    println!("{}", serde_json::to_string(&result)?);
                } else if result.already_running {
                    let port = resolve_port(&config, result.port);
                    println!(
                        "{} Node management daemon already running (PID {})",
                        "●".yellow(),
                        result.pid.to_string().bold()
                    );
                    if let Some(p) = port {
                        println!("  {} http://127.0.0.1:{p}/console", "Console".dimmed());
                    }
                } else {
                    let pid = result.pid.to_string().bold();
                    let port = resolve_port(&config, result.port);
                    match port {
                        Some(p) => {
                            println!(
                                "{} Node management daemon started — PID {} on port {}",
                                "✓".green().bold(),
                                pid,
                                p.to_string().cyan()
                            );
                            println!("  {} http://127.0.0.1:{p}/console", "Console".dimmed());
                        }
                        None => println!(
                            "{} Node management daemon started — PID {} (port pending)",
                            "✓".green().bold(),
                            pid
                        ),
                    }
                }
            }
            DaemonCommand::Stop => {
                let result = client::stop(&config).await?;
                if json_output {
                    println!("{}", serde_json::to_string(&result)?);
                } else {
                    println!(
                        "{} Node management daemon stopped (was PID {})",
                        "✓".green().bold(),
                        result.pid.to_string().dimmed()
                    );
                }
            }
            DaemonCommand::Status => {
                let status = client::status(&config).await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                } else if !status.running {
                    println!(
                        "{} Node management daemon is {}",
                        "●".red(),
                        "not running".red().bold()
                    );
                    println!("  Start it with: {}", "ant node daemon start".cyan());
                } else {
                    let port = resolve_port(&config, status.port);

                    println!(
                        "{} Node management daemon is {}",
                        "●".green(),
                        "running".green().bold()
                    );
                    println!();
                    if let Some(pid) = status.pid {
                        println!("  {}      {}", "PID".dimmed(), pid.to_string().bold());
                    }
                    if let Some(p) = port {
                        println!("  {}     {}", "Port".dimmed(), p.to_string().cyan());
                        println!("  {}  http://127.0.0.1:{p}/console", "Console".dimmed());
                    }
                    if let Some(uptime) = status.uptime_secs {
                        println!(
                            "  {}   {}",
                            "Uptime".dimmed(),
                            format_uptime(uptime).white()
                        );
                    }
                    println!();
                    println!(
                        "  {} {} total, {} running, {} stopped, {} errored",
                        "Nodes".dimmed(),
                        status.nodes_total.to_string().bold(),
                        status.nodes_running.to_string().green(),
                        status.nodes_stopped.to_string().yellow(),
                        if status.nodes_errored > 0 {
                            status.nodes_errored.to_string().red()
                        } else {
                            status.nodes_errored.to_string().dimmed()
                        }
                    );
                }
            }
            DaemonCommand::Info => {
                let info = client::info(&config);
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&info)?);
                } else if !info.running {
                    println!(
                        "{} Node management daemon is {}",
                        "●".red(),
                        "not running".red().bold()
                    );
                    println!("  Start it with: {}", "ant node daemon start".cyan());
                } else {
                    println!(
                        "{} Node management daemon is {}",
                        "●".green(),
                        "running".green().bold()
                    );
                    println!();
                    if let Some(pid) = info.pid {
                        println!("  {}      {}", "PID".dimmed(), pid.to_string().bold());
                    }
                    if let Some(port) = info.port {
                        println!("  {}     {}", "Port".dimmed(), port.to_string().cyan());
                        println!("  {}  http://127.0.0.1:{port}/console", "Console".dimmed());
                    }
                    if let Some(ref api_base) = info.api_base {
                        println!("  {} {}", "API".dimmed(), api_base.cyan());
                    }
                }
            }
            DaemonCommand::Run => {
                client::run(config).await?;
            }
        }

        Ok(())
    }
}
