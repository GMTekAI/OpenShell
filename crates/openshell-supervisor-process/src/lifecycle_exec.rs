// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authenticated product lifecycle execution over the supervisor relay.
//!
//! This is not an SSH mode and exposes no listener. The gateway selects the
//! internal relay target after user authorization; the supervisor independently
//! revalidates the compiled operation, policy grant, payload, fixed-path contract,
//! pinned executable/interpreter, and workload identity before spawning.
//! Root ownership and FD pinning prevent runtime workload replacement; they do
//! not attest image provenance, and the child receives no extra authority.

#[cfg(target_os = "linux")]
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::RawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{ffi::CString, mem::size_of, path::PathBuf};

use miette::{IntoDiagnostic as _, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::{Gid, Group, Pid, Uid, User};
#[cfg(target_os = "linux")]
use openshell_core::lifecycle_exec::{
    LIFECYCLE_AUTH_FD_ENV, NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE,
};
use openshell_core::lifecycle_exec::{
    LifecycleOperationSpec, MAX_LIFECYCLE_TIMEOUT_SECONDS, operation_for_command,
    validate_operation_command,
};
use openshell_core::policy::SandboxPolicy;
use openshell_core::proto::{
    LifecycleExecRelayEvent, LifecycleExecRelayRequest, lifecycle_exec_relay_event,
};
use prost::Message;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Child;
#[cfg(target_os = "linux")]
use tokio::process::Command;

const MAX_RELAY_FRAME: usize = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MINIMAL_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleIdentity {
    uid: Uid,
    primary_gid: Gid,
}

pub async fn serve(
    mut stream: tokio::io::DuplexStream,
    policy: SandboxPolicy,
    netns_fd: Option<RawFd>,
) -> Result<()> {
    let request = match read_message::<LifecycleExecRelayRequest>(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            return reject_pre_spawn(
                &mut stream,
                miette::miette!("lifecycle relay closed before its request"),
            )
            .await;
        }
        Err(error) => return reject_pre_spawn(&mut stream, error).await,
    };

    let prepared = (|| {
        let operation = validate_request(&policy, &request)?;
        let identity = resolve_lifecycle_identity(&policy)?;
        let pinned = PinnedOperation::open(operation)?;
        Ok::<_, miette::Report>((operation, identity, pinned))
    })();
    let (operation, identity, pinned) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return reject_pre_spawn(&mut stream, error).await,
    };
    let mut spawned =
        match spawn_lifecycle_child(&policy, &request.command, identity, pinned, netns_fd) {
            Ok(spawned) => spawned,
            Err(error) => return reject_pre_spawn(&mut stream, error).await,
        };
    if let Err(error) = spawned.authenticate(operation) {
        if let Some(pid) = spawned.child.id() {
            kill_process_group(&mut spawned.child, pid).await;
        }
        return reject_pre_spawn(&mut stream, error).await;
    }
    relay_child(stream, spawned.child, request.timeout_seconds).await
}

async fn reject_pre_spawn(
    stream: &mut tokio::io::DuplexStream,
    error: miette::Report,
) -> Result<()> {
    let mut message = error.to_string();
    if message.len() > 512 {
        let mut end = 512;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    let _ = write_event(stream, lifecycle_exec_relay_event::Payload::Error(message)).await;
    Err(error)
}

async fn relay_child(
    stream: tokio::io::DuplexStream,
    mut child: Child,
    timeout_seconds: u32,
) -> Result<()> {
    let pid = child
        .id()
        .ok_or_else(|| miette::miette!("lifecycle child has no process id"))?;

    let (mut relay_read, mut relay_write) = tokio::io::split(stream);
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| miette::miette!("lifecycle stdout pipe is missing"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| miette::miette!("lifecycle stderr pipe is missing"))?;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let timeout = tokio::time::sleep(Duration::from_secs(u64::from(timeout_seconds)));
    tokio::pin!(timeout);
    let mut stdout_buffer = vec![0u8; 16 * 1024];
    let mut stderr_buffer = vec![0u8; 16 * 1024];
    let mut unexpected = [0u8; 1];
    let mut exit_code = None;
    let mut timeout_fired = false;

    loop {
        if let Some(exit_code) = exit_code
            && stdout_done
            && stderr_done
        {
            write_event(
                &mut relay_write,
                lifecycle_exec_relay_event::Payload::ExitCode(exit_code),
            )
            .await?;
            return Ok(());
        }

        tokio::select! {
            read = stdout.read(&mut stdout_buffer), if !stdout_done => {
                let read = match read {
                    Ok(read) => read,
                    Err(error) => {
                        kill_process_group(&mut child, pid).await;
                        return Err(error).into_diagnostic();
                    }
                };
                match read {
                    0 => stdout_done = true,
                    count => {
                        if let Err(error) = write_event(
                            &mut relay_write,
                            lifecycle_exec_relay_event::Payload::Stdout(stdout_buffer[..count].to_vec()),
                        ).await {
                            kill_process_group(&mut child, pid).await;
                            return Err(error);
                        }
                    }
                }
            }
            read = stderr.read(&mut stderr_buffer), if !stderr_done => {
                let read = match read {
                    Ok(read) => read,
                    Err(error) => {
                        kill_process_group(&mut child, pid).await;
                        return Err(error).into_diagnostic();
                    }
                };
                match read {
                    0 => stderr_done = true,
                    count => {
                        if let Err(error) = write_event(
                            &mut relay_write,
                            lifecycle_exec_relay_event::Payload::Stderr(stderr_buffer[..count].to_vec()),
                        ).await {
                            kill_process_group(&mut child, pid).await;
                            return Err(error);
                        }
                    }
                }
            }
            status = child.wait(), if exit_code.is_none() => {
                match status {
                    Ok(status) => {
                        exit_code = Some(status.code().unwrap_or(1));
                        // A helper must not leave detached work in its process
                        // group after the leader exits.
                        let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
                        let _ = signal::killpg(Pid::from_raw(raw_pid), Signal::SIGKILL);
                    }
                    Err(error) => {
                        kill_process_group(&mut child, pid).await;
                        return Err(error).into_diagnostic();
                    }
                }
            }
            () = &mut timeout, if !timeout_fired => {
                timeout_fired = true;
                kill_process_group(&mut child, pid).await;
                exit_code = Some(124);
            }
            read = relay_read.read(&mut unexpected) => {
                let read = match read {
                    Ok(read) => read,
                    Err(error) => {
                        kill_process_group(&mut child, pid).await;
                        return Err(error).into_diagnostic();
                    }
                };
                if read == 0 {
                    kill_process_group(&mut child, pid).await;
                    return Err(miette::miette!("lifecycle relay cancelled"));
                }
                kill_process_group(&mut child, pid).await;
                let _ = write_event(
                    &mut relay_write,
                    lifecycle_exec_relay_event::Payload::Error(
                        "unexpected lifecycle relay payload".to_string(),
                    ),
                ).await;
                return Err(miette::miette!("unexpected lifecycle relay payload"));
            }
        }
    }
}

fn validate_request(
    policy: &SandboxPolicy,
    request: &LifecycleExecRelayRequest,
) -> Result<&'static LifecycleOperationSpec> {
    let operation = operation_for_command(&request.command)
        .ok_or_else(|| miette::miette!("command is not a compiled lifecycle operation"))?;
    validate_operation_command(operation, &request.command)
        .map_err(|error| miette::miette!(error))?;
    if request.timeout_seconds == 0 || request.timeout_seconds > MAX_LIFECYCLE_TIMEOUT_SECONDS {
        return Err(miette::miette!(
            "lifecycle timeout must be between 1 and {} seconds",
            MAX_LIFECYCLE_TIMEOUT_SECONDS
        ));
    }
    if !policy
        .process
        .lifecycle_operations
        .iter()
        .any(|allowed| allowed == operation.id)
    {
        return Err(miette::miette!(
            "lifecycle operation '{}' is not granted by process policy",
            operation.id
        ));
    }
    Ok(operation)
}

fn resolve_lifecycle_identity(policy: &SandboxPolicy) -> Result<LifecycleIdentity> {
    let user_name = policy.process.run_as_user.as_deref().unwrap_or("sandbox");
    let user = User::from_name(user_name)
        .into_diagnostic()?
        .ok_or_else(|| miette::miette!("workload user '{user_name}' does not exist"))?;
    let primary_group = match policy.process.run_as_group.as_deref() {
        Some(group_name) => Group::from_name(group_name)
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("workload group '{group_name}' does not exist"))?,
        None => Group::from_gid(user.gid)
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("workload primary group does not exist"))?,
    };
    validate_identity_values(user.uid.as_raw(), primary_group.gid.as_raw())?;
    Ok(LifecycleIdentity {
        uid: user.uid,
        primary_gid: primary_group.gid,
    })
}

fn validate_identity_values(uid: u32, primary_gid: u32) -> Result<()> {
    if uid == 0 || primary_gid == 0 {
        return Err(miette::miette!(
            "lifecycle workload identity must resolve to nonzero uid and gid"
        ));
    }
    Ok(())
}

struct PinnedOperation {
    #[cfg(target_os = "linux")]
    script: std::fs::File,
    #[cfg(target_os = "linux")]
    interpreter: std::fs::File,
    #[cfg(target_os = "linux")]
    interpreter_argv0: String,
}

impl PinnedOperation {
    fn open(operation: &LifecycleOperationSpec) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = operation;
            Err(miette::miette!(
                "lifecycle exec requires Linux openat2 semantics"
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let mut script = open_pinned(Path::new(operation.executable), false)?;
            validate_pinned_file(&script, operation.executable)?;
            let interpreter_argv0 = read_shebang_interpreter(&mut script)?;
            let interpreter = open_pinned(Path::new(&interpreter_argv0), true)?;
            validate_pinned_file(&interpreter, &interpreter_argv0)?;

            Ok(Self {
                script,
                interpreter,
                interpreter_argv0,
            })
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn open_pinned(path: &Path, allow_symlinks: bool) -> Result<std::fs::File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    validate_root_owned_components(path, allow_symlinks)?;
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| miette::miette!("lifecycle path contains a null byte"))?;
    let how = OpenHow {
        flags: u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC).unwrap_or_default(),
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS
            | if allow_symlinks {
                0
            } else {
                RESOLVE_NO_SYMLINKS
            },
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let fd = i32::try_from(fd).map_err(|_| miette::miette!("openat2 returned an invalid fd"))?;
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn validate_root_owned_components(path: &Path, allow_symlinks: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.is_absolute() {
        return Err(miette::miette!("lifecycle path must be absolute"));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        let std::path::Component::Normal(component) = component else {
            return Err(miette::miette!("lifecycle path must be canonical"));
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).into_diagnostic()?;
        if metadata.file_type().is_symlink() {
            if !allow_symlinks || metadata.uid() != 0 {
                return Err(miette::miette!(
                    "lifecycle path contains an untrusted symlink: {}",
                    current.display()
                ));
            }
        } else if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(miette::miette!(
                "lifecycle path component is not root-owned and non-writable: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_pinned_file(file: &std::fs::File, display: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().into_diagnostic()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(miette::miette!(
            "pinned lifecycle file is not root-owned, non-writable, and executable: {display}"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_shebang_interpreter(script: &mut std::fs::File) -> Result<String> {
    script.seek(SeekFrom::Start(0)).into_diagnostic()?;
    let mut prefix = [0u8; 512];
    let count = script.read(&mut prefix).into_diagnostic()?;
    script.seek(SeekFrom::Start(0)).into_diagnostic()?;
    if !prefix[..count].starts_with(b"#!") {
        return Err(miette::miette!(
            "lifecycle operation must be an exact shebang script"
        ));
    }
    let line_end = prefix[..count]
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(count);
    let shebang = std::str::from_utf8(&prefix[2..line_end])
        .into_diagnostic()?
        .trim();
    let mut parts = shebang.split_ascii_whitespace();
    let interpreter = parts
        .next()
        .ok_or_else(|| miette::miette!("lifecycle script has an empty shebang"))?;
    if parts.next().is_some() || interpreter == "/usr/bin/env" || !interpreter.starts_with('/') {
        return Err(miette::miette!(
            "lifecycle script must use one absolute pinned interpreter without shebang arguments"
        ));
    }
    Ok(interpreter.to_string())
}

#[cfg(target_os = "linux")]
struct LifecycleAuthPair {
    peer: OwnedFd,
    child: OwnedFd,
}

#[cfg(target_os = "linux")]
impl LifecycleAuthPair {
    #[allow(unsafe_code)]
    fn new() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(miette::miette!(
                "lifecycle authentication requires a root supervisor peer"
            ));
        }
        let mut fds = [-1; 2];
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).into_diagnostic();
        }
        let peer = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok(Self { peer, child })
    }
}

struct SpawnedLifecycleChild {
    child: Child,
    #[cfg(target_os = "linux")]
    auth_peer: Option<OwnedFd>,
}

impl SpawnedLifecycleChild {
    #[cfg(target_os = "linux")]
    fn authenticate(&mut self, operation: &LifecycleOperationSpec) -> Result<()> {
        if operation.id != openshell_core::lifecycle_exec::NEMOCLAW_HERMES_MCP_CONFIG_OPERATION {
            return Err(miette::miette!(
                "lifecycle operation has no authentication handshake"
            ));
        }
        let peer = self
            .auth_peer
            .take()
            .ok_or_else(|| miette::miette!("lifecycle authentication peer is missing"))?;
        send_auth_handshake(peer.as_raw_fd(), NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE)
            .into_diagnostic()
    }

    #[cfg(not(target_os = "linux"))]
    fn authenticate(&self, operation: &LifecycleOperationSpec) -> Result<()> {
        let _ = (self, operation);
        Err(miette::miette!("lifecycle exec requires Linux"))
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn send_auth_handshake(fd: RawFd, handshake: &[u8]) -> std::io::Result<()> {
    let mut written = 0;
    while written < handshake.len() {
        let result = unsafe {
            libc::send(
                fd,
                handshake[written..].as_ptr().cast(),
                handshake.len() - written,
                libc::MSG_NOSIGNAL,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "lifecycle authentication peer closed",
            ));
        }
        written += usize::try_from(result).unwrap_or(0);
    }
    if unsafe { libc::shutdown(fd, libc::SHUT_WR) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn spawn_lifecycle_child(
    policy: &SandboxPolicy,
    command_argv: &[String],
    identity: LifecycleIdentity,
    pinned: PinnedOperation,
    netns_fd: Option<RawFd>,
) -> Result<SpawnedLifecycleChild> {
    use std::os::unix::process::CommandExt as _;

    let interpreter_fd = pinned.interpreter.as_raw_fd();
    let script_fd = pinned.script.as_raw_fd();
    let executable = format!("/proc/self/fd/{interpreter_fd}");
    let script = format!("/proc/self/fd/{script_fd}");
    let auth = LifecycleAuthPair::new()?;
    let auth_child_fd = auth.child.as_raw_fd();
    let mut child = Command::new(executable);
    child
        .arg(script)
        .args(&command_argv[1..])
        .env_clear()
        .env(openshell_core::sandbox_env::SANDBOX, "1")
        .env("HOME", "/sandbox")
        .env("USER", "sandbox")
        .env("LOGNAME", "sandbox")
        .env("PATH", MINIMAL_PATH)
        .env("PYTHONNOUSERSITE", "1")
        .env("PYTHONSAFEPATH", "1")
        .env(LIFECYCLE_AUTH_FD_ENV, auth_child_fd.to_string())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    child.as_std_mut().arg0(&pinned.interpreter_argv0);

    #[cfg(target_os = "linux")]
    let mut prepared = Some(crate::sandbox::linux::prepare(policy, None)?);
    #[cfg(target_os = "linux")]
    let identity_mount = crate::process::supervisor_identity_mount_from_env()?;
    let policy = policy.clone();

    unsafe {
        child.pre_exec(move || {
            nix::unistd::setsid().map_err(|error| std::io::Error::other(error.to_string()))?;
            // Clear CLOEXEC only in this forked child. Keeping it set in the
            // multithreaded supervisor parent prevents concurrent ordinary
            // workload spawns from inheriting the authentication capability.
            let flags = libc::fcntl(auth_child_fd, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(auth_child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let script_flags = libc::fcntl(script_fd, libc::F_GETFD);
            if script_flags < 0
                || libc::fcntl(script_fd, libc::F_SETFD, script_flags & !libc::FD_CLOEXEC) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if let Some(fd) = netns_fd {
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(mount) = identity_mount.as_ref() {
                mount.enter_for_child()?;
            }

            crate::process::drop_privileges(&policy)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if nix::unistd::geteuid() != identity.uid
                || nix::unistd::getegid() != identity.primary_gid
            {
                return Err(std::io::Error::other(
                    "lifecycle identity post-condition failed",
                ));
            }
            crate::process::harden_child_process()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            #[cfg(target_os = "linux")]
            let prepared = prepared
                .take()
                .ok_or_else(|| std::io::Error::other("lifecycle sandbox state was consumed"))?;
            crate::sandbox::linux::enforce(prepared)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            Ok(())
        });
    }

    // Keep pinned descriptors alive until fork/exec has inherited them.
    let spawned = child.spawn().into_diagnostic()?;
    drop(auth.child);
    drop(pinned);
    Ok(SpawnedLifecycleChild {
        child: spawned,
        auth_peer: Some(auth.peer),
    })
}

#[cfg(not(target_os = "linux"))]
fn spawn_lifecycle_child(
    _policy: &SandboxPolicy,
    _command_argv: &[String],
    _identity: LifecycleIdentity,
    _pinned: PinnedOperation,
    _netns_fd: Option<RawFd>,
) -> Result<SpawnedLifecycleChild> {
    Err(miette::miette!("lifecycle exec requires Linux"))
}

async fn kill_process_group(child: &mut Child, pid: u32) {
    let raw_pid = i32::try_from(pid).unwrap_or(i32::MAX);
    let _ = signal::killpg(Pid::from_raw(raw_pid), Signal::SIGKILL);
    let _ = child.start_kill();
    let _ = child.wait().await;
}

async fn read_message<M: Message + Default>(
    stream: &mut tokio::io::DuplexStream,
) -> Result<Option<M>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).into_diagnostic(),
    }
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_RELAY_FRAME {
        return Err(miette::miette!(
            "lifecycle relay frame has an invalid length"
        ));
    }
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).await.into_diagnostic()?;
    M::decode(data.as_slice())
        .map(Some)
        .map_err(|error| miette::miette!("invalid lifecycle relay frame: {error}"))
}

async fn write_event<W>(writer: &mut W, payload: lifecycle_exec_relay_event::Payload) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let data = LifecycleExecRelayEvent {
        payload: Some(payload),
    }
    .encode_to_vec();
    let length = u32::try_from(data.len())
        .map_err(|_| miette::miette!("lifecycle relay event is too large"))?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .into_diagnostic()?;
    writer.write_all(&data).await.into_diagnostic()?;
    writer.flush().await.into_diagnostic()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::lifecycle_exec::{
        LIFECYCLE_AUTH_FD_ENV, NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE,
        NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE, NEMOCLAW_HERMES_MCP_CONFIG_OPERATION,
    };
    use openshell_core::policy::{FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy};
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use tokio::process::Command;

    fn policy() -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy {
                run_as_user: Some("sandbox".to_string()),
                run_as_group: Some("sandbox".to_string()),
                lifecycle_operations: vec![NEMOCLAW_HERMES_MCP_CONFIG_OPERATION.to_string()],
            },
        }
    }

    fn request() -> LifecycleExecRelayRequest {
        LifecycleExecRelayRequest {
            command: vec![
                NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
                "add".to_string(),
                "--payload".to_string(),
                r#"{"server":"demo","url":"https://mcp.example.test/mcp","headers":{"Authorization":"Bearer openshell:resolve:env:DEMO_TOKEN"},"replace_existing":false}"#.to_string(),
            ],
            timeout_seconds: 30,
        }
    }

    #[test]
    fn supervisor_revalidates_operation_policy_and_full_payload() {
        assert!(validate_request(&policy(), &request()).is_ok());

        let mut probe = request();
        probe.command = vec![
            NEMOCLAW_HERMES_MCP_CONFIG_EXECUTABLE.to_string(),
            "probe".to_string(),
        ];
        assert!(validate_request(&policy(), &probe).is_ok());

        let mut absent = policy();
        absent.process.lifecycle_operations.clear();
        assert!(validate_request(&absent, &request()).is_err());

        let mut raw_secret = request();
        raw_secret.command[3] = r#"{"server":"demo","url":"https://mcp.example.test/mcp","headers":{"Authorization":"Bearer raw-secret"}}"#.to_string();
        assert!(validate_request(&policy(), &raw_secret).is_err());
    }

    #[test]
    fn lifecycle_identity_is_exact_nonroot_workload_identity() {
        assert!(validate_identity_values(1000, 1000).is_ok());
        assert!(validate_identity_values(0, 1000).is_err());
        assert!(validate_identity_values(1000, 0).is_err());
    }

    #[test]
    fn lifecycle_auth_contract_binds_exact_operation() {
        assert_eq!(LIFECYCLE_AUTH_FD_ENV, "OPENSHELL_LIFECYCLE_AUTH_FD");
        assert_eq!(
            NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE,
            b"openshell-lifecycle-auth-v1:nemoclaw.hermes-mcp-config-transaction-v1\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    #[test]
    fn lifecycle_auth_handshake_is_exact_and_eof_terminated() {
        use std::io::Read as _;

        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let peer = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        send_auth_handshake(peer.as_raw_fd(), NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE)
            .expect("send handshake");
        drop(peer);

        let mut child: std::os::unix::net::UnixStream = child.into();
        let mut received = Vec::new();
        child
            .read_to_end(&mut received)
            .expect("read handshake through EOF");
        assert_eq!(received, NEMOCLAW_HERMES_MCP_CONFIG_AUTH_HANDSHAKE);
    }

    #[tokio::test]
    async fn pre_spawn_rejection_emits_one_bounded_error_event() {
        let mut invalid = request();
        invalid.timeout_seconds = 0;
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let supervisor = tokio::spawn(serve(server, policy(), None));
        let encoded = invalid.encode_to_vec();
        client
            .write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes())
            .await
            .expect("request length");
        client.write_all(&encoded).await.expect("request");

        let event = read_message::<LifecycleExecRelayEvent>(&mut client)
            .await
            .expect("read error event")
            .expect("error event");
        let lifecycle_exec_relay_event::Payload::Error(message) =
            event.payload.expect("error payload")
        else {
            panic!("expected pre-spawn error event");
        };
        assert!(message.len() <= 512);
        assert!(message.contains("timeout"));
        assert!(supervisor.await.expect("supervisor task").is_err());
    }

    fn spawn_test_process(script: &str) -> Child {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        command.spawn().expect("spawn test process group")
    }

    #[tokio::test]
    async fn relay_drains_output_and_emits_exit_last() {
        let child = spawn_test_process("printf final-output; printf final-error >&2; exit 7");
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(relay_child(server, child, 5));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut kinds = Vec::new();
        loop {
            let event = read_message::<LifecycleExecRelayEvent>(&mut client)
                .await
                .expect("read event")
                .expect("event before EOF");
            match event.payload.expect("event payload") {
                lifecycle_exec_relay_event::Payload::Stdout(data) => {
                    kinds.push("stdout");
                    stdout.extend(data);
                }
                lifecycle_exec_relay_event::Payload::Stderr(data) => {
                    kinds.push("stderr");
                    stderr.extend(data);
                }
                lifecycle_exec_relay_event::Payload::ExitCode(code) => {
                    kinds.push("exit");
                    assert_eq!(code, 7);
                    break;
                }
                lifecycle_exec_relay_event::Payload::Error(error) => {
                    panic!("unexpected relay error: {error}");
                }
            }
        }

        assert_eq!(stdout, b"final-output");
        assert_eq!(stderr, b"final-error");
        assert_eq!(kinds.last(), Some(&"exit"));
        relay.await.expect("relay task").expect("relay success");
    }

    #[allow(unsafe_code)]
    fn process_group_exists(pid: u32) -> bool {
        let pid = i32::try_from(pid).expect("test pid fits i32");
        let result = unsafe { libc::kill(-pid, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[tokio::test]
    async fn relay_drop_kills_and_reaps_silent_process_group() {
        let child = spawn_test_process("sleep 60 & wait");
        let pid = child.id().expect("child pid");
        let (client, server) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(relay_child(server, child, 5));

        drop(client);
        let result = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay cancellation deadline")
            .expect("relay task");
        assert!(result.is_err());

        for _ in 0..100 {
            if !process_group_exists(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("cancelled lifecycle process group {pid} still exists");
    }
}
