#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;
use std::process::ExitCode;

use datax_enterprise_studio_launcher::{RunOutcome, process_exit_code, run, show_error, show_info};

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(RunOutcome::Started) => ExitCode::SUCCESS,
        Ok(RunOutcome::BootstrapCanceled) => {
            show_info(
                "DataX Enterprise Studio",
                "首次管理员创建已取消。本机服务保持运行，但浏览器尚未打开。",
            );
            ExitCode::from(2)
        }
        Ok(RunOutcome::Stopped) => {
            show_info("DataX Enterprise Studio", "本机服务已安全停止。");
            ExitCode::SUCCESS
        }
        Ok(RunOutcome::BackupCreated {
            data_package,
            secrets_package,
        }) => {
            show_info(
                "DataX Enterprise Studio",
                &format!(
                    "系统备份已创建。\n\nDATA：{}\nSECRETS：{}\n\n请将两包及两把恢复 key 分开保管。当前版本尚未开放恢复或覆盖升级。",
                    data_package.display(),
                    secrets_package.display(),
                ),
            );
            ExitCode::SUCCESS
        }
        Ok(RunOutcome::ReleaseVerified) => ExitCode::SUCCESS,
        Ok(RunOutcome::Help(text)) => {
            show_info("DataX Enterprise Studio", &text);
            ExitCode::SUCCESS
        }
        Err(error) => {
            show_error(
                "DataX Enterprise Studio",
                &format!("{}：{}", error.code(), error.message()),
            );
            ExitCode::from(process_exit_code(&error))
        }
    }
}
