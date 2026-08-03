use crate::LauncherError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const STATE_HASH_DOMAIN: &[u8] = b"DXESRUNTIMEGENv1\n";
const LEGACY_SECRET_DIRECTORY: &str = "secrets";
const LEGACY_POSTGRES_VOLUME: &str = "des-postgres-data";
const LEGACY_LOG_VOLUME: &str = "des-log-data";
const LEGACY_WORKSPACE_VOLUME: &str = "des-workspace-data";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVolumes {
    pub postgres: String,
    pub logs: String,
    pub workspace: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGeneration {
    pub schema_version: String,
    pub generation_id: String,
    pub installation_id: String,
    pub source: String,
    pub restore_journal_id: Option<String>,
    pub secret_directory: String,
    pub volumes: RuntimeVolumes,
    pub committed_at: String,
    pub state_sha256: String,
}

impl RuntimeGeneration {
    pub fn legacy(
        generation_id: String,
        installation_id: String,
        committed_at: String,
    ) -> Result<Self, LauncherError> {
        let mut value = Self {
            schema_version: "1.0".to_owned(),
            generation_id,
            installation_id,
            source: "LEGACY".to_owned(),
            restore_journal_id: None,
            secret_directory: LEGACY_SECRET_DIRECTORY.to_owned(),
            volumes: RuntimeVolumes {
                postgres: LEGACY_POSTGRES_VOLUME.to_owned(),
                logs: LEGACY_LOG_VOLUME.to_owned(),
                workspace: LEGACY_WORKSPACE_VOLUME.to_owned(),
            },
            committed_at,
            state_sha256: String::new(),
        };
        value.state_sha256 = value.calculated_state_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn fresh(
        generation_id: String,
        installation_id: String,
        committed_at: String,
    ) -> Result<Self, LauncherError> {
        Self::generated(generation_id, installation_id, "FRESH", None, committed_at)
    }

    pub fn restore(
        generation_id: String,
        installation_id: String,
        restore_journal_id: String,
        committed_at: String,
    ) -> Result<Self, LauncherError> {
        Self::generated(
            generation_id,
            installation_id,
            "RESTORE",
            Some(restore_journal_id),
            committed_at,
        )
    }

    fn generated(
        generation_id: String,
        installation_id: String,
        source: &'static str,
        restore_journal_id: Option<String>,
        committed_at: String,
    ) -> Result<Self, LauncherError> {
        let mut value = Self {
            schema_version: "1.0".to_owned(),
            secret_directory: format!("generations/{generation_id}/secrets"),
            volumes: RuntimeVolumes {
                postgres: format!("des-postgres-{generation_id}"),
                logs: format!("des-log-{generation_id}"),
                workspace: format!("des-workspace-{generation_id}"),
            },
            generation_id,
            installation_id,
            source: source.to_owned(),
            restore_journal_id,
            committed_at,
            state_sha256: String::new(),
        };
        value.state_sha256 = value.calculated_state_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, LauncherError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| invalid("无法编码运行代际指针。"))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, LauncherError> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(invalid("运行代际指针大小无效。"));
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("运行代际指针不是严格 JSON。"))?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), LauncherError> {
        if self.schema_version != "1.0"
            || !is_lower_hex(&self.generation_id, 32)
            || !is_lower_hex(&self.installation_id, 64)
            || !is_utc_timestamp(&self.committed_at)
            || !is_lower_hex(&self.state_sha256, 64)
        {
            return Err(invalid("运行代际指针的身份、版本、时间或摘要字段无效。"));
        }
        match self.source.as_str() {
            "LEGACY" => {
                if self.restore_journal_id.is_some()
                    || self.secret_directory != LEGACY_SECRET_DIRECTORY
                    || self.volumes.postgres != LEGACY_POSTGRES_VOLUME
                    || self.volumes.logs != LEGACY_LOG_VOLUME
                    || self.volumes.workspace != LEGACY_WORKSPACE_VOLUME
                {
                    return Err(invalid("LEGACY 运行代际没有精确引用旧式完整对象集合。"));
                }
            }
            "FRESH" => {
                if self.restore_journal_id.is_some() || !self.has_generation_objects() {
                    return Err(invalid("FRESH 运行代际对象或 journal 字段无效。"));
                }
            }
            "RESTORE" => {
                if self
                    .restore_journal_id
                    .as_deref()
                    .is_none_or(|value| !is_lower_hex(value, 32))
                    || !self.has_generation_objects()
                {
                    return Err(invalid("RESTORE 运行代际对象或 journal 字段无效。"));
                }
            }
            _ => return Err(invalid("运行代际来源枚举无效。")),
        }
        if self.calculated_state_sha256()? != self.state_sha256 {
            return Err(invalid("运行代际指针摘要不匹配。"));
        }
        Ok(())
    }

    pub fn calculated_state_sha256(&self) -> Result<String, LauncherError> {
        let unsigned = serde_json::json!({
            "committed_at": self.committed_at,
            "generation_id": self.generation_id,
            "installation_id": self.installation_id,
            "restore_journal_id": self.restore_journal_id,
            "schema_version": self.schema_version,
            "secret_directory": self.secret_directory,
            "source": self.source,
            "volumes": {
                "logs": self.volumes.logs,
                "postgres": self.volumes.postgres,
                "workspace": self.volumes.workspace,
            },
        });
        let canonical =
            serde_json::to_vec(&unsigned).map_err(|_| invalid("无法规范化运行代际指针。"))?;
        let mut digest = Sha256::new();
        digest.update(STATE_HASH_DOMAIN);
        digest.update(canonical);
        Ok(hex_lower(&digest.finalize()))
    }

    pub fn compose_environment(&self, app_data_root: &Path) -> Vec<(OsString, OsString)> {
        let secret_directory = self.secret_path(app_data_root);
        vec![
            (
                OsString::from("DES_SECRET_DIR"),
                secret_directory.into_os_string(),
            ),
            (
                OsString::from("DES_INSTALLATION_ID"),
                OsString::from(&self.installation_id),
            ),
            (
                OsString::from("DES_POSTGRES_VOLUME_NAME"),
                OsString::from(&self.volumes.postgres),
            ),
            (
                OsString::from("DES_LOG_VOLUME_NAME"),
                OsString::from(&self.volumes.logs),
            ),
            (
                OsString::from("DES_WORKSPACE_VOLUME_NAME"),
                OsString::from(&self.volumes.workspace),
            ),
        ]
    }

    pub fn secret_path(&self, app_data_root: &Path) -> PathBuf {
        self.secret_directory
            .split('/')
            .fold(app_data_root.to_path_buf(), |path, component| {
                path.join(component)
            })
    }

    fn has_generation_objects(&self) -> bool {
        self.secret_directory == format!("generations/{}/secrets", self.generation_id)
            && self.volumes.postgres == format!("des-postgres-{}", self.generation_id)
            && self.volumes.logs == format!("des-log-{}", self.generation_id)
            && self.volumes.workspace == format!("des-workspace-{}", self.generation_id)
    }
}

fn invalid(message: &str) -> LauncherError {
    LauncherError::new("RUNTIME_GENERATION_INVALID", message)
}

fn is_lower_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_utc_timestamp(value: &str) -> bool {
    let Some((date, time)) = value
        .strip_suffix('Z')
        .and_then(|value| value.split_once('T'))
    else {
        return false;
    };
    let date_parts = date.split('-').collect::<Vec<_>>();
    let time_parts = time.split(':').collect::<Vec<_>>();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return false;
    }
    let Some(year) = decimal(date_parts[0], 4) else {
        return false;
    };
    let Some(month) = decimal(date_parts[1], 2) else {
        return false;
    };
    let Some(day) = decimal(date_parts[2], 2) else {
        return false;
    };
    let Some(hour) = decimal(time_parts[0], 2) else {
        return false;
    };
    let Some(minute) = decimal(time_parts[1], 2) else {
        return false;
    };
    let (second_text, fraction) = time_parts[2]
        .split_once('.')
        .map_or((time_parts[2], None), |(seconds, fraction)| {
            (seconds, Some(fraction))
        });
    let Some(second) = decimal(second_text, 2) else {
        return false;
    };
    if fraction.is_some_and(|digits| {
        digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return false;
    }
    if year < 2000 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=maximum_day).contains(&day)
}

fn decimal(value: &str, length: usize) -> Option<u32> {
    (value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(source: &str) -> RuntimeGeneration {
        let generation_id = "a".repeat(32);
        let installation_id = "b".repeat(64);
        let committed_at = "2026-08-01T09:30:00.123456Z".to_owned();
        match source {
            "FRESH" => RuntimeGeneration::fresh(generation_id, installation_id, committed_at),
            "RESTORE" => RuntimeGeneration::restore(
                generation_id,
                installation_id,
                "c".repeat(32),
                committed_at,
            ),
            _ => panic!("test helper only constructs FRESH or RESTORE generations"),
        }
        .unwrap()
    }

    #[test]
    fn fresh_constructor_binds_the_exact_generated_object_set() {
        let value = RuntimeGeneration::fresh(
            "a".repeat(32),
            "b".repeat(64),
            "2026-08-01T09:30:00.123456Z".to_owned(),
        )
        .unwrap();

        assert_eq!(value.source, "FRESH");
        assert_eq!(value.restore_journal_id, None);
        assert_eq!(
            value.secret_directory,
            format!("generations/{}/secrets", "a".repeat(32))
        );
        assert_eq!(
            value.volumes.postgres,
            format!("des-postgres-{}", "a".repeat(32))
        );
        assert_eq!(value.volumes.logs, format!("des-log-{}", "a".repeat(32)));
        assert_eq!(
            value.volumes.workspace,
            format!("des-workspace-{}", "a".repeat(32))
        );
        assert_eq!(value.state_sha256, value.calculated_state_sha256().unwrap());
        assert_eq!(
            RuntimeGeneration::parse(&value.to_bytes().unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn restore_constructor_binds_a_valid_journal_to_the_generated_object_set() {
        let restore_journal_id = "c".repeat(32);
        let value = RuntimeGeneration::restore(
            "a".repeat(32),
            "b".repeat(64),
            restore_journal_id.clone(),
            "2026-08-01T09:30:00.123456Z".to_owned(),
        )
        .unwrap();

        assert_eq!(value.source, "RESTORE");
        assert_eq!(
            value.restore_journal_id.as_deref(),
            Some(restore_journal_id.as_str())
        );
        assert_eq!(
            value.secret_directory,
            format!("generations/{}/secrets", "a".repeat(32))
        );
        assert_eq!(value.state_sha256, value.calculated_state_sha256().unwrap());
        assert_eq!(
            RuntimeGeneration::parse(&value.to_bytes().unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn generated_constructors_reject_invalid_identity_or_restore_journal() {
        assert_eq!(
            RuntimeGeneration::fresh(
                "not-a-generation".to_owned(),
                "b".repeat(64),
                "2026-08-01T09:30:00Z".to_owned(),
            )
            .unwrap_err()
            .code(),
            "RUNTIME_GENERATION_INVALID"
        );
        assert_eq!(
            RuntimeGeneration::restore(
                "a".repeat(32),
                "b".repeat(64),
                "not-a-journal".to_owned(),
                "2026-08-01T09:30:00Z".to_owned(),
            )
            .unwrap_err()
            .code(),
            "RUNTIME_GENERATION_INVALID"
        );
    }

    #[test]
    fn restore_generation_round_trips_and_binds_compose_environment() {
        let value = generation("RESTORE");
        let encoded = serde_json::to_vec(&value).unwrap();
        let parsed = RuntimeGeneration::parse(&encoded).unwrap();
        let environment = parsed.compose_environment(Path::new(r"C:\Local\DataX"));

        assert_eq!(parsed, value);
        assert!(environment.contains(&(
            OsString::from("DES_POSTGRES_VOLUME_NAME"),
            OsString::from(format!("des-postgres-{}", "a".repeat(32))),
        )));
        assert!(
            parsed
                .secret_path(Path::new(r"C:\Local\DataX"))
                .ends_with(Path::new(&format!(
                    "generations/{}/secrets",
                    "a".repeat(32)
                )))
        );
    }

    #[test]
    fn legacy_generation_requires_the_complete_fixed_set() {
        let mut value = RuntimeGeneration::legacy(
            "a".repeat(32),
            "b".repeat(64),
            "2026-08-01T09:30:00Z".to_owned(),
        )
        .unwrap();
        assert_eq!(
            RuntimeGeneration::parse(&value.to_bytes().unwrap()).unwrap(),
            value
        );
        assert!(value.validate().is_ok());

        value.volumes.logs = format!("des-log-{}", value.generation_id);
        value.state_sha256 = value.calculated_state_sha256().unwrap();
        assert_eq!(
            value.validate().unwrap_err().code(),
            "RUNTIME_GENERATION_INVALID"
        );
    }

    #[test]
    fn generation_rejects_mixed_objects_traversal_and_tampering() {
        let mut mixed = generation("RESTORE");
        mixed.volumes.workspace = LEGACY_WORKSPACE_VOLUME.to_owned();
        mixed.state_sha256 = mixed.calculated_state_sha256().unwrap();
        assert!(mixed.validate().is_err());

        let mut traversal = generation("RESTORE");
        traversal.secret_directory = "generations/../secrets".to_owned();
        traversal.state_sha256 = traversal.calculated_state_sha256().unwrap();
        assert!(traversal.validate().is_err());

        let mut tampered = generation("RESTORE");
        tampered.installation_id = "d".repeat(64);
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn timestamp_validation_rejects_impossible_or_non_utc_values() {
        let mut value = generation("FRESH");
        for invalid_timestamp in [
            "2026-02-30T00:00:00Z",
            "2026-08-01T24:00:00Z",
            "2026-08-01T09:30:00+08:00",
            "2026-08-01T09:30:00.1234567Z",
        ] {
            value.committed_at = invalid_timestamp.to_owned();
            value.state_sha256 = value.calculated_state_sha256().unwrap();
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn state_hash_matches_independent_rfc8785_fixture() {
        let value = generation("FRESH");
        assert_eq!(
            value.state_sha256,
            "e364afc4df97525795d08bfd94a79863d787c3331ab09f96a54c9fd62bc5ed15"
        );
    }
}
