use futures::FutureExt;
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{
        SideloaderBuilder, builder::MaxCertsBehavior, cert_identity::CertificateIdentity,
        sideloader::Sideloader,
    },
    util::callbacks::MaxCertsCallbackBox,
};
use tauri_plugin_dialog::DialogExt;
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::debug;

use crate::{
    error::AppError,
    secure_storage::create_sideloading_storage,
    sideload::{SideloaderGuard, SideloaderMutex},
};

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    if save_credentials {
        let pass_entry = Entry::new("iloader", &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    if let Some(account) = &*sideloader_guard {
        return Some(account.get_email().to_string());
    }
    None
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
}

#[tauri::command]
pub fn reset_anisette_state() -> Result<bool, AppError> {
    let state_entry = Entry::new("iloader", "anisette_state").map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for anisette".into(),
            e.to_string(),
        )
    })?;

    match state_entry.delete_credential() {
        Ok(_) => {
            debug!("Anisette state deleted from keyring.");
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No existing anisette state found in keyring, nothing to delete.");
            Ok(false)
        }
        Err(e) => Err(AppError::KeyringWithMessage(
            "Failed to delete anisette state".into(),
            e.to_string(),
        )),
    }
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox>, AppError> {
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();

            async move {
                window_clone
                    .emit("2fa-required", params)
                    .context("Failed to emit 2fa-required event")?;

                let (tx, rx) = std::sync::mpsc::channel::<String>();
                let handler_id = window_clone.listen("2fa-recieved", move |event| {
                    let code = event.payload();
                    let _ = tx.send(code.to_string());
                });

                let result = rx.recv_timeout(Duration::from_secs(120))?;
                window_clone.unlisten(handler_id);

                let code = result.trim_matches('"').to_string();
                Ok(TwoFactorCallbackResponse::SubmitCode(code))
            }
            .boxed()
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(create_sideloading_storage(app)?)
                .set_url(&anisette_url),
        )
        .login(password, Box::new(tfa_closure))
        .await?;

    debug!("Logged in");

    let dev_session = DeveloperSession::from_account(&mut account).await?;

    debug!("Created developer session");

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                window_clone.emit("max-certs-reached", cert_infos)?;

                let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<String>>>();
                let handler_id = window_clone.listen("max-certs-response", move |event| {
                    let certs = event.payload();
                    let certs = serde_json::from_str::<Option<Vec<String>>>(certs).unwrap_or(None);
                    let _ = tx.send(certs);
                });

                let result = rx.recv_timeout(Duration::from_secs(300));
                window_clone.unlisten(handler_id);
                Ok(result?)
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("iloader".into())
        .storage(create_sideloading_storage(app)?)
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    debug!("Built sideloader");

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

/// Export the logged-in account's signing certificate and private key as a PKCS#12 (.p12) file.
///
/// Prompts the user for a save location, writes the archive there, and returns the archive's
/// password. The password is the account's machine id, which is the same password
/// SideStore / AltStore and LiveContainer's JIT-Less mode expect when importing the
/// certificate manually.
#[tauri::command]
pub async fn save_certificate_p12(
    app: AppHandle,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<String, AppError> {
    let save_path = app
        .dialog()
        .file()
        .add_filter("PKCS#12 Certificate", &["p12"])
        .set_file_name("certificate.p12")
        .set_title("Save Certificate (.p12)")
        .blocking_save_file();

    let save_path = match save_path.and_then(|p| p.as_path().map(|p| p.to_path_buf())) {
        Some(p) => p,
        None => return Err(AppError::Canceled("Save .p12".into())),
    };

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let email = sideloader.get_mut().get_email().to_string();
    let team = sideloader.get_mut().get_team().await?;
    let storage = create_sideloading_storage(&app)?;
    let max_certs = MaxCertsBehavior::<MaxCertsCallbackBox>::Error;
    let dev_session = sideloader.get_mut().get_dev_session();

    let cert_identity = CertificateIdentity::retrieve(
        "iloader",
        &email,
        dev_session,
        &team,
        storage.as_ref(),
        &max_certs,
    )
    .await
    .map_err(|e| AppError::Misc(format!("Failed to retrieve certificate identity: {:?}", e)))?;

    let password = "1234".to_string();
    let p12 = cert_identity
        .as_p12(&password)
        .await
        .map_err(|e| AppError::Misc(format!("Failed to encode certificate as .p12: {:?}", e)))?;

    tokio::fs::write(&save_path, &p12)
        .await
        .map_err(|e| AppError::Filesystem("Failed to write .p12 file".into(), e.to_string()))?;

    Ok(password)
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}
