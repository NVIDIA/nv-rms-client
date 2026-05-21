/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, io};

use chrono::{DateTime, Utc};
use tonic::Status;

use crate::client::{RackManagerClientT, RetryConfig, RmsApiConfig, RmsTlsClient};
use crate::client_config::RmsClientConfig;
use crate::protos::rack_manager as rms;
use crate::protos::rack_manager::{
    UpgradeFirmwareOnSwitchCommand, UpgradeFirmwareOnSwitchResponse,
};
use crate::protos::rack_manager_client::RackManagerApiClient;
pub mod client;
pub mod client_config;
pub mod protos;
pub mod timestamp_serde {
    use chrono::{DateTime, Utc};
    use prost_types::Timestamp;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(timestamp) => {
                let dt = DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
                    .ok_or_else(|| {
                        serde::ser::Error::custom("invalid google.protobuf.Timestamp")
                    })?;
                serializer.serialize_some(&dt.to_rfc3339())
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Timestamp>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| {
                let dt = DateTime::parse_from_rfc3339(&value)
                    .map_err(D::Error::custom)?
                    .with_timezone(&Utc);
                Ok(Timestamp {
                    seconds: dt.timestamp(),
                    nanos: dt.timestamp_subsec_nanos() as i32,
                })
            })
            .transpose()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RmsTlsClientError {
    #[error("ConnectError error: {0}")]
    Connection(String),
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("Rust TLS error: {0}")]
    RustTLS(#[from] rustls::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigurationError {
    #[error("Invalid URI {uri_string}: {error}")]
    InvalidUri {
        uri_string: String,
        error: hyper::http::uri::InvalidUri,
    },
    #[error("Could not read Root CA cert at {path}: {error}")]
    CouldNotReadRootCa { path: String, error: io::Error },
    #[error("Could not read Client cert at {path}: {error}")]
    CouldNotReadClientCert { path: String, error: io::Error },
    #[error("Could not read Client key at {path}: {error}")]
    CouldNotReadClientKey { path: String, error: io::Error },
    #[error("Invalid Client cert: {error}")]
    InvalidClientCert { error: String },
    #[error("Invalid Client key: {error}")]
    InvalidClientKey { error: String },
    #[error("Invalid Root CA: {error}")]
    InvalidRootCa { error: String },
    #[error("Invalid HTTP URL with TLS enforced: {url}")]
    InvalidHTTPURL { url: String },
}

impl From<RmsTlsClientError> for tonic::Status {
    fn from(value: RmsTlsClientError) -> Self {
        tonic::Status::unavailable(value.to_string())
    }
}

impl RackManagerApiClient {
    pub fn new(rms_config: &RmsApiConfig<'_>) -> Self {
        Self::build(RmsTlsConnectionProvider {
            url: rms_config.url.to_string(),
            client_config: rms_config.client_config.clone(),
            retry_config: rms_config.retry_config,
        })
    }
}

// TODO: Add more error types for better error handling.
#[derive(thiserror::Error, Debug)]
pub enum RackManagerError {
    #[error("The connection or API call to the Rack Manager server returned {0}")]
    ApiInvocationError(#[from] tonic::Status),
    #[error("TLS client error: {0}")]
    TlsError(#[from] RmsTlsClientError),
}

#[derive(Clone)]
pub struct RmsClientPool {
    pub client: RackManagerApi,
}

impl RmsClientPool {
    pub fn new(rms_api_config: &RmsApiConfig<'_>) -> Self {
        let client = RackManagerApi::new(rms_api_config);
        Self { client }
    }
}

#[async_trait::async_trait]
pub trait RackManagerClientPool: Send + Sync + 'static {
    async fn create_client(&self) -> Arc<dyn RmsApi>;
}

#[async_trait::async_trait]
impl RackManagerClientPool for RmsClientPool {
    async fn create_client(&self) -> Arc<dyn RmsApi> {
        Arc::new(self.client.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RackManagerApi {
    pub client: RackManagerApiClient,
    #[allow(unused)]
    pub config: RmsClientConfig,
    #[allow(unused)]
    pub api_url: String,
}

impl RackManagerApi {
    /// create a rack manager client that can be used in the api server
    pub fn new(rms_api_config: &RmsApiConfig<'_>) -> Self {
        let client = RackManagerApiClient::new(rms_api_config);
        Self {
            client,
            config: rms_api_config.client_config.clone(),
            api_url: rms_api_config.url.to_string(),
        }
    }
}

// declare the functions
#[allow(clippy::too_many_arguments, dead_code)]
#[async_trait::async_trait]
pub trait RmsApi: Send + Sync + 'static {
    async fn set_power_state(
        &self,
        cmd: rms::SetPowerStateRequest,
    ) -> Result<rms::SetPowerStateResponse, RackManagerError>;
    async fn set_power_state_by_device_list(
        &self,
        cmd: rms::SetPowerStateByDeviceListRequest,
    ) -> Result<rms::SetPowerStateByDeviceListResponse, RackManagerError>;
    async fn get_power_state(
        &self,
        cmd: rms::GetPowerStateRequest,
    ) -> Result<rms::GetPowerStateResponse, RackManagerError>;
    async fn get_power_state_by_device_list(
        &self,
        cmd: rms::GetPowerStateByDeviceListRequest,
    ) -> Result<rms::GetPowerStateByDeviceListResponse, RackManagerError>;
    async fn sequence_rack_power(
        &self,
        cmd: rms::SequenceRackPowerRequest,
    ) -> Result<rms::SequenceRackPowerResponse, RackManagerError>;
    async fn get_all_inventory(
        &self,
        cmd: rms::GetAllInventoryRequest,
    ) -> Result<rms::GetAllInventoryResponse, RackManagerError>;
    async fn add_node(
        &self,
        cmd: rms::AddNodeRequest,
    ) -> Result<rms::AddNodeResponse, RackManagerError>;
    async fn update_node(
        &self,
        cmd: rms::UpdateNodeRequest,
    ) -> Result<rms::UpdateNodeResponse, RackManagerError>;
    async fn remove_node(
        &self,
        cmd: rms::RemoveNodeRequest,
    ) -> Result<rms::RemoveNodeResponse, RackManagerError>;
    async fn get_rack_power_on_sequence(
        &self,
        cmd: rms::GetRackPowerOnSequenceRequest,
    ) -> Result<rms::GetRackPowerOnSequenceResponse, RackManagerError>;
    async fn set_rack_power_on_sequence(
        &self,
        cmd: rms::SetRackPowerOnSequenceRequest,
    ) -> Result<rms::SetRackPowerOnSequenceResponse, RackManagerError>;
    async fn list_racks(
        &self,
        cmd: rms::ListRacksRequest,
    ) -> Result<rms::ListRacksResponse, RackManagerError>;
    async fn get_node_device_info(
        &self,
        cmd: rms::GetNodeDeviceInfoRequest,
    ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError>;
    async fn get_device_info_by_node_type(
        &self,
        cmd: rms::GetDeviceInfoByNodeTypeRequest,
    ) -> Result<rms::GetDeviceInfoByNodeTypeResponse, RackManagerError>;
    async fn get_device_info_by_device_list(
        &self,
        cmd: rms::GetDeviceInfoByDeviceListRequest,
    ) -> Result<rms::GetDeviceInfoByDeviceListResponse, RackManagerError>;
    async fn get_node_firmware_inventory(
        &self,
        cmd: rms::GetNodeFirmwareInventoryRequest,
    ) -> Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError>;
    async fn get_rack_firmware_inventory(
        &self,
        cmd: rms::GetRackFirmwareInventoryRequest,
    ) -> Result<rms::GetRackFirmwareInventoryResponse, RackManagerError>;
    async fn add_firmware_object(
        &self,
        cmd: rms::AddFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError>;
    async fn get_firmware_object(
        &self,
        cmd: rms::GetFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError>;
    async fn list_firmware_objects(
        &self,
        cmd: rms::ListFirmwareObjectsRequest,
    ) -> Result<rms::ListFirmwareObjectsResponse, RackManagerError>;
    async fn delete_firmware_object(
        &self,
        cmd: rms::DeleteFirmwareObjectRequest,
    ) -> Result<rms::OperationResponse, RackManagerError>;
    async fn set_default_firmware_object(
        &self,
        cmd: rms::SetDefaultFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError>;
    async fn apply_firmware_object(
        &self,
        cmd: rms::ApplyFirmwareObjectRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError>;
    async fn apply_firmware_object_from_json(
        &self,
        cmd: rms::ApplyFirmwareObjectFromJsonRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError>;
    async fn apply_switch_system_image_from_json(
        &self,
        cmd: rms::ApplySwitchSystemImageFromJsonRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError>;
    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError>;
    async fn get_firmware_object_history(
        &self,
        cmd: rms::GetFirmwareObjectHistoryRequest,
    ) -> Result<rms::GetFirmwareObjectHistoryResponse, RackManagerError>;
    async fn list_firmware_on_switch(
        &self,
        cmd: rms::ListFirmwareOnSwitchCommand,
    ) -> Result<rms::ListFirmwareOnSwitchResponse, RackManagerError>;
    async fn push_firmware_to_switch(
        &self,
        cmd: rms::PushFirmwareToSwitchCommand,
    ) -> Result<rms::PushFirmwareToSwitchResponse, RackManagerError>;
    async fn upgrade_firmware_on_switch(
        &self,
        cmd: rms::UpgradeFirmwareOnSwitchCommand,
    ) -> Result<rms::UpgradeFirmwareOnSwitchResponse, RackManagerError>;
    async fn configure_scale_up_fabric_manager(
        &self,
        cmd: rms::ConfigureScaleUpFabricManagerRequest,
    ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError>;
    async fn set_scale_up_fabric_state(
        &self,
        cmd: rms::SetScaleUpFabricStateRequest,
    ) -> Result<rms::SetScaleUpFabricStateResponse, RackManagerError>;
    async fn fetch_switch_system_image(
        &self,
        cmd: rms::FetchSwitchSystemImageRequest,
    ) -> Result<rms::FetchSwitchSystemImageResponse, RackManagerError>;
    async fn install_switch_system_image(
        &self,
        cmd: rms::InstallSwitchSystemImageRequest,
    ) -> Result<rms::InstallSwitchSystemImageResponse, RackManagerError>;
    async fn list_switch_system_images(
        &self,
        cmd: rms::ListSwitchSystemImagesRequest,
    ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError>;
    async fn enable_scale_up_fabric_telemetry_interface(
        &self,
        cmd: rms::EnableScaleUpFabricTelemetryInterfaceRequest,
    ) -> Result<rms::EnableScaleUpFabricTelemetryInterfaceResponse, RackManagerError>;
    async fn version(&self) -> Result<(), RackManagerError>;
    async fn poll_job_status(
        &self,
        cmd: rms::PollJobStatusCommand,
    ) -> Result<rms::PollJobStatusResponse, RackManagerError>;
    async fn update_node_firmware_async(
        &self,
        cmd: rms::UpdateNodeFirmwareRequest,
    ) -> Result<rms::UpdateNodeFirmwareResponse, RackManagerError>;
    async fn update_firmware_by_node_type_async(
        &self,
        cmd: rms::UpdateFirmwareByNodeTypeRequest,
    ) -> Result<rms::UpdateFirmwareByNodeTypeAsyncResponse, RackManagerError>;
    async fn update_firmware_by_device_list(
        &self,
        cmd: rms::UpdateFirmwareByDeviceListRequest,
    ) -> Result<rms::UpdateFirmwareByDeviceListResponse, RackManagerError>;
    async fn get_firmware_job_status(
        &self,
        cmd: rms::GetFirmwareJobStatusRequest,
    ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError>;
    async fn update_switch_system_password(
        &self,
        cmd: rms::UpdateSwitchSystemPasswordRequest,
    ) -> Result<rms::UpdateSwitchSystemPasswordResponse, RackManagerError>;
}

#[async_trait::async_trait]
impl RmsApi for RackManagerApi {
    async fn set_power_state(
        &self,
        cmd: rms::SetPowerStateRequest,
    ) -> Result<rms::SetPowerStateResponse, RackManagerError> {
        Ok(self.client.set_power_state(cmd).await?)
    }
    async fn set_power_state_by_device_list(
        &self,
        cmd: rms::SetPowerStateByDeviceListRequest,
    ) -> Result<rms::SetPowerStateByDeviceListResponse, RackManagerError> {
        Ok(self.client.set_power_state_by_device_list(cmd).await?)
    }
    async fn get_power_state(
        &self,
        cmd: rms::GetPowerStateRequest,
    ) -> Result<rms::GetPowerStateResponse, RackManagerError> {
        Ok(self.client.get_power_state(cmd).await?)
    }
    async fn get_power_state_by_device_list(
        &self,
        cmd: rms::GetPowerStateByDeviceListRequest,
    ) -> Result<rms::GetPowerStateByDeviceListResponse, RackManagerError> {
        Ok(self.client.get_power_state_by_device_list(cmd).await?)
    }
    async fn sequence_rack_power(
        &self,
        cmd: rms::SequenceRackPowerRequest,
    ) -> Result<rms::SequenceRackPowerResponse, RackManagerError> {
        Ok(self.client.sequence_rack_power(cmd).await?)
    }
    async fn get_all_inventory(
        &self,
        cmd: rms::GetAllInventoryRequest,
    ) -> Result<rms::GetAllInventoryResponse, RackManagerError> {
        Ok(self.client.get_all_inventory(cmd).await?)
    }
    async fn add_node(
        &self,
        cmd: rms::AddNodeRequest,
    ) -> Result<rms::AddNodeResponse, RackManagerError> {
        Ok(self.client.add_node(cmd).await?)
    }
    async fn update_node(
        &self,
        cmd: rms::UpdateNodeRequest,
    ) -> Result<rms::UpdateNodeResponse, RackManagerError> {
        Ok(self.client.update_node(cmd).await?)
    }
    async fn remove_node(
        &self,
        cmd: rms::RemoveNodeRequest,
    ) -> Result<rms::RemoveNodeResponse, RackManagerError> {
        Ok(self.client.remove_node(cmd).await?)
    }
    async fn get_rack_power_on_sequence(
        &self,
        cmd: rms::GetRackPowerOnSequenceRequest,
    ) -> Result<rms::GetRackPowerOnSequenceResponse, RackManagerError> {
        Ok(self.client.get_rack_power_on_sequence(cmd).await?)
    }
    async fn set_rack_power_on_sequence(
        &self,
        cmd: rms::SetRackPowerOnSequenceRequest,
    ) -> Result<rms::SetRackPowerOnSequenceResponse, RackManagerError> {
        Ok(self.client.set_rack_power_on_sequence(cmd).await?)
    }
    async fn list_racks(
        &self,
        cmd: rms::ListRacksRequest,
    ) -> Result<rms::ListRacksResponse, RackManagerError> {
        Ok(self.client.list_racks(cmd).await?)
    }
    async fn get_node_device_info(
        &self,
        cmd: rms::GetNodeDeviceInfoRequest,
    ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError> {
        Ok(self.client.get_node_device_info(cmd).await?)
    }
    async fn get_device_info_by_node_type(
        &self,
        cmd: rms::GetDeviceInfoByNodeTypeRequest,
    ) -> Result<rms::GetDeviceInfoByNodeTypeResponse, RackManagerError> {
        Ok(self.client.get_device_info_by_node_type(cmd).await?)
    }
    async fn get_device_info_by_device_list(
        &self,
        cmd: rms::GetDeviceInfoByDeviceListRequest,
    ) -> Result<rms::GetDeviceInfoByDeviceListResponse, RackManagerError> {
        Ok(self.client.get_device_info_by_device_list(cmd).await?)
    }
    async fn get_node_firmware_inventory(
        &self,
        cmd: rms::GetNodeFirmwareInventoryRequest,
    ) -> Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError> {
        Ok(self.client.get_node_firmware_inventory(cmd).await?)
    }
    async fn get_rack_firmware_inventory(
        &self,
        cmd: rms::GetRackFirmwareInventoryRequest,
    ) -> Result<rms::GetRackFirmwareInventoryResponse, RackManagerError> {
        Ok(self.client.get_rack_firmware_inventory(cmd).await?)
    }
    async fn add_firmware_object(
        &self,
        cmd: rms::AddFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError> {
        Ok(self.client.add_firmware_object(cmd).await?)
    }
    async fn get_firmware_object(
        &self,
        cmd: rms::GetFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError> {
        Ok(self.client.get_firmware_object(cmd).await?)
    }
    async fn list_firmware_objects(
        &self,
        cmd: rms::ListFirmwareObjectsRequest,
    ) -> Result<rms::ListFirmwareObjectsResponse, RackManagerError> {
        Ok(self.client.list_firmware_objects(cmd).await?)
    }
    async fn delete_firmware_object(
        &self,
        cmd: rms::DeleteFirmwareObjectRequest,
    ) -> Result<rms::OperationResponse, RackManagerError> {
        Ok(self.client.delete_firmware_object(cmd).await?)
    }
    async fn set_default_firmware_object(
        &self,
        cmd: rms::SetDefaultFirmwareObjectRequest,
    ) -> Result<rms::FirmwareObject, RackManagerError> {
        Ok(self.client.set_default_firmware_object(cmd).await?)
    }
    async fn apply_firmware_object(
        &self,
        cmd: rms::ApplyFirmwareObjectRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.apply_firmware_object(cmd).await?)
    }
    async fn apply_firmware_object_from_json(
        &self,
        cmd: rms::ApplyFirmwareObjectFromJsonRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.apply_firmware_object_from_json(cmd).await?)
    }
    async fn apply_switch_system_image_from_json(
        &self,
        cmd: rms::ApplySwitchSystemImageFromJsonRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.apply_switch_system_image_from_json(cmd).await?)
    }
    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.apply_switch_system_image(cmd).await?)
    }
    async fn get_firmware_object_history(
        &self,
        cmd: rms::GetFirmwareObjectHistoryRequest,
    ) -> Result<rms::GetFirmwareObjectHistoryResponse, RackManagerError> {
        Ok(self.client.get_firmware_object_history(cmd).await?)
    }
    async fn list_firmware_on_switch(
        &self,
        cmd: rms::ListFirmwareOnSwitchCommand,
    ) -> Result<rms::ListFirmwareOnSwitchResponse, RackManagerError> {
        Ok(self.client.list_firmware_on_switch(cmd).await?)
    }
    async fn push_firmware_to_switch(
        &self,
        cmd: rms::PushFirmwareToSwitchCommand,
    ) -> Result<rms::PushFirmwareToSwitchResponse, RackManagerError> {
        Ok(self.client.push_firmware_to_switch(cmd).await?)
    }
    async fn upgrade_firmware_on_switch(
        &self,
        cmd: UpgradeFirmwareOnSwitchCommand,
    ) -> Result<UpgradeFirmwareOnSwitchResponse, RackManagerError> {
        Ok(self.client.upgrade_firmware_on_switch(cmd).await?)
    }
    async fn configure_scale_up_fabric_manager(
        &self,
        cmd: rms::ConfigureScaleUpFabricManagerRequest,
    ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError> {
        Ok(self.client.configure_scale_up_fabric_manager(cmd).await?)
    }
    async fn set_scale_up_fabric_state(
        &self,
        cmd: rms::SetScaleUpFabricStateRequest,
    ) -> Result<rms::SetScaleUpFabricStateResponse, RackManagerError> {
        Ok(self.client.set_scale_up_fabric_state(cmd).await?)
    }
    async fn fetch_switch_system_image(
        &self,
        cmd: rms::FetchSwitchSystemImageRequest,
    ) -> Result<rms::FetchSwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.fetch_switch_system_image(cmd).await?)
    }
    async fn install_switch_system_image(
        &self,
        cmd: rms::InstallSwitchSystemImageRequest,
    ) -> Result<rms::InstallSwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.install_switch_system_image(cmd).await?)
    }
    async fn list_switch_system_images(
        &self,
        cmd: rms::ListSwitchSystemImagesRequest,
    ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError> {
        Ok(self.client.list_switch_system_images(cmd).await?)
    }
    async fn enable_scale_up_fabric_telemetry_interface(
        &self,
        cmd: rms::EnableScaleUpFabricTelemetryInterfaceRequest,
    ) -> Result<rms::EnableScaleUpFabricTelemetryInterfaceResponse, RackManagerError> {
        Ok(self
            .client
            .enable_scale_up_fabric_telemetry_interface(cmd)
            .await?)
    }
    async fn version(&self) -> Result<(), RackManagerError> {
        Ok(self.client.version().await?)
    }
    async fn poll_job_status(
        &self,
        cmd: rms::PollJobStatusCommand,
    ) -> Result<rms::PollJobStatusResponse, RackManagerError> {
        Ok(self.client.poll_job_status(cmd).await?)
    }
    async fn update_node_firmware_async(
        &self,
        cmd: rms::UpdateNodeFirmwareRequest,
    ) -> Result<rms::UpdateNodeFirmwareResponse, RackManagerError> {
        Ok(self.client.update_node_firmware_async(cmd).await?)
    }
    async fn update_firmware_by_node_type_async(
        &self,
        cmd: rms::UpdateFirmwareByNodeTypeRequest,
    ) -> Result<rms::UpdateFirmwareByNodeTypeAsyncResponse, RackManagerError> {
        Ok(self.client.update_firmware_by_node_type_async(cmd).await?)
    }
    async fn update_firmware_by_device_list(
        &self,
        cmd: rms::UpdateFirmwareByDeviceListRequest,
    ) -> Result<rms::UpdateFirmwareByDeviceListResponse, RackManagerError> {
        Ok(self.client.update_firmware_by_device_list(cmd).await?)
    }
    async fn get_firmware_job_status(
        &self,
        cmd: rms::GetFirmwareJobStatusRequest,
    ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError> {
        Ok(self.client.get_firmware_job_status(cmd).await?)
    }
    async fn update_switch_system_password(
        &self,
        cmd: rms::UpdateSwitchSystemPasswordRequest,
    ) -> Result<rms::UpdateSwitchSystemPasswordResponse, RackManagerError> {
        Ok(self.client.update_switch_system_password(cmd).await?)
    }
}

#[derive(Debug)]
pub struct RmsTlsConnectionProvider {
    pub url: String,
    pub client_config: RmsClientConfig,
    pub retry_config: RetryConfig,
}

#[async_trait::async_trait]
impl tonic_client_wrapper::ConnectionProvider<RackManagerClientT> for RmsTlsConnectionProvider {
    async fn provide_connection(&self) -> Result<RackManagerClientT, Status> {
        let mut retries = 0;
        loop {
            match RmsTlsClient::retry_build_rms(
                &RmsApiConfig::new(&self.url, &self.client_config).with_retry_config(RetryConfig {
                    // We do our own retry counting
                    retries: 1,
                    interval: self.retry_config.interval,
                }),
            )
            .await
            .map_err(Into::into)
            {
                Ok(client) => return Ok(client),
                Err(e) => {
                    retries += 1;
                    if retries > self.retry_config.retries {
                        return Err(e);
                    }
                }
            }
        }
    }

    async fn connection_is_stale(&self, last_connected: SystemTime) -> bool {
        if let Some(ref client_cert) = self.client_config.client_cert {
            if let Ok(mtime) = fs::metadata(&client_cert.cert_path).and_then(|m| m.modified()) {
                if mtime > last_connected {
                    let old_cert_date = DateTime::<Utc>::from(last_connected);
                    let new_cert_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        cert_path = &client_cert.cert_path,
                        %old_cert_date,
                        %new_cert_date,
                        "RmsApiClient: Reconnecting to pick up newer client certificate"
                    );
                    true
                } else {
                    false
                }
            } else if let Ok(mtime) = fs::metadata(&client_cert.key_path).and_then(|m| m.modified())
            {
                // Just in case the cert and key are created some amount of time apart and we
                // last constructed a client with the new cert but the old key...
                if mtime > last_connected {
                    let old_key_date = DateTime::<Utc>::from(last_connected);
                    let new_key_date = DateTime::<Utc>::from(mtime);
                    tracing::info!(
                        key_path = &client_cert.key_path,
                        %old_key_date,
                        %new_key_date,
                        "RmsApiClient: Reconnecting to pick up newer client key"
                    );
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn connection_url(&self) -> &str {
        self.url.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::protos::rack_manager as rms;

    /// Compile-time trait bound check. The function body is empty and optimized away;
    /// the compiler just verifies T satisfies Serialize + DeserializeOwned. If the
    /// type_attribute in build.rs stops covering a type, the call site fails to compile.
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}

    /// Verifies that the single package-level type_attribute(".rack_manager", ...) in
    /// build.rs correctly applies serde derives to all proto-generated types. Covers
    /// the structurally distinct categories: plain messages, the oneof enum nested inside
    /// Credentials (which previously needed separate handling), top-level enums, and a
    /// request/response pair.
    #[test]
    fn proto_types_implement_serde() {
        // Plain message
        assert_serde::<rms::Credentials>();

        // Oneof enum — the case that previously required special handling in build.rs
        assert_serde::<rms::credentials::Auth>();

        // Top-level enums
        assert_serde::<rms::NodeType>();
        assert_serde::<rms::PowerOperation>();

        // Representative request/response pair
        assert_serde::<rms::SetPowerStateRequest>();
        assert_serde::<rms::SetPowerStateResponse>();
        assert_serde::<rms::SetScaleUpFabricStateRequest>();
        assert_serde::<rms::SetScaleUpFabricStateResponse>();
    }
}
