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

use crate::client::{RackManagerClientT, RetryConfig, RmsApiConfig, RmsTlsClient};
use crate::client_config::RmsClientConfig;
use crate::protos::rack_manager as rms;
use crate::protos::rack_manager_client::RackManagerApiClient;

use chrono::{DateTime, Utc};
use tonic::Status;

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

    async fn batch_set_power_state(
        &self,
        cmd: rms::BatchSetPowerStateRequest,
    ) -> Result<rms::BatchSetPowerStateResponse, RackManagerError>;

    async fn get_power_state(
        &self,
        cmd: rms::GetPowerStateRequest,
    ) -> Result<rms::GetPowerStateResponse, RackManagerError>;

    async fn batch_get_power_state(
        &self,
        cmd: rms::BatchGetPowerStateRequest,
    ) -> Result<rms::BatchGetPowerStateResponse, RackManagerError>;

    async fn sequence_rack_power(
        &self,
        cmd: rms::SequenceRackPowerRequest,
    ) -> Result<rms::SequenceRackPowerResponse, RackManagerError>;

    async fn list_node_inventory(&self)
    -> Result<rms::ListNodeInventoryResponse, RackManagerError>;

    async fn create_nodes(
        &self,
        cmd: rms::CreateNodesRequest,
    ) -> Result<rms::CreateNodesResponse, RackManagerError>;

    async fn update_node(
        &self,
        cmd: rms::UpdateNodeRequest,
    ) -> Result<rms::UpdateNodeResponse, RackManagerError>;

    async fn delete_node(
        &self,
        cmd: rms::DeleteNodeRequest,
    ) -> Result<rms::DeleteNodeResponse, RackManagerError>;

    async fn get_rack_power_on_sequence(
        &self,
        cmd: rms::GetRackPowerOnSequenceRequest,
    ) -> Result<rms::GetRackPowerOnSequenceResponse, RackManagerError>;

    async fn set_rack_power_on_sequence(
        &self,
        cmd: rms::SetRackPowerOnSequenceRequest,
    ) -> Result<rms::SetRackPowerOnSequenceResponse, RackManagerError>;

    async fn list_racks(&self) -> Result<rms::ListRacksResponse, RackManagerError>;

    async fn get_node_device_info(
        &self,
        cmd: rms::GetNodeDeviceInfoRequest,
    ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError>;

    async fn list_node_device_info_by_node_type(
        &self,
        cmd: rms::ListNodeDeviceInfoByNodeTypeRequest,
    ) -> Result<rms::ListNodeDeviceInfoByNodeTypeResponse, RackManagerError>;

    async fn batch_get_node_device_info(
        &self,
        cmd: rms::BatchGetNodeDeviceInfoRequest,
    ) -> Result<rms::BatchGetNodeDeviceInfoResponse, RackManagerError>;

    async fn get_node_firmware_inventory(
        &self,
        cmd: rms::GetNodeFirmwareInventoryRequest,
    ) -> Result<rms::GetNodeFirmwareInventoryResponse, RackManagerError>;

    async fn get_rack_firmware_inventory(
        &self,
        cmd: rms::GetRackFirmwareInventoryRequest,
    ) -> Result<rms::GetRackFirmwareInventoryResponse, RackManagerError>;

    async fn update_firmware(
        &self,
        cmd: rms::UpdateFirmwareRequest,
    ) -> Result<rms::UpdateFirmwareResponse, RackManagerError>;

    async fn batch_update_firmware_by_node_type(
        &self,
        cmd: rms::BatchUpdateFirmwareByNodeTypeRequest,
    ) -> Result<rms::BatchUpdateFirmwareByNodeTypeResponse, RackManagerError>;

    async fn batch_update_firmware(
        &self,
        cmd: rms::BatchUpdateFirmwareRequest,
    ) -> Result<rms::BatchUpdateFirmwareResponse, RackManagerError>;

    async fn update_switch_system_image(
        &self,
        cmd: rms::UpdateSwitchSystemImageRequest,
    ) -> Result<rms::UpdateSwitchSystemImageResponse, RackManagerError>;

    async fn add_firmware_object(
        &self,
        cmd: rms::AddFirmwareObjectRequest,
    ) -> Result<rms::AddFirmwareObjectResponse, RackManagerError>;

    async fn get_firmware_object(
        &self,
        cmd: rms::GetFirmwareObjectRequest,
    ) -> Result<rms::GetFirmwareObjectResponse, RackManagerError>;

    async fn list_firmware_objects(
        &self,
        cmd: rms::ListFirmwareObjectsRequest,
    ) -> Result<rms::ListFirmwareObjectsResponse, RackManagerError>;

    async fn delete_firmware_object(
        &self,
        cmd: rms::DeleteFirmwareObjectRequest,
    ) -> Result<rms::DeleteFirmwareObjectResponse, RackManagerError>;

    async fn set_default_firmware_object(
        &self,
        cmd: rms::SetDefaultFirmwareObjectRequest,
    ) -> Result<rms::SetDefaultFirmwareObjectResponse, RackManagerError>;

    async fn apply_stored_firmware_object(
        &self,
        cmd: rms::ApplyStoredFirmwareObjectRequest,
    ) -> Result<rms::ApplyStoredFirmwareObjectResponse, RackManagerError>;

    async fn apply_firmware_object(
        &self,
        cmd: rms::ApplyFirmwareObjectRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError>;

    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError>;

    async fn apply_stored_switch_system_image(
        &self,
        cmd: rms::ApplyStoredSwitchSystemImageRequest,
    ) -> Result<rms::ApplyStoredSwitchSystemImageResponse, RackManagerError>;

    async fn get_firmware_object_history(
        &self,
        cmd: rms::GetFirmwareObjectHistoryRequest,
    ) -> Result<rms::GetFirmwareObjectHistoryResponse, RackManagerError>;

    async fn list_switch_firmware(
        &self,
        cmd: rms::ListSwitchFirmwareRequest,
    ) -> Result<rms::ListSwitchFirmwareResponse, RackManagerError>;

    async fn push_switch_firmware(
        &self,
        cmd: rms::PushSwitchFirmwareRequest,
    ) -> Result<rms::PushSwitchFirmwareResponse, RackManagerError>;

    async fn configure_scale_up_fabric_manager(
        &self,
        cmd: rms::ConfigureScaleUpFabricManagerRequest,
    ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError>;

    async fn batch_reset_switch_sdn_factory_default(
        &self,
        cmd: rms::BatchResetSwitchSdnFactoryDefaultRequest,
    ) -> Result<rms::BatchResetSwitchSdnFactoryDefaultResponse, RackManagerError>;

    async fn batch_set_scale_up_fabric_state(
        &self,
        cmd: rms::BatchSetScaleUpFabricStateRequest,
    ) -> Result<rms::BatchSetScaleUpFabricStateResponse, RackManagerError>;

    async fn batch_get_scale_up_fabric_service_status(
        &self,
        cmd: rms::BatchGetScaleUpFabricServiceStatusRequest,
    ) -> Result<rms::BatchGetScaleUpFabricServiceStatusResponse, RackManagerError>;

    async fn get_scale_up_fabric_state(
        &self,
        cmd: rms::GetScaleUpFabricStateRequest,
    ) -> Result<rms::GetScaleUpFabricStateResponse, RackManagerError>;

    async fn set_scale_up_fabric_telemetry_interface_state(
        &self,
        cmd: rms::SetScaleUpFabricTelemetryInterfaceStateRequest,
    ) -> Result<rms::SetScaleUpFabricTelemetryInterfaceStateResponse, RackManagerError>;

    async fn configure_switch_certificate(
        &self,
        cmd: rms::ConfigureSwitchCertificateRequest,
    ) -> Result<rms::ConfigureSwitchCertificateResponse, RackManagerError>;

    async fn get_configure_switch_certificate_job_status(
        &self,
        cmd: rms::GetConfigureSwitchCertificateJobStatusRequest,
    ) -> Result<rms::GetConfigureSwitchCertificateJobStatusResponse, RackManagerError>;

    async fn list_switch_system_images(
        &self,
        cmd: rms::ListSwitchSystemImagesRequest,
    ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError>;

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, RackManagerError>;

    async fn update_switch_system_password(
        &self,
        cmd: rms::UpdateSwitchSystemPasswordRequest,
    ) -> Result<rms::UpdateSwitchSystemPasswordResponse, RackManagerError>;

    async fn get_version(&self) -> Result<rms::GetVersionResponse, RackManagerError>;

    async fn get_firmware_job_status(
        &self,
        cmd: rms::GetFirmwareJobStatusRequest,
    ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError>;

    async fn get_job_status(
        &self,
        cmd: rms::GetJobStatusRequest,
    ) -> Result<rms::GetJobStatusResponse, RackManagerError>;
}

#[async_trait::async_trait]
impl RmsApi for RackManagerApi {
    async fn set_power_state(
        &self,
        cmd: rms::SetPowerStateRequest,
    ) -> Result<rms::SetPowerStateResponse, RackManagerError> {
        Ok(self.client.set_power_state(cmd).await?)
    }

    async fn batch_set_power_state(
        &self,
        cmd: rms::BatchSetPowerStateRequest,
    ) -> Result<rms::BatchSetPowerStateResponse, RackManagerError> {
        Ok(self.client.batch_set_power_state(cmd).await?)
    }

    async fn get_power_state(
        &self,
        cmd: rms::GetPowerStateRequest,
    ) -> Result<rms::GetPowerStateResponse, RackManagerError> {
        Ok(self.client.get_power_state(cmd).await?)
    }

    async fn batch_get_power_state(
        &self,
        cmd: rms::BatchGetPowerStateRequest,
    ) -> Result<rms::BatchGetPowerStateResponse, RackManagerError> {
        Ok(self.client.batch_get_power_state(cmd).await?)
    }

    async fn sequence_rack_power(
        &self,
        cmd: rms::SequenceRackPowerRequest,
    ) -> Result<rms::SequenceRackPowerResponse, RackManagerError> {
        Ok(self.client.sequence_rack_power(cmd).await?)
    }

    async fn list_node_inventory(
        &self,
    ) -> Result<rms::ListNodeInventoryResponse, RackManagerError> {
        Ok(self.client.list_node_inventory().await?)
    }

    async fn create_nodes(
        &self,
        cmd: rms::CreateNodesRequest,
    ) -> Result<rms::CreateNodesResponse, RackManagerError> {
        Ok(self.client.create_nodes(cmd).await?)
    }

    async fn update_node(
        &self,
        cmd: rms::UpdateNodeRequest,
    ) -> Result<rms::UpdateNodeResponse, RackManagerError> {
        Ok(self.client.update_node(cmd).await?)
    }

    async fn delete_node(
        &self,
        cmd: rms::DeleteNodeRequest,
    ) -> Result<rms::DeleteNodeResponse, RackManagerError> {
        Ok(self.client.delete_node(cmd).await?)
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

    async fn list_racks(&self) -> Result<rms::ListRacksResponse, RackManagerError> {
        Ok(self.client.list_racks().await?)
    }

    async fn get_node_device_info(
        &self,
        cmd: rms::GetNodeDeviceInfoRequest,
    ) -> Result<rms::GetNodeDeviceInfoResponse, RackManagerError> {
        Ok(self.client.get_node_device_info(cmd).await?)
    }

    async fn list_node_device_info_by_node_type(
        &self,
        cmd: rms::ListNodeDeviceInfoByNodeTypeRequest,
    ) -> Result<rms::ListNodeDeviceInfoByNodeTypeResponse, RackManagerError> {
        Ok(self.client.list_node_device_info_by_node_type(cmd).await?)
    }

    async fn batch_get_node_device_info(
        &self,
        cmd: rms::BatchGetNodeDeviceInfoRequest,
    ) -> Result<rms::BatchGetNodeDeviceInfoResponse, RackManagerError> {
        Ok(self.client.batch_get_node_device_info(cmd).await?)
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

    async fn update_firmware(
        &self,
        cmd: rms::UpdateFirmwareRequest,
    ) -> Result<rms::UpdateFirmwareResponse, RackManagerError> {
        Ok(self.client.update_firmware(cmd).await?)
    }

    async fn batch_update_firmware_by_node_type(
        &self,
        cmd: rms::BatchUpdateFirmwareByNodeTypeRequest,
    ) -> Result<rms::BatchUpdateFirmwareByNodeTypeResponse, RackManagerError> {
        Ok(self.client.batch_update_firmware_by_node_type(cmd).await?)
    }

    async fn batch_update_firmware(
        &self,
        cmd: rms::BatchUpdateFirmwareRequest,
    ) -> Result<rms::BatchUpdateFirmwareResponse, RackManagerError> {
        Ok(self.client.batch_update_firmware(cmd).await?)
    }

    async fn update_switch_system_image(
        &self,
        cmd: rms::UpdateSwitchSystemImageRequest,
    ) -> Result<rms::UpdateSwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.update_switch_system_image(cmd).await?)
    }

    async fn add_firmware_object(
        &self,
        cmd: rms::AddFirmwareObjectRequest,
    ) -> Result<rms::AddFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.add_firmware_object(cmd).await?)
    }

    async fn get_firmware_object(
        &self,
        cmd: rms::GetFirmwareObjectRequest,
    ) -> Result<rms::GetFirmwareObjectResponse, RackManagerError> {
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
    ) -> Result<rms::DeleteFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.delete_firmware_object(cmd).await?)
    }

    async fn set_default_firmware_object(
        &self,
        cmd: rms::SetDefaultFirmwareObjectRequest,
    ) -> Result<rms::SetDefaultFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.set_default_firmware_object(cmd).await?)
    }

    async fn apply_stored_firmware_object(
        &self,
        cmd: rms::ApplyStoredFirmwareObjectRequest,
    ) -> Result<rms::ApplyStoredFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.apply_stored_firmware_object(cmd).await?)
    }

    async fn apply_firmware_object(
        &self,
        cmd: rms::ApplyFirmwareObjectRequest,
    ) -> Result<rms::ApplyFirmwareObjectResponse, RackManagerError> {
        Ok(self.client.apply_firmware_object(cmd).await?)
    }

    async fn apply_switch_system_image(
        &self,
        cmd: rms::ApplySwitchSystemImageRequest,
    ) -> Result<rms::ApplySwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.apply_switch_system_image(cmd).await?)
    }

    async fn apply_stored_switch_system_image(
        &self,
        cmd: rms::ApplyStoredSwitchSystemImageRequest,
    ) -> Result<rms::ApplyStoredSwitchSystemImageResponse, RackManagerError> {
        Ok(self.client.apply_stored_switch_system_image(cmd).await?)
    }

    async fn get_firmware_object_history(
        &self,
        cmd: rms::GetFirmwareObjectHistoryRequest,
    ) -> Result<rms::GetFirmwareObjectHistoryResponse, RackManagerError> {
        Ok(self.client.get_firmware_object_history(cmd).await?)
    }

    async fn list_switch_firmware(
        &self,
        cmd: rms::ListSwitchFirmwareRequest,
    ) -> Result<rms::ListSwitchFirmwareResponse, RackManagerError> {
        Ok(self.client.list_switch_firmware(cmd).await?)
    }

    async fn push_switch_firmware(
        &self,
        cmd: rms::PushSwitchFirmwareRequest,
    ) -> Result<rms::PushSwitchFirmwareResponse, RackManagerError> {
        Ok(self.client.push_switch_firmware(cmd).await?)
    }

    async fn configure_scale_up_fabric_manager(
        &self,
        cmd: rms::ConfigureScaleUpFabricManagerRequest,
    ) -> Result<rms::ConfigureScaleUpFabricManagerResponse, RackManagerError> {
        Ok(self.client.configure_scale_up_fabric_manager(cmd).await?)
    }

    async fn batch_reset_switch_sdn_factory_default(
        &self,
        cmd: rms::BatchResetSwitchSdnFactoryDefaultRequest,
    ) -> Result<rms::BatchResetSwitchSdnFactoryDefaultResponse, RackManagerError> {
        Ok(self
            .client
            .batch_reset_switch_sdn_factory_default(cmd)
            .await?)
    }

    async fn batch_set_scale_up_fabric_state(
        &self,
        cmd: rms::BatchSetScaleUpFabricStateRequest,
    ) -> Result<rms::BatchSetScaleUpFabricStateResponse, RackManagerError> {
        Ok(self.client.batch_set_scale_up_fabric_state(cmd).await?)
    }

    async fn batch_get_scale_up_fabric_service_status(
        &self,
        cmd: rms::BatchGetScaleUpFabricServiceStatusRequest,
    ) -> Result<rms::BatchGetScaleUpFabricServiceStatusResponse, RackManagerError> {
        Ok(self
            .client
            .batch_get_scale_up_fabric_service_status(cmd)
            .await?)
    }

    async fn get_scale_up_fabric_state(
        &self,
        cmd: rms::GetScaleUpFabricStateRequest,
    ) -> Result<rms::GetScaleUpFabricStateResponse, RackManagerError> {
        Ok(self.client.get_scale_up_fabric_state(cmd).await?)
    }

    async fn set_scale_up_fabric_telemetry_interface_state(
        &self,
        cmd: rms::SetScaleUpFabricTelemetryInterfaceStateRequest,
    ) -> Result<rms::SetScaleUpFabricTelemetryInterfaceStateResponse, RackManagerError> {
        Ok(self
            .client
            .set_scale_up_fabric_telemetry_interface_state(cmd)
            .await?)
    }

    async fn configure_switch_certificate(
        &self,
        cmd: rms::ConfigureSwitchCertificateRequest,
    ) -> Result<rms::ConfigureSwitchCertificateResponse, RackManagerError> {
        Ok(self.client.configure_switch_certificate(cmd).await?)
    }

    async fn get_configure_switch_certificate_job_status(
        &self,
        cmd: rms::GetConfigureSwitchCertificateJobStatusRequest,
    ) -> Result<rms::GetConfigureSwitchCertificateJobStatusResponse, RackManagerError> {
        Ok(self
            .client
            .get_configure_switch_certificate_job_status(cmd)
            .await?)
    }

    async fn list_switch_system_images(
        &self,
        cmd: rms::ListSwitchSystemImagesRequest,
    ) -> Result<rms::ListSwitchSystemImagesResponse, RackManagerError> {
        Ok(self.client.list_switch_system_images(cmd).await?)
    }

    async fn get_switch_system_image_job_status(
        &self,
        cmd: rms::GetSwitchSystemImageJobStatusRequest,
    ) -> Result<rms::GetSwitchSystemImageJobStatusResponse, RackManagerError> {
        Ok(self.client.get_switch_system_image_job_status(cmd).await?)
    }

    async fn update_switch_system_password(
        &self,
        cmd: rms::UpdateSwitchSystemPasswordRequest,
    ) -> Result<rms::UpdateSwitchSystemPasswordResponse, RackManagerError> {
        Ok(self.client.update_switch_system_password(cmd).await?)
    }

    async fn get_version(&self) -> Result<rms::GetVersionResponse, RackManagerError> {
        Ok(self.client.get_version().await?)
    }

    async fn get_firmware_job_status(
        &self,
        cmd: rms::GetFirmwareJobStatusRequest,
    ) -> Result<rms::GetFirmwareJobStatusResponse, RackManagerError> {
        Ok(self.client.get_firmware_job_status(cmd).await?)
    }

    async fn get_job_status(
        &self,
        cmd: rms::GetJobStatusRequest,
    ) -> Result<rms::GetJobStatusResponse, RackManagerError> {
        Ok(self.client.get_job_status(cmd).await?)
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
