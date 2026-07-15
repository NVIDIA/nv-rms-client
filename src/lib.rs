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

#[cfg(feature = "client")]
mod client_api;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod client_config;
pub mod protos;
#[cfg(feature = "serde")]
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

#[cfg(feature = "client")]
pub(crate) use client::RackManagerClientT;

#[cfg(feature = "client")]
pub use client_api::*;

#[cfg(test)]
mod proto_model_tests {
    use super::protos::rack_manager::NodeType;

    #[test]
    fn vrnvl72_node_types_have_stable_wire_values_and_names() {
        assert_eq!(NodeType::ComputeVrnvl72Nvidia as i32, 10);
        assert_eq!(NodeType::SwitchVrnvl72Nvidia as i32, 11);

        assert_eq!(
            NodeType::ComputeVrnvl72Nvidia.as_str_name(),
            "COMPUTE_VRNVL72_NVIDIA"
        );
        assert_eq!(
            NodeType::SwitchVrnvl72Nvidia.as_str_name(),
            "SWITCH_VRNVL72_NVIDIA"
        );

        assert_eq!(
            NodeType::from_str_name("COMPUTE_VRNVL72_NVIDIA"),
            Some(NodeType::ComputeVrnvl72Nvidia)
        );
        assert_eq!(
            NodeType::from_str_name("SWITCH_VRNVL72_NVIDIA"),
            Some(NodeType::SwitchVrnvl72Nvidia)
        );
    }
}

#[cfg(all(test, feature = "client"))]
mod client_feature_tests {
    use super::*;

    fn assert_public_type<T: ?Sized>() -> &'static str {
        std::any::type_name::<T>()
    }

    #[test]
    fn client_feature_exposes_expected_public_api_paths() {
        let public_api_types = [
            assert_public_type::<RackManagerApi>(),
            assert_public_type::<RmsClientPool>(),
            assert_public_type::<dyn RmsApi>(),
            assert_public_type::<client::RmsTlsClient<'static>>(),
            assert_public_type::<client_config::RmsClientConfig>(),
            assert_public_type::<
                protos::rack_manager::rack_manager_client::RackManagerClient<
                    tonic::transport::Channel,
                >,
            >(),
            assert_public_type::<protos::rack_manager_client::RackManagerApiClient>(),
        ];

        assert_eq!(public_api_types.len(), 7);
    }
}

#[cfg(all(test, feature = "server"))]
mod server_feature_tests {
    use super::*;

    #[test]
    fn server_feature_exposes_generated_server_type() {
        let server_type = std::any::type_name::<
            protos::rack_manager::rack_manager_server::RackManagerServer<()>,
        >();

        assert!(server_type.ends_with("RackManagerServer<()>"));
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::protos::rack_manager as rms;

    /// Compile-time trait bound check. The function body is empty and optimized away;
    /// the compiler just verifies T satisfies Serialize + DeserializeOwned. If the
    /// type_attribute in build.rs stops covering a type, the call site fails to compile.
    fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}

    /// Verifies that the single package-level type_attribute(".rack_manager", ...) in
    /// build.rs correctly applies serde derives to all proto-generated types. Covers
    /// the structurally distinct categories: plain messages, the oneof enum nested inside
    /// Credentials (which previously needed separate handling), top-level enums,
    /// request/response pairs, and timestamp-backed responses.
    #[test]
    fn proto_types_implement_serde() {
        // Plain message
        assert_serde::<rms::Credentials>();
        assert_serde::<rms::ComponentInventoryInfo>();

        // Oneof enum - the case that previously required special handling in build.rs
        assert_serde::<rms::credentials::Auth>();

        // Top-level enums
        assert_serde::<rms::NodeType>();
        assert_serde::<rms::PowerOperation>();
        assert_serde::<rms::SwitchService>();

        // Representative request/response pair
        assert_serde::<rms::SetPowerStateRequest>();
        assert_serde::<rms::SetPowerStateResponse>();
        assert_serde::<rms::BatchSetScaleUpFabricStateRequest>();
        assert_serde::<rms::BatchSetScaleUpFabricStateResponse>();
        assert_serde::<rms::BatchResetSwitchSdnFactoryDefaultRequest>();
        assert_serde::<rms::BatchResetSwitchSdnFactoryDefaultResponse>();
        assert_serde::<rms::JobStatus>();
        assert_serde::<rms::GetJobStatusRequest>();
        assert_serde::<rms::GetJobStatusResponse>();
        assert_serde::<rms::ConfigureSwitchCertificateRequest>();
        assert_serde::<rms::ConfigureSwitchCertificateResponse>();
        assert_serde::<rms::ConfigureSwitchCertificateJobInfo>();
        assert_serde::<rms::GetConfigureSwitchCertificateJobStatusRequest>();
        assert_serde::<rms::GetConfigureSwitchCertificateJobStatusResponse>();

        // Timestamp-backed responses
        assert_serde::<rms::GetFirmwareJobStatusResponse>();
        assert_serde::<rms::GetSwitchSystemImageJobStatusResponse>();
    }
}
