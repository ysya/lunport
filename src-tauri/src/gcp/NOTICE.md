# Third-party notice: Google Cloud SDK (gcloud)

`relay.rs` and `iap.rs` in this directory are a Rust port of the IAP TCP-forwarding client in the Google Cloud SDK, version 590.0.0:

- `lib/googlecloudsdk/api_lib/compute/iap_tunnel_websocket.py`
- `lib/googlecloudsdk/api_lib/compute/iap_tunnel_websocket_utils.py`
- `lib/googlecloudsdk/api_lib/compute/iap_tunnel_websocket_helper.py`
- `lib/googlecloudsdk/api_lib/compute/iap_tunnel_lightweight_websocket.py`

Copyright 2018 Google LLC. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use those files except in compliance with the License. You may obtain a copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>. Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

The port keeps the protocol constants, the frame layout, the acknowledgement rules and the reconnect limits of the original; the code itself is written for Lunport's tokio-based engine. `cedws/iapc` (MIT or GPL-3.0) was consulted as a cross-check only; nothing from it is included. The rest of Lunport is licensed under PolyForm Noncommercial 1.0.0 (see `/LICENSE`).
