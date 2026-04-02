//! HTTP-based WebRTC signaling.
//!
//! Exchanges SDP offers/answers with a network node's signaling endpoint
//! using the browser's Fetch API.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[derive(Serialize)]
struct SdpOffer {
    #[serde(rename = "type")]
    sdp_type: String,
    sdp: String,
}

#[derive(Deserialize)]
pub struct SdpAnswer {
    #[serde(rename = "type")]
    pub sdp_type: String,
    pub sdp: String,
}

/// Exchange an SDP offer for an SDP answer via the node's HTTP signaling endpoint.
///
/// Posts the local SDP offer to `{signaling_url}/webrtc/sdp` and returns the
/// remote SDP answer.
pub async fn exchange_sdp(signaling_url: &str, local_sdp: &str) -> Result<SdpAnswer, String> {
    let url = format!("{}/webrtc/sdp", signaling_url.trim_end_matches('/'));

    let offer = SdpOffer {
        sdp_type: "offer".to_string(),
        sdp: local_sdp.to_string(),
    };
    let body =
        serde_json::to_string(&offer).map_err(|e| format!("failed to serialize offer: {e}"))?;

    let mut opts = web_sys::RequestInit::new();
    opts.method("POST");
    opts.body(Some(&JsValue::from_str(&body)));

    let request = web_sys::Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("failed to create request: {e:?}"))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| format!("failed to set header: {e:?}"))?;

    let window =
        web_sys::window().ok_or_else(|| "no window object (not in browser?)".to_string())?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| "response is not a Response object".to_string())?;

    if !resp.ok() {
        return Err(format!(
            "signaling server returned HTTP {}",
            resp.status()
        ));
    }

    let json = JsFuture::from(
        resp.json()
            .map_err(|e| format!("failed to read response body: {e:?}"))?,
    )
    .await
    .map_err(|e| format!("failed to parse response JSON: {e:?}"))?;

    let answer: SdpAnswer = serde_wasm_bindgen::from_value(json)
        .map_err(|e| format!("failed to deserialize SDP answer: {e}"))?;

    Ok(answer)
}
