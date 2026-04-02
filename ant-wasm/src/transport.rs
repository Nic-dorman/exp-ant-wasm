//! WebRTC data channel transport.
//!
//! Wraps the browser's `RTCPeerConnection` and `RTCDataChannel` APIs
//! to provide a request/response interface for chunk protocol messages.

use crate::signaling;
use js_sys::{ArrayBuffer, Uint8Array};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    MessageEvent, RtcDataChannel, RtcDataChannelInit, RtcDataChannelState, RtcPeerConnection,
    RtcSdpType, RtcSessionDescriptionInit,
};

/// Pending response state: a oneshot-style channel for request/response correlation.
type PendingMap = Rc<RefCell<HashMap<u64, js_sys::Function>>>;

/// WebRTC data channel transport for communicating with an Autonomi network node.
pub struct WebRtcTransport {
    pc: RtcPeerConnection,
    dc: RtcDataChannel,
    pending: PendingMap,
}

impl WebRtcTransport {
    /// Connect to a node's WebRTC signaling endpoint and establish a data channel.
    pub async fn connect(signaling_url: &str) -> Result<Self, String> {
        // Create peer connection (use default ICE servers for now)
        let pc = RtcPeerConnection::new()
            .map_err(|e| format!("failed to create RTCPeerConnection: {e:?}"))?;

        // Create data channel before creating offer (required for offer to include DC)
        let mut dc_init = RtcDataChannelInit::new();
        dc_init.ordered(true);
        let dc = pc.create_data_channel_with_data_channel_dict("chunks", &dc_init);
        dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);

        // Create and set local offer
        let offer = JsFuture::from(pc.create_offer())
            .await
            .map_err(|e| format!("failed to create offer: {e:?}"))?;

        let offer_sdp = js_sys::Reflect::get(&offer, &JsValue::from_str("sdp"))
            .map_err(|e| format!("failed to get offer sdp: {e:?}"))?
            .as_string()
            .ok_or("offer sdp is not a string")?;

        let mut local_desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
        local_desc.sdp(&offer_sdp);
        JsFuture::from(pc.set_local_description(&local_desc))
            .await
            .map_err(|e| format!("failed to set local description: {e:?}"))?;

        // Exchange SDP with the node's signaling endpoint
        let answer = signaling::exchange_sdp(signaling_url, &offer_sdp).await?;

        // Set remote answer
        let mut remote_desc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        remote_desc.sdp(&answer.sdp);
        JsFuture::from(pc.set_remote_description(&remote_desc))
            .await
            .map_err(|e| format!("failed to set remote description: {e:?}"))?;

        // Wait for the data channel to open
        wait_for_dc_open(&dc).await?;

        // Set up response handler
        let pending: PendingMap = Rc::new(RefCell::new(HashMap::new()));
        setup_message_handler(&dc, pending.clone());

        Ok(Self { pc, dc, pending })
    }

    /// Send a chunk protocol message and await the response.
    ///
    /// The message must be a postcard-encoded `ChunkMessage` with a `request_id`.
    /// The response is correlated by `request_id` and returned as raw bytes.
    pub async fn send_request(
        &self,
        request_id: u64,
        message_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.dc.ready_state() != RtcDataChannelState::Open {
            return Err("data channel is not open".to_string());
        }

        // Create a promise that resolves when the response arrives
        let (promise, resolve) = new_resolve_pair();

        // Register the pending request
        self.pending.borrow_mut().insert(request_id, resolve);

        // Send the message with a 4-byte length prefix
        let len = message_bytes.len() as u32;
        let mut framed = Vec::with_capacity(4 + message_bytes.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(message_bytes);

        let array = Uint8Array::from(framed.as_slice());
        self.dc
            .send_with_array_buffer_view(&array)
            .map_err(|e| format!("failed to send: {e:?}"))?;

        // Await the response
        let response_value = JsFuture::from(promise)
            .await
            .map_err(|e| format!("request failed: {e:?}"))?;

        let response_array: Uint8Array = response_value
            .dyn_into()
            .map_err(|_| "response is not a Uint8Array".to_string())?;

        Ok(response_array.to_vec())
    }

    /// Close the WebRTC connection.
    pub fn close(&self) {
        self.dc.close();
        self.pc.close();
    }
}

/// Wait for the data channel to reach the "open" state.
async fn wait_for_dc_open(dc: &RtcDataChannel) -> Result<(), String> {
    if dc.ready_state() == RtcDataChannelState::Open {
        return Ok(());
    }

    let (promise, resolve) = new_resolve_pair();

    let resolve_clone = resolve.clone();
    let onopen = Closure::once_into_js(move || {
        let _ = resolve_clone.call0(&JsValue::NULL);
    });
    dc.set_onopen(Some(onopen.unchecked_ref()));

    // Also handle errors
    let (err_promise, err_resolve) = new_resolve_pair();
    let err_resolve_clone = err_resolve.clone();
    let onerror = Closure::once_into_js(move |_: web_sys::Event| {
        let _ = err_resolve_clone.call1(&JsValue::NULL, &JsValue::from_str("DC open failed"));
    });
    dc.set_onerror(Some(onerror.unchecked_ref()));

    // Race: either opens successfully or errors
    let result = js_sys::Promise::race(&js_sys::Array::of2(&promise, &err_promise));
    JsFuture::from(result)
        .await
        .map_err(|e| format!("data channel failed to open: {e:?}"))?;

    if dc.ready_state() != RtcDataChannelState::Open {
        return Err("data channel did not reach open state".to_string());
    }

    Ok(())
}

/// Set up the onmessage handler that routes responses to pending requests.
fn setup_message_handler(dc: &RtcDataChannel, pending: PendingMap) {
    let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();

        // Data channel messages arrive as ArrayBuffer
        let buffer: ArrayBuffer = match data.dyn_into() {
            Ok(buf) => buf,
            Err(_) => return,
        };

        let array = Uint8Array::new(&buffer);
        let bytes = array.to_vec();

        // Strip the 4-byte length prefix
        if bytes.len() < 4 {
            return;
        }
        let payload = &bytes[4..];

        // Try to extract the request_id from the postcard-encoded ChunkMessage.
        // The request_id is a varint at the start of the message.
        if let Ok(msg) = ant_protocol::ChunkMessage::decode(payload) {
            let mut pending_map = pending.borrow_mut();
            if let Some(resolve) = pending_map.remove(&msg.request_id) {
                let response = Uint8Array::from(payload);
                let _ = resolve.call1(&JsValue::NULL, &response);
            }
        }
    }) as Box<dyn FnMut(MessageEvent)>);

    dc.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget(); // prevent the closure from being dropped
}

/// Create a JS Promise and its resolve function.
fn new_resolve_pair() -> (js_sys::Promise, js_sys::Function) {
    let resolve_holder: Rc<RefCell<Option<js_sys::Function>>> = Rc::new(RefCell::new(None));
    let resolve_clone = resolve_holder.clone();

    let promise = js_sys::Promise::new(&mut move |resolve, _reject| {
        *resolve_clone.borrow_mut() = Some(resolve);
    });

    let resolve = resolve_holder
        .borrow_mut()
        .take()
        .expect("resolve function should be set");

    (promise, resolve)
}
