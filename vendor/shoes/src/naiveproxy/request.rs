use std::io;
use http::{HeaderMap, HeaderValue, Method, Request, Version};
use rand::RngExt;
use crate::address::NetLocation;
use super::{options::Headers, naive_padding_stream::{PaddingType, generate_padding_header}};

pub(super) fn connect_request(
    target: &NetLocation, authorization: &str, padding: bool, headers: &Headers, version: Version,
) -> io::Result<Request<()>> {
    let mut request = Request::builder().method(Method::CONNECT)
        .uri(super::naive_client_session::format_authority(target)).version(version).body(())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    *request.headers_mut() = headers.parsed()?;
    let mut authorization = HeaderValue::from_str(authorization)
        .map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"invalid proxy authorization"))?;
    authorization.set_sensitive(true);
    request.headers_mut().insert("proxy-authorization", authorization);
    if padding {
        request.headers_mut().insert("padding", HeaderValue::from_str(&generate_padding_header(rand::rng().random_range(16..=32))).unwrap());
        request.headers_mut().insert("padding-type-request",HeaderValue::from_static("1, 0"));
    }
    Ok(request)
}

pub(super) fn response_padding(headers: &HeaderMap, enabled: bool) -> io::Result<PaddingType> {
    if !enabled { return Ok(PaddingType::None); }
    if let Some(value) = headers.get("padding-type-reply") {
        return value.to_str().ok().and_then(|v|v.trim().parse::<u8>().ok())
            .and_then(PaddingType::from_u8)
            .ok_or_else(||io::Error::new(io::ErrorKind::InvalidData,"unsupported Naive padding type"));
    }
    Ok(if headers.contains_key("padding") { PaddingType::Variant1 } else { PaddingType::None })
}

pub(super) fn uot_target(version: u8) -> crate::address::ResolvedLocation {
    NetLocation::new(crate::address::Address::Hostname(if version == 1 {crate::uot::UOT_V1_MAGIC_ADDRESS} else {crate::uot::UOT_V2_MAGIC_ADDRESS}.into()), 0).into()
}
