//! Lossless SRS export for the application's rule editor.
use super::{srs, singbox};
use crate::rules::{Compiler, Expression, invalid};
use serde_json::{Value, json};
use std::io;

pub fn validate_bytes(bytes: &[u8], binary: bool) -> io::Result<()> {
    let mut compiler = Compiler::default();
    let expression = if binary { srs::decode(bytes, &mut compiler)? } else { singbox::decode(bytes, &mut compiler)? };
    compiler.compile(expression)?;
    Ok(())
}

pub fn decompile_srs(bytes: &[u8]) -> io::Result<Value> {
    let expression = srs::decode(bytes, &mut Compiler::default())?;
    let rules = if matches!(&expression, Expression::Never) { vec![] } else { vec![export(expression)?] };
    Ok(json!({"version":3,"rules":rules}))
}

fn export(expression: Expression) -> io::Result<Value> {
    use Expression::*;
    let expression = match expression {
        Expression::Domain(ref v) | Expression::DomainSuffix(ref v) | Expression::Subdomains(ref v) | Expression::DomainKeyword(ref v) | Expression::DomainRegex(ref v) | Expression::IpCidr(ref v) if v.is_empty() => Expression::Never,
        Expression::Ranges(ref ranges, _) if ranges.is_empty() => Expression::Never,
        other => other,
    };
    Ok(match expression {
        AnyDestination(value) => json!({"port_range":["0:65535"],"invert":!value}),
        Never => json!({"port_range":["0:65535"],"invert":true}),
        Domain(v) => json!({"domain":v}),
        DomainSuffix(v) => json!({"domain_suffix":v}),
        Subdomains(v) => json!({"domain_suffix":v.into_iter().map(|v|format!(".{v}")).collect::<Vec<_>>()}),
        DomainKeyword(v) => json!({"domain_keyword":v}),
        DomainRegex(v) => json!({"domain_regex":v}),
        IpCidr(v) => json!({"ip_cidr":v}),
        DestinationPort(v) => json!({"port":v}),
        DestinationPortRange(v) => json!({"port_range":v}),
        PortRanges(v) => json!({"port_range":v.into_iter().map(|(a,b)|format!("{a}:{b}")).collect::<Vec<_>>()}),
        Network(v) => json!({"network":v}),
        Protocol(v) => json!({"protocol":v}),
        All(v) | Any(v) if v.is_empty() => return Err(invalid("unexpected empty SRS logical rule")),
        All(v) => json!({"type":"logical","mode":"and","rules":v.into_iter().map(export).collect::<io::Result<Vec<_>>>()?}),
        Any(v) => json!({"type":"logical","mode":"or","rules":v.into_iter().map(export).collect::<io::Result<Vec<_>>>()?}),
        Not(child) => {let mut value=export(*child)?;let invert=value["invert"].as_bool().unwrap_or(false);value["invert"]=(!invert).into();value},
        Ranges(ranges, false) => {
            let mut cidrs=vec![];
            for (start,end) in ranges.v4 { cidrs.extend(range_cidrs(u128::from(start),u128::from(end),32)); }
            for (start,end) in ranges.v6 { cidrs.extend(range_cidrs(start,end,128)); }
            json!({"ip_cidr":cidrs})
        }
        _ => return Err(invalid("SRS expression cannot be represented by source JSON")),
    })
}
fn range_cidrs(mut start:u128,end:u128,bits:u32)->Vec<String> {
    let mut out=vec![];
    loop {
        let aligned=start.trailing_zeros().min(bits);
        let remaining=if start==0 && end==u128::MAX {128}else{127-(end-start+1).leading_zeros()};
        let host_bits=aligned.min(remaining);
        let ip=if bits==32 {std::net::IpAddr::V4(std::net::Ipv4Addr::from(start as u32))} else {std::net::IpAddr::V6(std::net::Ipv6Addr::from(start))};
        out.push(format!("{ip}/{}",bits-host_bits));
        if host_bits==128 {break;}
        let Some(next)=start.checked_add(1u128<<host_bits) else{break;};
        if next>end {break;}
        start=next;
    }
    out
}
