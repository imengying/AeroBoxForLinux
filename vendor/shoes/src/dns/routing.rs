//! DNS policy and named endpoint resolvers. Policies never fall back to an
//! unrelated resolver after an upstream error, and FakeIP is interception-only.
use super::IpStrategy;
use crate::{
    address::NetLocation,
    config::dns::{DnsRoutingConfig, DomainResolverConfig},
    resolver::{DnsExchangeFuture, ResolveFuture, Resolver},
    rules::Outcome,
};
use hickory_resolver::proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Instant};

#[derive(Debug)]
pub(super) struct RoutingResolver {
    config: DnsRoutingConfig,
    upstreams: HashMap<String, Arc<dyn Resolver>>,
}
impl RoutingResolver {
    pub(super) fn new(
        config: DnsRoutingConfig,
        get: impl Fn(&str) -> Option<Arc<dyn Resolver>>,
    ) -> io::Result<Arc<Self>> {
        let mut upstreams = HashMap::new();
        for name in config.dependencies() {
            upstreams.insert(
                name.to_owned(),
                get(name).ok_or_else(|| {
                    crate::rules::invalid(format!("DNS upstream '{name}' is not ready"))
                })?,
            );
        }
        Ok(Arc::new(Self { config, upstreams }))
    }
    fn rule(
        &self,
        name: &str,
        kind: RecordType,
        intercepted: bool,
    ) -> Option<&crate::config::dns::DnsRoutingRule> {
        // DNS queries may randomize letter case; rule sources match canonical
        // names. Keep the original question intact when returning the reply.
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.config.rules.iter().find(|rule| {
            (intercepted || !rule.fake_ip)
                && (rule.query_types.is_empty() || rule.query_types.contains(&u16::from(kind)))
                && rule.compiled.as_ref().is_some_and(|p| {
                    (if rule.domain_only {
                        p.evaluate_query_name(&name)
                    } else {
                        p.evaluate(Some(&name), None, 53)
                    }) == Outcome::Match
                })
        })
    }
    pub(super) fn wants_fake(&self, request: &Message) -> bool {
        request.queries.len() == 1
            && self
                .rule(
                    &request.queries[0].name.to_ascii(),
                    request.queries[0].query_type,
                    true,
                )
                .is_some_and(|r| r.fake_ip)
    }
    fn dispatch(
        &self,
        request: Vec<u8>,
        deadline: Option<tokio::time::Instant>,
    ) -> DnsExchangeFuture {
        let parsed = super::message::decode(&request);
        let (upstream, response) = match parsed {
            Ok(message) if message.queries.len() == 1 => {
                let question = &message.queries[0];
                let rule = self.rule(&question.name.to_ascii(), question.query_type, false);
                if let Some(code) = rule.and_then(|r| r.rcode) {
                    (
                        None,
                        Some(
                            super::fake_ip::responder::response(
                                &message,
                                ResponseCode::from(0, code as u8),
                            )
                            .to_vec()
                            .map_err(io::Error::other),
                        ),
                    )
                } else {
                    let name = rule
                        .and_then(|r| r.server.as_ref())
                        .unwrap_or(&self.config.final_server);
                    (Some(self.upstreams[name].clone()), None)
                }
            }
            Ok(message) => (
                None,
                Some(
                    super::fake_ip::responder::response(&message, ResponseCode::FormErr)
                        .to_vec()
                        .map_err(io::Error::other),
                ),
            ),
            Err(error) => (None, Some(Err(error))),
        };
        if let Some(response) = response {
            return Box::pin(async { response });
        }
        let upstream = upstream.unwrap();
        match deadline {
            Some(deadline) => upstream.exchange_with_deadline(request, deadline),
            None => upstream.exchange(request),
        }
    }
}
impl Resolver for RoutingResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(address) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![address]) });
        }
        let location = location.clone();
        let strategy = self.config.ip_strategy;
        let name = location.address().hostname().unwrap().to_owned();
        let query = |kind| {
            let mut message = Message::query();
            // Only locally generated lookups request recursion. Intercepted
            // requests keep their original flags and raw response semantics.
            message.metadata.recursion_desired = true;
            let parsed = Name::from_ascii(&name).map_err(io::Error::other);
            let selected_rule = self.rule(&name, kind, false);
            let policy_code = selected_rule.and_then(|rule| rule.rcode);
            let upstream = selected_rule
                .map_or(self.config.final_server.as_str(), |rule| {
                    if rule.rcode.is_some() {
                        "policy-response"
                    } else {
                        rule.server.as_deref().unwrap_or(&self.config.final_server)
                    }
                })
                .to_owned();
            let future = match parsed {
                Ok(name) => {
                    message.add_query(Query::query(name, kind));
                    match message.to_vec() {
                        Ok(bytes) => self.dispatch(bytes, None),
                        Err(error) => Box::pin(async move { Err(io::Error::other(error)) })
                            as DnsExchangeFuture,
                    }
                }
                Err(error) => Box::pin(async move { Err(error) }) as DnsExchangeFuture,
            };
            let name = name.clone();
            let port = location.port();
            async move {
                let began = Instant::now();
                let result = future.await.and_then(|bytes| {
                    let message = super::message::decode(&bytes)?;
                    log::debug!("stage=dns query={name:?} qtype={kind} upstream={upstream:?} rcode={} elapsed_ms={}",
                        message.metadata.response_code, began.elapsed().as_millis());
                    if message.metadata.response_code != ResponseCode::NoError {
                        if let Some(code) = policy_code {
                            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                crate::diagnostics::DnsPolicyRejection(code)));
                        }
                        return Err(io::Error::new(io::ErrorKind::NotFound,
                            format!("DNS response {}", message.metadata.response_code)));
                    }
                    let addresses: Vec<_> = super::message::addresses(&message)
                        .filter(|ip| ip.is_ipv6() == (kind == RecordType::AAAA))
                        .map(|ip| SocketAddr::new(ip, port)).collect();
                    if addresses.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::NotFound,
                            "DNS returned no usable IP addresses"));
                    }
                    Ok(addresses)
                });
                result.map_err(|error| crate::diagnostics::context(format!(
                    "stage=dns query={name:?} qtype={kind} upstream={upstream:?} elapsed_ms={}",
                    began.elapsed().as_millis()), error))
            }
        };
        let ipv4 = query(RecordType::A);
        let ipv6 = query(RecordType::AAAA);
        Box::pin(async move {
            let (v4, v6) = match strategy {
                IpStrategy::Ipv4Only => (ipv4.await, Ok(Vec::new())),
                IpStrategy::Ipv6Only => (Ok(Vec::new()), ipv6.await),
                _ => tokio::join!(ipv4, ipv6),
            };
            let mut addresses = Vec::new();
            let mut error = None;
            for result in if strategy == IpStrategy::Ipv6ThenIpv4 {
                [v6, v4]
            } else {
                [v4, v6]
            } {
                match result {
                    Ok(ips) => {
                        for ip in ips {
                            if !addresses.contains(&ip) {
                                addresses.push(ip);
                            }
                        }
                    }
                    Err(e) => error = Some(e),
                }
            }
            if addresses.is_empty() {
                Err(error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "DNS returned no usable IP addresses",
                    )
                }))
            } else {
                Ok(addresses)
            }
        })
    }
    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.dispatch(request, None)
    }
    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.dispatch(request, Some(deadline))
    }
    fn retire(&self) {
        for resolver in self.upstreams.values() {
            resolver.retire();
        }
    }
}

#[derive(Debug)]
struct Scope {
    base: Arc<dyn Resolver>,
    named: HashMap<String, Arc<dyn Resolver>>,
}
pub(super) fn scope(
    base: Arc<dyn Resolver>,
    named: impl Iterator<Item = (String, Arc<dyn Resolver>)>,
) -> Arc<dyn Resolver> {
    Arc::new(Scope {
        base,
        named: named.collect(),
    })
}
impl Resolver for Scope {
    fn named(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.named.get(name).cloned()
    }
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        self.base.resolve_location(location)
    }
    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.base.exchange(request)
    }
    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.base.exchange_with_deadline(request, deadline)
    }
    fn fake_dns_context(&self) -> Option<Arc<super::DnsContext>> {
        self.base.fake_dns_context()
    }
    fn request_timeout(&self) -> Option<std::time::Duration> {
        self.base.request_timeout()
    }
    fn retire(&self) {
        self.base.retire();
    }
}

pub(crate) fn endpoint_resolver(
    base: &Arc<dyn Resolver>,
    config: &DomainResolverConfig,
) -> io::Result<Arc<dyn Resolver>> {
    let inner = base.named(&config.server).ok_or_else(|| {
        crate::rules::invalid(format!(
            "domain_resolver '{}' is unavailable",
            config.server
        ))
    })?;
    Ok(Arc::new(Strategy {
        inner,
        strategy: config.ip_strategy,
    }))
}
#[derive(Debug)]
struct Strategy {
    inner: Arc<dyn Resolver>,
    strategy: IpStrategy,
}
impl Resolver for Strategy {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let future = self.inner.resolve_location(location);
        let strategy = self.strategy;
        Box::pin(async move {
            let mut addresses = future.await?;
            match strategy {
                IpStrategy::Ipv4Only => addresses.retain(SocketAddr::is_ipv4),
                IpStrategy::Ipv6Only => addresses.retain(SocketAddr::is_ipv6),
                IpStrategy::Ipv6ThenIpv4 => addresses.sort_by_key(SocketAddr::is_ipv4),
                _ => addresses.sort_by_key(SocketAddr::is_ipv6),
            }
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "domain resolver returned no address in the requested family",
                ));
            }
            Ok(addresses)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NxDomain;
    impl Resolver for NxDomain {
        fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
            unreachable!()
        }
        fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
            Box::pin(async move {
                let mut answer = super::super::message::decode(&request)?.into_response();
                answer.metadata.response_code = ResponseCode::NXDomain;
                answer.to_vec().map_err(io::Error::other)
            })
        }
    }

    #[tokio::test]
    async fn local_reject_is_distinct_from_upstream_nxdomain_and_raw_replies_are_unchanged() {
        for local in [false, true] {
            let mut config: DnsRoutingConfig = serde_json::from_value(serde_json::json!({
                "final_server":"test-upstream", "ip_strategy":"ipv4_only", "rules": if local {
                    serde_json::json!([{"conditions":{"any_destination":true}, "rcode":3}])
                } else { serde_json::json!([]) }
            }))
            .unwrap();
            let mut compiler = crate::rules::Compiler::default();
            for rule in &mut config.rules {
                rule.compiled = Some(compiler.compile(rule.conditions.clone()).unwrap());
            }
            let resolver = RoutingResolver::new(config, |_| Some(Arc::new(NxDomain))).unwrap();
            let error = resolver
                .resolve_location(&NetLocation::from_str("blocked.example:443", None).unwrap())
                .await
                .unwrap_err();
            assert_eq!(
                crate::diagnostics::contains::<crate::diagnostics::DnsPolicyRejection>(&error),
                local
            );
            assert_eq!(
                error.kind(),
                if local {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::NotFound
                }
            );
            assert!(error.to_string().contains("stage=dns"));
            if !local {
                assert!(error.to_string().contains("test-upstream"));
            }
            let mut request = Message::query();
            request.metadata.id = 123;
            request.add_query(Query::query(
                Name::from_ascii("blocked.example.").unwrap(),
                RecordType::A,
            ));
            let answer = resolver.exchange(request.to_vec().unwrap()).await.unwrap();
            let answer = super::super::message::decode(&answer).unwrap();
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
            assert_eq!(answer.metadata.id, 123);
        }
    }
}
