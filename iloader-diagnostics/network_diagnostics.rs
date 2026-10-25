// SPDX-License-Identifier: MIT
// Unofficial diagnostic-only extension; no requests, credentials or TLS changes.
use std::collections::BTreeSet;
use std::error::Error;
use std::io::ErrorKind;

const MAX_DEPTH: usize = 12;
const MAX_REPORT_LAYERS: usize = 12;

#[derive(Default)]
struct Summary {
    flags: BTreeSet<&'static str>,
    services: BTreeSet<&'static str>,
    operations: BTreeSet<&'static str>,
    causes: Vec<&'static str>,
    status: Option<u16>,
    truncated: bool,
}

impl Summary {
    fn inspect(&mut self, error: &(dyn Error + 'static)) {
        let label = if let Some(error) = error.downcast_ref::<reqwest::Error>() {
            for (present, flag) in [
                (error.is_timeout(), "timeout"),
                (error.is_connect(), "connect"),
                (error.is_builder(), "builder"),
                (error.is_request(), "request"),
                (error.is_body(), "body"),
                (error.is_decode(), "decode"),
            ] {
                if present { self.flags.insert(flag); }
            }
            self.status = self.status.or(error.status().map(|s| s.as_u16()));
            if let Some(destination) = error.url() {
                let (service, operation) = endpoint_category(destination);
                self.services.insert(service);
                self.operations.insert(operation);
            }
            "reqwest"
        } else if let Some(error) = error.downcast_ref::<std::io::Error>() {
            self.flags.insert(match error.kind() {
                ErrorKind::TimedOut => "timeout",
                ErrorKind::ConnectionRefused => "connection-refused",
                ErrorKind::ConnectionReset => "connection-reset",
                ErrorKind::ConnectionAborted => "connection-aborted",
                ErrorKind::BrokenPipe => "broken-pipe",
                ErrorKind::UnexpectedEof => "unexpected-eof",
                ErrorKind::NotConnected => "not-connected",
                _ => "io-other",
            });
            "io"
        } else if error.downcast_ref::<rustls::Error>().is_some() {
            self.flags.insert("tls");
            "tls"
        } else if error.downcast_ref::<reqwest_middleware::Error>().is_some() {
            "middleware"
        } else { "other" };
        self.causes.push(label);

        // Classify hidden platform causes, but NEVER return their Display text.
        let text = error.to_string().to_ascii_lowercase();
        for (markers, category) in [
            (&["dns error", "failed to lookup", "name resolution"][..], "dns"),
            (&["tls handshake", "handshake failure"][..], "tls"),
            (&["invalid peer certificate", "unknownissuer", "certificate verify"][..], "tls-certificate"),
            (&["http2 error", "http/2 error", "http2 stream", "http/2 stream"][..], "http2"),
            (&["connection closed", "connection reset", "broken pipe"][..], "connection-interrupted"),
        ] {
            if markers.iter().any(|marker| text.contains(marker)) {
                self.flags.insert(category);
            }
        }
    }

    fn render(&self) -> String {
        let flags = if self.flags.is_empty() { "unclassified".to_string() }
            else { self.flags.iter().copied().collect::<Vec<_>>().join(",") };
        let status = self.status.map(|s| s.to_string()).unwrap_or_else(|| "none".into());
        let service = if self.services.is_empty() { "unknown".to_string() }
            else { self.services.iter().copied().collect::<Vec<_>>().join(",") };
        let operation = if self.operations.is_empty() { "unknown".to_string() }
            else { self.operations.iter().copied().collect::<Vec<_>>().join(",") };
        format!("PIVOT-NET-D2; service={service}; operation={operation}; flags={flags}; causes={}; http={status}; truncated={}",
            self.causes.join(">"), self.truncated)
    }
}

// Inspect only a typed error's destination. Never return any part of its URL,
// query, fragment, user information, headers or body. Unknown input fails closed.
fn endpoint_category(destination: &reqwest::Url) -> (&'static str, &'static str) {
    if destination.scheme() != "https" || destination.port_or_known_default() != Some(443)
        || !destination.username().is_empty() || destination.password().is_some() {
        return ("other", "unknown");
    }
    match destination.host_str() {
        Some("gsa.apple.com" | "gsa-hb.apple.com" | "gsa-gpk.apple.com" | "gsas.apple.com") => {
            let operation = match destination.path() {
                "/grandslam/GsService2/lookup" => "account-lookup",
                "/grandslam/GsService2" => "account-request",
                "/auth" | "/auth/verify/phone" | "/auth/verify/phone/securitycode" => "account-verification",
                _ => "unknown",
            };
            ("apple-account", operation)
        }
        Some("developerservices2.apple.com") => {
            let operation = if destination.path().starts_with("/services/QH65B2/") {
                match destination.path().rsplit('/').next().unwrap_or("") {
                    "listApplicationGroups.action" => "list-app-groups",
                    "downloadTeamProvisioningProfile.action" => "download-profile",
                    "listProvisioningProfiles.action" => "list-profiles",
                    "listAllDevelopmentCerts.action" => "list-signing-certificates",
                    "submitDevelopmentCSR.action" => "request-signing-certificate",
                    "listTeams.action" => "list-teams",
                    _ => "legacy-developer-request",
                }
            } else if destination.path().starts_with("/services/v1/") {
                "developer-v1-request"
            } else { "unknown" };
            ("apple-developer", operation)
        }
        Some("mac-ani.jkcoxson.com" | "new.ani.sidestore.io") => {
            let operation = match destination.path() {
                "/v3/client_info" => "provider-client-info",
                "/v3/get_headers" => "provider-headers",
                "/v3/provisioning_session" => "provider-provisioning",
                _ => "unknown",
            };
            ("anisette-provider", operation)
        }
        _ => ("other", "unknown"),
    }
}

fn summarize_error(error: &(dyn Error + 'static)) -> String {
    let mut summary = Summary::default();
    let mut next = Some(error);
    for _ in 0..MAX_DEPTH {
        let Some(current) = next else { break; };
        summary.inspect(current);
        next = if let Some(reqwest_middleware::Error::Reqwest(inner)) =
            current.downcast_ref::<reqwest_middleware::Error>() {
            Some(inner as &(dyn Error + 'static))
        } else { current.source() };
    }
    summary.truncated = next.is_some();
    summary.render()
}

pub fn summarize_report(report: &rootcause::Report) -> Option<String> {
    for layer in report.iter_reports().take(MAX_REPORT_LAYERS) {
        if let Some(error) = layer.downcast_current_context::<reqwest_middleware::Error>() {
            return Some(summarize_error(error));
        }
        if let Some(error) = layer.downcast_current_context::<reqwest::Error>() {
            return Some(summarize_error(error));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct Fixture { text: &'static str, child: Option<Box<dyn Error + Send + Sync>> }
    impl fmt::Display for Fixture {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.text) }
    }
    impl Error for Fixture {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.child.as_deref().map(|e| e as &(dyn Error + 'static))
        }
    }
    fn fixture(text: &'static str) -> Fixture { Fixture { text, child: None } }
    fn io(kind: ErrorKind) -> String {
        summarize_error(&std::io::Error::new(kind, "FIXTURE_SECRET_NOT_A_CREDENTIAL"))
    }
    fn builder_error() -> reqwest::Error {
        reqwest::Client::new().get("not a valid URL FIXTURE_SECRET_NOT_A_CREDENTIAL").build().unwrap_err()
    }
    #[test] fn raw_display_is_not_output() {
        let result = summarize_error(&fixture("FIXTURE_SECRET_NOT_A_CREDENTIAL"));
        assert!(!result.contains("FIXTURE_SECRET")); assert!(result.contains("unclassified"));
    }
    #[test] fn timeout_is_classified() { assert!(io(ErrorKind::TimedOut).contains("flags=timeout;")); }
    #[test] fn refusal_is_classified() { assert!(io(ErrorKind::ConnectionRefused).contains("connection-refused")); }
    #[test] fn reset_is_classified() { assert!(io(ErrorKind::ConnectionReset).contains("connection-reset")); }
    #[test] fn aborted_is_classified() { assert!(io(ErrorKind::ConnectionAborted).contains("connection-aborted")); }
    #[test] fn broken_pipe_is_classified() { assert!(io(ErrorKind::BrokenPipe).contains("broken-pipe")); }
    #[test] fn eof_is_classified() { assert!(io(ErrorKind::UnexpectedEof).contains("unexpected-eof")); }
    #[test] fn dns_marker_is_redacted() {
        let result = summarize_error(&fixture("dns error for FIXTURE_SECRET_NOT_A_CREDENTIAL"));
        assert!(result.contains("flags=dns;")); assert!(!result.contains("FIXTURE_SECRET"));
    }
    #[test] fn certificate_marker_is_redacted() {
        let result = summarize_error(&fixture("invalid peer certificate: UnknownIssuer FIXTURE_SECRET"));
        assert!(result.contains("tls-certificate")); assert!(!result.contains("UnknownIssuer"));
    }
    #[test] fn http2_marker_is_redacted() {
        let result = summarize_error(&fixture("http/2 stream FIXTURE_SECRET"));
        assert!(result.contains("flags=http2;")); assert!(!result.contains("FIXTURE_SECRET"));
    }
    #[derive(Debug)] struct Cycle;
    impl fmt::Display for Cycle { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("cycle") } }
    impl Error for Cycle { fn source(&self) -> Option<&(dyn Error + 'static)> { Some(self) } }
    #[test] fn cyclic_sources_are_bounded() {
        let result = summarize_error(&Cycle);
        assert!(result.contains("truncated=true")); assert!(result.len() < 350);
    }
    #[test] fn nested_io_source_is_seen() {
        let error = Fixture { text: "private context", child: Some(Box::new(std::io::Error::from(ErrorKind::TimedOut))) };
        let result = summarize_error(&error);
        assert!(result.contains("causes=other>io")); assert!(result.contains("timeout"));
    }
    #[test] fn real_reqwest_builder_error_is_seen_without_network() {
        assert!(summarize_error(&builder_error()).contains("builder"));
    }
    #[test] fn report_context_preserves_typed_reqwest() {
        let report: rootcause::Report = rootcause::Report::new_sendsync(builder_error()).context("FIXTURE_SECRET_CONTEXT").into_dynamic();
        let result = summarize_report(&report).unwrap();
        assert!(result.contains("reqwest")); assert!(!result.contains("FIXTURE_SECRET"));
    }
    #[test] fn middleware_report_is_detected() {
        let error = reqwest_middleware::Error::Reqwest(builder_error());
        let report: rootcause::Report = rootcause::Report::new_sendsync(error).context("FIXTURE_SECRET_CONTEXT").into_dynamic();
        let result = summarize_report(&report).unwrap();
        assert!(result.contains("causes=middleware>reqwest"));
        assert!(result.contains("builder"));
    }
    #[test] fn non_network_report_is_unchanged() {
        let report: rootcause::Report = rootcause::Report::new_sendsync(fixture("ordinary non-network error")).into_dynamic();
        assert!(summarize_report(&report).is_none());
    }
    #[test] fn mixed_case_tls_marker_is_seen() {
        let result = summarize_error(&fixture("TLS HANDSHAKE failure FIXTURE_SECRET"));
        assert!(result.contains("flags=tls;")); assert!(!result.contains("FIXTURE_SECRET"));
    }
    #[test] fn synthetic_url_and_identifiers_are_not_output() {
        let result = summarize_error(&fixture("dns error https://fixture.invalid/?credential=FIXTURE_SECRET device=FIXTURE_DEVICE"));
        for forbidden in ["https", "credential", "FIXTURE_SECRET", "FIXTURE_DEVICE", "fixture.invalid"] {
            assert!(!result.contains(forbidden));
        }
        assert!(result.len() < 350);
    }
    fn error_at(destination: &str) -> reqwest::Error {
        builder_error().with_url(reqwest::Url::parse(destination).unwrap())
    }
    #[test] fn known_apple_routes_are_classified_and_redacted() {
        for (destination, service, operation) in [
            ("https://gsa.apple.com/grandslam/GsService2/lookup", "apple-account", "account-lookup"),
            ("https://gsa-hb.apple.com/grandslam/GsService2", "apple-account", "account-request"),
            ("https://gsas.apple.com/auth/verify/phone/securitycode", "apple-account", "account-verification"),
            ("https://developerservices2.apple.com/services/QH65B2/listApplicationGroups.action", "apple-developer", "list-app-groups"),
            ("https://developerservices2.apple.com/services/QH65B2/downloadTeamProvisioningProfile.action", "apple-developer", "download-profile"),
            ("https://developerservices2.apple.com/services/v1/bundleIds/FIXTURE_IDENTIFIER", "apple-developer", "developer-v1-request"),
        ] {
            let result = summarize_error(&error_at(destination));
            assert!(result.contains(&format!("service={service}; operation={operation};")));
            assert!(!result.contains("apple.com"));
            assert!(!result.contains("FIXTURE_IDENTIFIER"));
        }
    }
    #[test] fn known_provider_routes_are_classified_and_redacted() {
        for host in ["mac-ani.jkcoxson.com", "new.ani.sidestore.io"] {
            for (path, operation) in [("client_info", "provider-client-info"), ("get_headers", "provider-headers"),
                                      ("provisioning_session", "provider-provisioning")] {
                let result = summarize_error(&error_at(&format!("https://{host}/v3/{path}")));
                assert!(result.contains(&format!("service=anisette-provider; operation={operation};")));
                assert!(!result.contains(host));
            }
        }
    }
    #[test] fn unknown_endpoint_fails_closed() {
        for destination in ["https://fixture.invalid/v3/client_info", "https://custom.fixture.invalid/services/QH65B2/listTeams.action"] {
            assert_eq!(endpoint_category(&reqwest::Url::parse(destination).unwrap()), ("other", "unknown"));
        }
    }
    #[test] fn exact_hosts_protocol_and_paths_are_required() {
        for destination in ["https://gsa.apple.com.fixture.invalid/grandslam/GsService2", "http://gsa.apple.com/grandslam/GsService2",
                            "https://gsa.apple.com:444/grandslam/GsService2"] {
            assert_eq!(endpoint_category(&reqwest::Url::parse(destination).unwrap()), ("other", "unknown"));
        }
        let mut user_info = reqwest::Url::parse("https://gsa.apple.com/grandslam/GsService2").unwrap();
        user_info.set_username("FIXTURE_USER").unwrap();
        user_info.set_password(Some("FIXTURE_SECRET")).unwrap();
        assert_eq!(endpoint_category(&user_info), ("other", "unknown"));
        for destination in ["https://gsa.apple.com/grandslam/GsService2/unknown", "https://mac-ani.jkcoxson.com/v3/client_info/unknown"] {
            assert_eq!(endpoint_category(&reqwest::Url::parse(destination).unwrap()).1, "unknown");
        }
    }
    #[test] fn query_and_fragment_cannot_select_an_operation() {
        let destination = "https://gsa.apple.com/unknown?route=/grandslam/GsService2&credential=FIXTURE_SECRET#FIXTURE_DEVICE";
        let result = summarize_error(&error_at(destination));
        assert!(result.contains("service=apple-account; operation=unknown;"));
        for forbidden in ["FIXTURE", "credential", "gsa.apple.com", "/unknown", "route="] { assert!(!result.contains(forbidden)); }
    }
    #[test] fn typed_url_survives_report_context_without_raw_output() {
        let error = reqwest_middleware::Error::Reqwest(error_at("https://developerservices2.apple.com/services/QH65B2/downloadTeamProvisioningProfile.action?device=FIXTURE_DEVICE&token=FIXTURE_SECRET"));
        let report: rootcause::Report = rootcause::Report::new_sendsync(error).context("FIXTURE_SECRET_CONTEXT").into_dynamic();
        let result = summarize_report(&report).unwrap();
        assert!(result.contains("service=apple-developer; operation=download-profile;"));
        assert!(result.contains("causes=middleware>reqwest"));
        for forbidden in ["FIXTURE", "apple.com", "token", "device=", "https"] { assert!(!result.contains(forbidden)); }
    }
    #[test] fn absent_typed_url_remains_unknown() {
        let result = summarize_error(&std::io::Error::from(ErrorKind::TimedOut));
        assert!(result.contains("service=unknown; operation=unknown;"));
        assert!(result.contains("flags=timeout;"));
    }
    #[test] fn hostile_destination_output_stays_bounded_and_private() {
        let destination = format!("https://developerservices2.apple.com/services/QH65B2/{}.action?token={}#FIXTURE_DEVICE", "FIXTURE_PRIVATE".repeat(400), "FIXTURE_SECRET".repeat(400));
        let result = summarize_error(&error_at(&destination));
        assert!(result.contains("service=apple-developer; operation=legacy-developer-request;"));
        assert!(result.len() < 500);
        for forbidden in ["FIXTURE", "https", "apple.com", "token", ".action"] { assert!(!result.contains(forbidden)); }
    }
}
