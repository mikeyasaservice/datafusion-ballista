// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! The TLS accept loop: only peers with a verified client certificate get
//! through, a silent client cannot hold up others, and the accepted
//! connection carries the peer's certificate.

use std::{sync::Arc, time::Duration};

use ballista_core::tls::{self, PeerAuthorizer, PeerIdentity, TlsConfig};
use futures::StreamExt;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsConnector;

struct AllowAll;
impl PeerAuthorizer for AllowAll {
    fn authorize(&self, _: &PeerIdentity, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn authorize_executor(&self, _: &PeerIdentity, _: &str) -> Result<(), String> {
        Ok(())
    }
}

struct Pki {
    roots: RootCertStore,
    server: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    client: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
}

fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let leaf = |purpose| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.extended_key_usages = vec![purpose];
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    };
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    Pki {
        roots,
        server: leaf(ExtendedKeyUsagePurpose::ServerAuth),
        client: leaf(ExtendedKeyUsagePurpose::ClientAuth),
    }
}

fn server_config(pki: &Pki) -> TlsConfig {
    let provider = Arc::new(default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(pki.roots.clone()),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki.server.0.clone(), pki.server.1.clone_key())
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    TlsConfig {
        server: Arc::new(server),
        client: Arc::new(client_config(pki, true)),
        authorizer: Arc::new(AllowAll),
        handshake_timeout: Duration::from_secs(3),
        plain_health: None,
    }
}

fn client_config(pki: &Pki, with_cert: bool) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(pki.roots.clone());
    let mut config = if with_cert {
        builder
            .with_client_auth_cert(pki.client.0.clone(), pki.client.1.clone_key())
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

async fn handshake(addr: std::net::SocketAddr, config: ClientConfig) {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    if let Ok(mut stream) = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
    {
        // TLS 1.3 servers reject a missing client certificate after the
        // client has finished; write so the client sees the alert.
        let _ = stream.write_all(b"x").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn only_verified_peers_are_accepted_and_slow_handshakes_do_not_block() {
    let pki = pki();
    let config = server_config(&pki);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut accepted = Box::pin(tls::accept(
        tokio_stream::wrappers::TcpListenerStream::new(listener),
        &config,
    ));

    // A client that never speaks, then one without a client certificate.
    let _silent = TcpStream::connect(addr).await.unwrap();
    handshake(addr, client_config(&pki, false)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), accepted.next())
            .await
            .is_err(),
        "a peer without a client certificate was accepted"
    );

    // A verified peer gets through at once, behind the silent client.
    let started = std::time::Instant::now();
    let good = tokio::spawn(handshake(addr, client_config(&pki, true)));
    let conn = tokio::time::timeout(Duration::from_secs(2), accepted.next())
        .await
        .expect("verified peer blocked behind a silent client")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(conn.peer().certs.first(), pki.client.0.first());
    assert_eq!(conn.peer().addr.ip(), addr.ip());
    good.await.unwrap();
}
