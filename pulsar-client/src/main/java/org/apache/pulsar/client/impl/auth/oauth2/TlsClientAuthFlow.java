/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.client.impl.auth.oauth2;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.pulsar.PulsarVersion;
import org.apache.pulsar.client.api.PulsarClientException;
import org.apache.pulsar.client.impl.auth.oauth2.protocol.ClientCredentialsExchangeRequest;
import org.apache.pulsar.client.impl.auth.oauth2.protocol.TokenClient;
import org.apache.pulsar.client.impl.auth.oauth2.protocol.TokenExchangeException;
import org.apache.pulsar.client.impl.auth.oauth2.protocol.TokenResult;
import org.apache.pulsar.client.util.ExecutorProvider;
import org.apache.pulsar.client.util.PulsarHttpAsyncSslEngineFactory;
import org.apache.pulsar.common.util.PulsarSslConfiguration;
import org.apache.pulsar.common.util.PulsarSslFactory;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClientConfig;
import org.asynchttpclient.SslEngineFactory;

/**
 * Implementation of OAuth 2.0 Client TLS Authentication flow.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8705">RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication</a>
 */
@Slf4j
class TlsClientAuthFlow extends FlowBase {
    public static final String CONFIG_PARAM_ISSUER_URL = "issuerUrl";
    public static final String CONFIG_PARAM_CLIENT_ID = "clientId";
    public static final String CONFIG_PARAM_CERT_FILE = "tlsCertFile";
    public static final String CONFIG_PARAM_KEY_FILE = "tlsKeyFile";
    public static final String CONFIG_PARAM_AUDIENCE = "audience";
    public static final String CONFIG_PARAM_SCOPE = "scope";
    public static final String CONFIG_PARAM_AUTO_CERT_REFRESH_DURATION = "autoCertRefreshDuration";

    private static final Duration DEFAULT_AUTO_CERT_REFRESH_DURATION = Duration.ofSeconds(300);
    private static final String DEFAULT_CLIENT_ID = "pulsar-client";

    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String audience;
    private final String scope;
    private final long autoCertRefreshSeconds; // Certificate refresh interval in seconds
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final String trustCertsFilePath;
    private final String certFile;
    private final String keyFile;

    private transient TokenClient exchanger;
    private transient ScheduledExecutorService scheduler;
    private transient PulsarSslFactory sslFactory;
    private transient AsyncHttpClient tokenHttpClient;

    private boolean initialized = false;

    @Builder
    public TlsClientAuthFlow(URL issuerUrl, String clientId, String certFile, String keyFile, String audience,
                             String scope, Duration connectTimeout, Duration readTimeout, String trustCertsFilePath,
                             String wellKnownMetadataPath, Duration autoCertRefreshDuration) {
        super(issuerUrl, connectTimeout, readTimeout, trustCertsFilePath, wellKnownMetadataPath);
        this.clientId = clientId == null ? DEFAULT_CLIENT_ID : clientId;
        this.audience = audience;
        this.scope = scope;
        this.autoCertRefreshSeconds = getParameterDurationToSeconds(CONFIG_PARAM_AUTO_CERT_REFRESH_DURATION,
                autoCertRefreshDuration, DEFAULT_AUTO_CERT_REFRESH_DURATION);
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.trustCertsFilePath = trustCertsFilePath;
        this.certFile = certFile;
        this.keyFile = keyFile;
    }

    /**
     * Constructs a {@link TlsClientAuthFlow} from configuration parameters.
     *
     * @param params Configuration parameters
     * @return A new TlsClientAuthFlow instance
     */
    public static TlsClientAuthFlow fromParameters(Map<String, String> params) {
        URL issuerUrl = parseParameterUrl(params, CONFIG_PARAM_ISSUER_URL);
        // In mTLS-based providers, caller input for client_id can be optional.
        // Keep sending client_id in token request for RFC compatibility by applying a default value.
        String clientId = params.getOrDefault(CONFIG_PARAM_CLIENT_ID, DEFAULT_CLIENT_ID);
        String certFile = parseParameterString(params, CONFIG_PARAM_CERT_FILE);
        String keyFile = parseParameterString(params, CONFIG_PARAM_KEY_FILE);
        // These are optional parameters, so we allow null values
        String scope = params.get(CONFIG_PARAM_SCOPE);
        String audience = params.get(CONFIG_PARAM_AUDIENCE);
        Duration connectTimeout = parseParameterDuration(params, CONFIG_PARAM_CONNECT_TIMEOUT);
        Duration readTimeout = parseParameterDuration(params, CONFIG_PARAM_READ_TIMEOUT);
        String trustCertsFilePath = params.get(CONFIG_PARAM_TRUST_CERTS_FILE_PATH);
        String wellKnownMetadataPath = params.get(CONFIG_PARAM_WELL_KNOWN_METADATA_PATH);
        Duration autoCertRefreshDuration = parseParameterDuration(params, CONFIG_PARAM_AUTO_CERT_REFRESH_DURATION);

        return TlsClientAuthFlow.builder()
                .issuerUrl(issuerUrl)
                .clientId(clientId)
                .certFile(certFile)
                .keyFile(keyFile)
                .audience(audience)
                .scope(scope)
                .connectTimeout(connectTimeout)
                .readTimeout(readTimeout)
                .trustCertsFilePath(trustCertsFilePath)
                .wellKnownMetadataPath(wellKnownMetadataPath)
                .autoCertRefreshDuration(autoCertRefreshDuration)
                .build();
    }

    @Override
    public void initialize() throws PulsarClientException {
        super.initialize();
        assert this.metadata != null;

        URL tokenUrl = this.metadata.getTokenEndpoint();
        TlsHttpClientContext tlsHttpClientContext = createTlsHttpClientContext(tokenUrl.getHost());
        this.tokenHttpClient = tlsHttpClientContext.httpClient();
        this.sslFactory = tlsHttpClientContext.sslFactory();

        this.exchanger = new TokenClient(tokenUrl, this.tokenHttpClient);

        if (sslFactory != null && autoCertRefreshSeconds > 0) {
            scheduler = Executors.newSingleThreadScheduledExecutor(new ExecutorProvider
                            .ExtendedThreadFactory("tls-cert-refresher"));
            scheduler.scheduleAtFixedRate(this::refreshSslContext,
                autoCertRefreshSeconds, autoCertRefreshSeconds, TimeUnit.SECONDS);

            log.info("Scheduled TLS certificate refresh every {} seconds", autoCertRefreshSeconds);
        }

        initialized = true;
    }

    private PulsarSslConfiguration buildSslConfiguration() {
        return PulsarSslConfiguration.builder()
                .tlsCertificateFilePath(certFile)
                .tlsKeyFilePath(keyFile)
                .tlsTrustCertsFilePath(trustCertsFilePath)
                .allowInsecureConnection(false)
                .serverMode(false)
                .isHttps(true)
                .build();
    }

    private TlsHttpClientContext createTlsHttpClientContext(String hostname) throws PulsarClientException {
        try {
            PulsarSslConfiguration sslConfiguration = buildSslConfiguration();
            PulsarSslFactory sslFactory = new org.apache.pulsar.common.util.DefaultPulsarSslFactory();
            sslFactory.initialize(sslConfiguration);
            sslFactory.createInternalSslContext();

            DefaultAsyncHttpClientConfig.Builder confBuilder = new DefaultAsyncHttpClientConfig.Builder();
            confBuilder.setCookieStore(null);
            confBuilder.setUseProxyProperties(true);
            confBuilder.setFollowRedirect(true);
            confBuilder.setConnectTimeout(
                    getParameterDurationToMillis(
                            CONFIG_PARAM_CONNECT_TIMEOUT, connectTimeout, DEFAULT_CONNECT_TIMEOUT));
            confBuilder.setReadTimeout(
                    getParameterDurationToMillis(CONFIG_PARAM_READ_TIMEOUT, readTimeout, DEFAULT_READ_TIMEOUT));
            confBuilder.setUserAgent(String.format("Pulsar-Java-v%s", PulsarVersion.getVersion()));
            SslEngineFactory sslEngineFactory = new PulsarHttpAsyncSslEngineFactory(sslFactory, hostname);
            confBuilder.setSslEngineFactory(sslEngineFactory);

            return new TlsHttpClientContext(new DefaultAsyncHttpClient(confBuilder.build()), sslFactory);
        } catch (Exception e) {
            throw new PulsarClientException.InvalidConfigurationException(e);
        }
    }

    private void refreshSslContext() {
        if (this.sslFactory == null) {
            return;
        }
        try {
            this.sslFactory.update();
            log.debug("Successfully refreshed SSL context");
        } catch (Exception e) {
            log.error("Failed to refresh SSL context", e);
        }
    }

    public TokenResult authenticate() throws PulsarClientException {
        // request an access token using TLS client authentication
        ClientCredentialsExchangeRequest req = ClientCredentialsExchangeRequest.builder()
                .clientId(this.clientId)
                .audience(this.audience)
                .scope(this.scope)
                .build();
        TokenResult tr;
        if (!initialized) {
            initialize();
        }
        try {
            tr = this.exchanger.exchangeTlsClientAuth(req);
        } catch (TokenExchangeException | IOException e) {
            throw new PulsarClientException.AuthenticationException("Unable to obtain an access token: "
                    + e.getMessage());
        }

        return tr;
    }

    @Override
    public void close() throws Exception {
        super.close();
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        if (exchanger != null) {
            exchanger.close();
        } else if (tokenHttpClient != null) {
            tokenHttpClient.close();
        }
    }

    private record TlsHttpClientContext(AsyncHttpClient httpClient, PulsarSslFactory sslFactory) { }
}
