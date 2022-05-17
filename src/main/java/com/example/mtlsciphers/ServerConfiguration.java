package com.example.mtlsciphers;

import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import reactor.netty.http.Http11SslContextSpec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@Configuration
public class ServerConfiguration {
    ResourceLoader resourceLoader;

    public ServerConfiguration(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public WebServerFactoryCustomizer<NettyReactiveWebServerFactory> customizer() {
        return factory -> factory.addServerCustomizers(httpServer -> httpServer.secure(sslContextSpec -> {
            try {
                Ssl ssl = factory.getSsl();
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                char[] keyStorePassword = ssl.getKeyStorePassword().toCharArray();
                keyStore.load(resourceLoader.getResource(ssl.getKeyStore()).getInputStream(), keyStorePassword);
                KeyManagerFactory keyManagerFactory = OpenSslCachingX509KeyManagerFactory
                        .getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword);
                Http11SslContextSpec http11SslContextSpec = Http11SslContextSpec.forServer(keyManagerFactory)
                        .configure(sslContextBuilder -> {
                            sslContextBuilder.sslProvider(SslProvider.OPENSSL);
                            sslContextBuilder.ciphers(Arrays.asList(ssl.getCiphers()));
                            sslContextBuilder.protocols(ssl.getEnabledProtocols());
                            sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
                            sslContextBuilder.clientAuth(ClientAuth.REQUIRE);
                        });
                sslContextSpec.sslContext(http11SslContextSpec)
                        .handlerConfigurator(sslHandler -> {
                            sslHandler.setCloseNotifyReadTimeout(18000, TimeUnit.MILLISECONDS);
                            sslHandler.setHandshakeTimeout(19000, TimeUnit.MILLISECONDS);
                            SSLParameters sslParameters = sslHandler.engine().getSSLParameters();
                            sslParameters.setUseCipherSuitesOrder(false);
                            sslHandler.engine().setSSLParameters(sslParameters);
                        });
            } catch (UnrecoverableKeyException | IOException | CertificateException | KeyStoreException |
                     NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }));
    }
}
