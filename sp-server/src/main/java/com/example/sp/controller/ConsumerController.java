package com.example.sp.controller;

import com.example.sp.util.OpenSAMLUtils;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static com.example.sp.util.OpenSAMLUtils.x509Certificate;

/**
 * Created by Privat on 4/6/14.
 */
@Slf4j
@Controller
@RequestMapping("/sp/consumer")
public class ConsumerController {
    public static final String ARTIFACT_RESOLUTION_SERVICE = "http://localhost:9090/artifactResolutionService";

    @Value("classpath:credentials/rp-private.key")
    private RSAPrivateKey rpKey;
    @Value("classpath:credentials/rp-certificate.crt")
    private File rpFile;
    @Value("classpath:credentials/idp-certificate.crt")
    private File idpFile;



    @GetMapping
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        log.info("Artifact received");
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        log.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        log.info("Sending ArtifactResolve");

        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve, resp);
        // todo 插入到验证环节
        String samlResponse = SerializeSupport.nodeToString(artifactResponse.getMessage().getDOM());
//        resp.sendRedirect("http://localhost:8090/saml/SSO?SAMLResponse=123");
    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve, HttpServletResponse servletResponse) throws RuntimeException {
        try {

            MessageContext<ArtifactResolve> contextOut = new MessageContext<>();

            contextOut.setMessage(artifactResolve);

            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

            X509Certificate rpCert = x509Certificate(rpFile);
            Saml2X509Credential signing = Saml2X509Credential.signing(rpKey, rpCert);
            BasicX509Credential spCredential = new BasicX509Credential(signing.getCertificate(),signing.getPrivateKey());
            signatureSigningParameters.setSigningCredential(spCredential);
            signatureSigningParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            SecurityParametersContext securityParametersContext = contextOut.getSubcontext(SecurityParametersContext.class, true);
            securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);

            InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<>();
            context.setOutboundMessageContext(contextOut);



            AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient() {
                protected HttpClientMessagePipeline newPipeline() throws SOAPException {
                    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                    HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();

                    BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(
                            encoder,
                            decoder
                    );

                    pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
                    return pipeline;
                }};

            HttpClientBuilder clientBuilder = new HttpClientBuilder();

            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(ARTIFACT_RESOLUTION_SERVICE, context);

            return context.getInboundMessageContext().getMessage();
        } catch (Exception e){
            throw new RuntimeException(e);
        }

    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        // todo
        issuer.setValue("TestSP");
        artifactResolve.setIssuer(issuer);

        artifactResolve.setIssueInstant(new DateTime());

        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());

        artifactResolve.setDestination(ARTIFACT_RESOLUTION_SERVICE);

        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }
}
