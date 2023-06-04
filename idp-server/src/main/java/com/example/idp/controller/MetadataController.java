package com.example.idp.controller;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;

import java.io.File;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

import static com.example.idp.util.OpenSAMLUtils.DEFAULT_ENTITY_ID;
import static com.example.idp.util.OpenSAMLUtils.*;

@RestController
public class MetadataController {
    @Value("classpath:credentials/idpssl.key")
    private RSAPrivateKey idpKey;
    @Value("classpath:credentials/idpssl.crt")
    private File idpFile;

    @Autowired
    @GetMapping(value = "/metadata", produces = "application/xml")
    public String metadata(@Value("${idp.base_url}") String idpBaseUrl) throws MarshallingException, SecurityException, SignatureException {
        EntityDescriptor entityDescriptor = buildSAMLObject(EntityDescriptor.class);
        entityDescriptor.setEntityID(DEFAULT_ENTITY_ID);
        entityDescriptor.setID(generateSecureRandomId());
        entityDescriptor.setValidUntil(new DateTime().plusMillis(86400000));

        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        marshallerFactory.getMarshaller(entityDescriptor).marshall(entityDescriptor);

        IDPSSODescriptor idpssoDescriptor = buildSAMLObject(IDPSSODescriptor.class);
        NameIDFormat nameIDFormat = buildSAMLObject(NameIDFormat.class);
        nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        idpssoDescriptor.getNameIDFormats().add(nameIDFormat);
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        SingleSignOnService singleSignOnService = buildSAMLObject(SingleSignOnService.class);
        singleSignOnService.setLocation(idpBaseUrl + "/SingleSignOnService");
        singleSignOnService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService);

        List<ArtifactResolutionService> resolutionServices = idpssoDescriptor.getArtifactResolutionServices();
        ArtifactResolutionService artifactResolutionService = buildSAMLObject(ArtifactResolutionService.class);
        artifactResolutionService.setLocation(idpBaseUrl + "/artifactResolutionService");
        artifactResolutionService.setBinding(SAMLConstants.POST_METHOD);
        resolutionServices.add(artifactResolutionService);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyDescriptor encKeyDescriptor = buildSAMLObject(KeyDescriptor.class);
        encKeyDescriptor.setUse(UsageType.SIGNING);

        X509Certificate idpCert = x509Certificate(idpFile);
        Saml2X509Credential signing = Saml2X509Credential.signing(idpKey, idpCert);
        BasicX509Credential spCredential = new BasicX509Credential(signing.getCertificate(),signing.getPrivateKey());

        encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(spCredential));
        idpssoDescriptor.getKeyDescriptors().add(encKeyDescriptor);
        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(spCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        entityDescriptor.setSignature(signature);
        marshallerFactory.getMarshaller(entityDescriptor).marshall(entityDescriptor);
        Signer.signObject(signature);

        Element element = marshallerFactory.getMarshaller(entityDescriptor).marshall(entityDescriptor);
        return SerializeSupport.nodeToString(element);
    }

}
