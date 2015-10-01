package it.infn.security.saml.utils;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeProfile;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.impl.AttributeAuthorityDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.AttributeProfileBuilder;
import org.opensaml.saml2.metadata.impl.AttributeServiceBuilder;
import org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.KeyNameBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.signature.impl.X509SubjectNameBuilder;

public class SAML2ObjectBuilder {

    private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    private static final EntityDescriptorBuilder entDescrBuilder = (EntityDescriptorBuilder) builderFactory
            .getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME);

    private static final AttributeAuthorityDescriptorBuilder aaDescrBuilder = (AttributeAuthorityDescriptorBuilder) builderFactory
            .getBuilder(AttributeAuthorityDescriptor.DEFAULT_ELEMENT_NAME);

    private static final KeyDescriptorBuilder keyDescrBuilder = (KeyDescriptorBuilder) builderFactory
            .getBuilder(KeyDescriptor.DEFAULT_ELEMENT_NAME);

    private static final KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) builderFactory
            .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);

    private static final KeyNameBuilder keyNameBuilder = (KeyNameBuilder) builderFactory
            .getBuilder(KeyName.DEFAULT_ELEMENT_NAME);

    private static final X509DataBuilder x509DataBuilder = (X509DataBuilder) builderFactory
            .getBuilder(X509Data.DEFAULT_ELEMENT_NAME);

    private static final X509SubjectNameBuilder x509SbjBuilder = (X509SubjectNameBuilder) builderFactory
            .getBuilder(X509SubjectName.DEFAULT_ELEMENT_NAME);

    private static final X509CertificateBuilder x509CertBuilder = (X509CertificateBuilder) builderFactory
            .getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);

    private static final AttributeServiceBuilder asBuilder = (AttributeServiceBuilder) builderFactory
            .getBuilder(AttributeService.DEFAULT_ELEMENT_NAME);

    private static final NameIDFormatBuilder nifBuilder = (NameIDFormatBuilder) builderFactory
            .getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME);

    private static final AttributeProfileBuilder apBuilder = (AttributeProfileBuilder) builderFactory
            .getBuilder(AttributeProfile.DEFAULT_ELEMENT_NAME);

    private static final AttributeBuilder attrBuilder = (AttributeBuilder) builderFactory
            .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

    private static final SignatureBuilder signBuilder = (SignatureBuilder) builderFactory
            .getBuilder(Signature.DEFAULT_ELEMENT_NAME);

    private static final ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory
            .getBuilder(Response.DEFAULT_ELEMENT_NAME);

    private static final IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory
            .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    private static final StatusBuilder statusBuilder = (StatusBuilder) builderFactory
            .getBuilder(Status.DEFAULT_ELEMENT_NAME);

    private static final StatusCodeBuilder statusCodeBuilder = (StatusCodeBuilder) builderFactory
            .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);

    private static final StatusMessageBuilder statusMessageBuilder = (StatusMessageBuilder) builderFactory
            .getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);

    public static EntityDescriptor buildEntityDescriptor() {
        return entDescrBuilder.buildObject();
    }

    public static AttributeAuthorityDescriptor buildAttributeAuthorityDescriptor() {
        return aaDescrBuilder.buildObject();
    }

    public static KeyDescriptor buildKeyDescriptor() {
        return keyDescrBuilder.buildObject();
    }

    public static KeyInfo buildKeyInfo() {
        return keyInfoBuilder.buildObject();
    }

    public static KeyName buildKeyName() {
        return keyNameBuilder.buildObject();
    }

    public static X509Data buildX509Data() {
        return x509DataBuilder.buildObject();
    }
    
    public static X509SubjectName buildX509SubjectName() {
        return x509SbjBuilder.buildObject();
    }
    
    public static X509Certificate buildX509Certificate() {
        return x509CertBuilder.buildObject();
    }

    public static AttributeService buildAttributeService() {
        return asBuilder.buildObject();
    }

    public static NameIDFormat buildNameIDFormat() {
        return nifBuilder.buildObject();
    }

    public static AttributeProfile buildAttributeProfile() {
        return apBuilder.buildObject();
    }

    public static Attribute buildAttribute() {
        return attrBuilder.buildObject();
    }

    public static Signature buildSignature() {
        return signBuilder.buildObject();
    }

    public static Response buildResponse() {
        return responseBuilder.buildObject();
    }

    public static Issuer buildIssuer() {
        return issuerBuilder.buildObject();
    }

    public static Status buildStatus() {
        return statusBuilder.buildObject();
    }

    public static StatusCode buildStatusCode() {
        return statusCodeBuilder.buildObject();
    }

    public static StatusMessage buildStatusMessage() {
        return statusMessageBuilder.buildObject();
    }
}