package it.infn.security.saml.utils;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeProfile;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.saml2.metadata.TelephoneNumber;
import org.opensaml.saml2.metadata.impl.AttributeAuthorityDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.AttributeProfileBuilder;
import org.opensaml.saml2.metadata.impl.AttributeServiceBuilder;
import org.opensaml.saml2.metadata.impl.ContactPersonBuilder;
import org.opensaml.saml2.metadata.impl.EmailAddressBuilder;
import org.opensaml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.GivenNameBuilder;
import org.opensaml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml2.metadata.impl.NameIDFormatBuilder;
import org.opensaml.saml2.metadata.impl.OrganizationBuilder;
import org.opensaml.saml2.metadata.impl.OrganizationDisplayNameBuilder;
import org.opensaml.saml2.metadata.impl.OrganizationNameBuilder;
import org.opensaml.saml2.metadata.impl.OrganizationURLBuilder;
import org.opensaml.saml2.metadata.impl.SurNameBuilder;
import org.opensaml.saml2.metadata.impl.TelephoneNumberBuilder;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.FaultCode;
import org.opensaml.ws.soap.soap11.FaultString;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
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

    private static final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

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

    private static final AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory
            .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

    private static final AttributeStatementBuilder attrStatBuilder = (AttributeStatementBuilder) builderFactory
            .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);

    private static final ContactPersonBuilder contactPerBuilder = (ContactPersonBuilder) builderFactory
            .getBuilder(ContactPerson.DEFAULT_ELEMENT_NAME);

    private static final GivenNameBuilder gNameBuilder = (GivenNameBuilder) builderFactory
            .getBuilder(GivenName.DEFAULT_ELEMENT_NAME);

    private static final SurNameBuilder sNameBuilder = (SurNameBuilder) builderFactory
            .getBuilder(SurName.DEFAULT_ELEMENT_NAME);

    private static final EmailAddressBuilder emailBuilder = (EmailAddressBuilder) builderFactory
            .getBuilder(EmailAddress.DEFAULT_ELEMENT_NAME);

    private static final TelephoneNumberBuilder phoneBuilder = (TelephoneNumberBuilder) builderFactory
            .getBuilder(TelephoneNumber.DEFAULT_ELEMENT_NAME);

    private static final OrganizationBuilder organizBuilder = (OrganizationBuilder) builderFactory
            .getBuilder(Organization.DEFAULT_ELEMENT_NAME);

    private static final OrganizationNameBuilder orgNameBuilder = (OrganizationNameBuilder) builderFactory
            .getBuilder(OrganizationName.DEFAULT_ELEMENT_NAME);

    private static final OrganizationDisplayNameBuilder orgDispBuilder = (OrganizationDisplayNameBuilder) builderFactory
            .getBuilder(OrganizationDisplayName.DEFAULT_ELEMENT_NAME);

    private static final OrganizationURLBuilder orgUrlBuilder = (OrganizationURLBuilder) builderFactory
            .getBuilder(OrganizationURL.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<Fault> faultBuilder = (SOAPObjectBuilder<Fault>) builderFactory
            .getBuilder(Fault.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<FaultCode> fCodeBuilder = (SOAPObjectBuilder<FaultCode>) builderFactory
            .getBuilder(FaultCode.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<FaultString> fStrBuilder = (SOAPObjectBuilder<FaultString>) builderFactory
            .getBuilder(FaultString.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
            .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
            .getBuilder(Body.DEFAULT_ELEMENT_NAME);

    public static Marshaller getMarshaller(XMLObject xmlObj) {
        return marshallerFactory.getMarshaller(xmlObj);
    }

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

    public static Assertion buildAssertion() {
        return assertionBuilder.buildObject();
    }

    public static AttributeStatement buildAttributeStatement() {
        return attrStatBuilder.buildObject();
    }

    public static ContactPerson buildContactPerson() {
        return contactPerBuilder.buildObject();
    }

    public static GivenName buildGivenName() {
        return gNameBuilder.buildObject();
    }

    public static SurName buildSurName() {
        return sNameBuilder.buildObject();
    }

    public static EmailAddress buildEmailAddress() {
        return emailBuilder.buildObject();
    }

    public static TelephoneNumber buildTelephoneNumber() {
        return phoneBuilder.buildObject();
    }

    public static Organization buildOrganization() {
        return organizBuilder.buildObject();
    }

    public static OrganizationName buildOrganizationName() {
        return orgNameBuilder.buildObject();
    }

    public static OrganizationDisplayName buildOrganizationDisplayName() {
        return orgDispBuilder.buildObject();
    }

    public static OrganizationURL buildOrganizationURL() {
        return orgUrlBuilder.buildObject();
    }

    public static Fault buildFault() {
        return faultBuilder.buildObject();
    }

    public static FaultCode buildFaultCode() {
        return fCodeBuilder.buildObject();
    }

    public static FaultString buildFaultString() {
        return fStrBuilder.buildObject();
    }

    public static Envelope buildEnvelope() {
        return envBuilder.buildObject();
    }

    public static Body buildBody() {
        return bodyBuilder.buildObject();
    }
}