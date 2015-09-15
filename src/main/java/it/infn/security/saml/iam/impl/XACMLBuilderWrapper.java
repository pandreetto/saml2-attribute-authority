package it.infn.security.saml.iam.impl;

import java.util.Collection;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.ActionType;
import org.opensaml.xacml.ctx.AttributeType;
import org.opensaml.xacml.ctx.AttributeValueType;
import org.opensaml.xacml.ctx.EnvironmentType;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResourceContentType;
import org.opensaml.xacml.ctx.ResourceType;
import org.opensaml.xacml.ctx.SubjectType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.XMLObjectBuilderFactory;

public class XACMLBuilderWrapper {

    private SAMLObjectBuilder<XACMLAuthzDecisionQueryType> authzDecisionQueryBuilder;

    private SOAPObjectBuilder<Body> bodyBuilder;

    private SOAPObjectBuilder<Envelope> envelopeBuilder;

    private SAMLObjectBuilder<Issuer> issuerBuilder;

    private XACMLObjectBuilder<RequestType> requestBuilder;

    private XACMLObjectBuilder<ActionType> actionBuilder;

    private XACMLObjectBuilder<AttributeType> attributeBuilder;

    private XACMLObjectBuilder<AttributeValueType> attributeValueBuilder;

    private XACMLObjectBuilder<EnvironmentType> environmentBuilder;

    private XACMLObjectBuilder<ResourceType> resourceBuilder;

    private XACMLObjectBuilder<ResourceContentType> resourceContentBuilder;

    private XACMLObjectBuilder<SubjectType> subjectBuilder;

    @SuppressWarnings("unchecked")
    private XACMLBuilderWrapper() {

        XMLObjectBuilderFactory objFactory = Configuration.getBuilderFactory();

        Object tmpo = objFactory.getBuilder(XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);
        authzDecisionQueryBuilder = (SAMLObjectBuilder<XACMLAuthzDecisionQueryType>) tmpo;
        bodyBuilder = (SOAPObjectBuilder<Body>) objFactory.getBuilder(Body.TYPE_NAME);
        envelopeBuilder = (SOAPObjectBuilder<Envelope>) objFactory.getBuilder(Envelope.TYPE_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) objFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        requestBuilder = (XACMLObjectBuilder<RequestType>) objFactory.getBuilder(RequestType.DEFAULT_ELEMENT_NAME);
        actionBuilder = (XACMLObjectBuilder<ActionType>) objFactory.getBuilder(ActionType.DEFAULT_ELEMENT_NAME);
        attributeBuilder = (XACMLObjectBuilder<AttributeType>) objFactory
                .getBuilder(AttributeType.DEFAULT_ELEMENT_NAME);
        attributeValueBuilder = (XACMLObjectBuilder<AttributeValueType>) objFactory
                .getBuilder(AttributeValueType.DEFAULT_ELEMENT_NAME);
        environmentBuilder = (XACMLObjectBuilder<EnvironmentType>) objFactory
                .getBuilder(EnvironmentType.DEFAULT_ELEMENT_NAME);
        resourceBuilder = (XACMLObjectBuilder<ResourceType>) objFactory.getBuilder(ResourceType.DEFAULT_ELEMENT_NAME);
        resourceContentBuilder = (XACMLObjectBuilder<ResourceContentType>) objFactory
                .getBuilder(ResourceContentType.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (XACMLObjectBuilder<SubjectType>) objFactory.getBuilder(SubjectType.DEFAULT_ELEMENT_NAME);
    }

    public XACMLAuthzDecisionQueryType buildDecisionQuery() {
        return authzDecisionQueryBuilder.buildObject(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20,
                XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);
    }

    public Issuer buildIssuer(String format) {
        Issuer result = issuerBuilder.buildObject();
        result.setFormat(format);
        return result;
    }

    public Body buildBody() {
        return bodyBuilder.buildObject();
    }

    public Envelope buildEnvelope() {
        return envelopeBuilder.buildObject();
    }

    public RequestType buildRequest() {
        return requestBuilder.buildObject();
    }

    public ActionType buildAction() {
        return actionBuilder.buildObject();
    }

    public EnvironmentType buildEnviron() {
        return environmentBuilder.buildObject();
    }

    public ResourceType buildResource(String contentStr) {
        ResourceType resource = resourceBuilder.buildObject();

        contentStr = safeTrimOrNullString(contentStr);
        if (contentStr != null) {
            ResourceContentType resourceContent = resourceContentBuilder.buildObject();
            resourceContent.setValue(contentStr);
            resource.setResourceContent(resourceContent);
        }
        return resource;
    }

    public SubjectType buildSubject(String category) {
        SubjectType subject = subjectBuilder.buildObject();
        subject.setSubjectCategory(safeTrimOrNullString(category));
        return subject;
    }

    public AttributeType buildAttribute(String id, String type, String issuer, String value) {
        AttributeType xacmlAttribute = attributeBuilder.buildObject();
        xacmlAttribute.setAttributeID(safeTrimOrNullString(id));
        xacmlAttribute.setDataType(safeTrimOrNullString(type));
        xacmlAttribute.setIssuer(safeTrimOrNullString(issuer));
        if (value != null) {
            AttributeValueType xacmlAttributeValue = attributeValueBuilder.buildObject();
            xacmlAttributeValue.setValue(value);
            xacmlAttribute.getAttributeValues().add(xacmlAttributeValue);
        }
        return xacmlAttribute;
    }

    public AttributeType buildAttribute(String id, String type, String issuer, Collection<String> values) {
        AttributeType xacmlAttribute = attributeBuilder.buildObject();

        xacmlAttribute.setAttributeID(safeTrimOrNullString(id));
        xacmlAttribute.setDataType(safeTrimOrNullString(type));
        xacmlAttribute.setIssuer(safeTrimOrNullString(issuer));

        if (values != null) {
            AttributeValueType xacmlAttributeValue;
            for (Object attributeValue : values) {
                String value = safeTrimOrNullString(attributeValue.toString());
                if (value != null) {
                    xacmlAttributeValue = attributeValueBuilder.buildObject();
                    xacmlAttributeValue.setValue(value);
                    xacmlAttribute.getAttributeValues().add(xacmlAttributeValue);
                }
            }
        }

        return xacmlAttribute;

    }

    private String safeTrimOrNullString(String s) {
        if (s != null) {
            String sTrimmed = s.trim();
            if (sTrimmed.length() > 0) {
                return sTrimmed;
            }
        }

        return null;
    }

    private static final XACMLBuilderWrapper theWrapper = new XACMLBuilderWrapper();

    public static XACMLBuilderWrapper getInstance() {
        return theWrapper;
    }
}