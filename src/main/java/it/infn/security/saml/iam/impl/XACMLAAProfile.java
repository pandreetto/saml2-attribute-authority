package it.infn.security.saml.iam.impl;

public class XACMLAAProfile {

    public static final String ACTION_ID_URI = "urn:oasis:names:tc:xacml:1.0:action:action-id";

    public static final String SUBJECT_ID_URI = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
    
    public static final String RESOURCE_ID_URI = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";

    public static final String XACML_SAML_PROFILE_URI = "urn:mace:switch.ch:doc:xacml-saml:profile:200711:SOAP";

    /*
     * Types
     */

    public static final String XSD_STRING = "http://www.w3.org/2001/XMLSchema#string";
    
    public static final String XSD_X500NAME = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";

    /*
     * Actions
     */

    public static final String QUERY_ATTR_ACTION_URI = "http://infn.it/xacml/aa/query-attribute";

    /*
     * Environment
     */

    public static final String PROFILE_ID_URI = "http://infn.it/xacml/aa/profile-id";

    public static final String PROFILE_ID_VALUE = "http://infn.it/xacml/aa/1.0";

    /*
     * Obligations
     */

    public static final String ATTR_FILTER_OBLI_URI = "http://infn.it/xacml/aa/obligation/attribute-filter";

    public static final String ATTR_FILTER_ID_URI = "http://infn.it/xacml/aa/obligation/attribute-id";

}