package it.infn.security.scim.protocol;

public class SCIMConstants {

    /*
     * TODO change to application/scim+json
     */
    public static final String APPLICATION_JSON = "application/json";
    
    public static final String TEXT_XML = "text/xml";

    public static final String ACCEPT_HEADER = "Accept";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String CONTENT_TYPE_HEADER = "Content-Type";

    public static final String ID = "id";

    public static final int CODE_BAD_REQUEST = 400;

    public static final int CODE_OK = 200;

    public static final String DESC_BAD_REQUEST_GET = "GET request does not support the "
            + "requested URL query parameter combination.";

}