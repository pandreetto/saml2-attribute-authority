package it.infn.security.scim.protocol;

public class SCIMConstants {

    public static final String GROUP_ENDPOINT = "/Groups";

    public static final String USER_ENDPOINT = "/Users";

    public static final String SELF_ENDPOINT = "/Me";

    public static final String APPLICATION_SCIM = "application/scim+json";

    public static final String APPLICATION_JSON = "application/json";

    public static final String TEXT_XML = "text/xml";

    public static final String ACCEPT_HEADER = "Accept";

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String CONTENT_TYPE_HEADER = "Content-Type";

    public static final String LOCATION_HEADER = "Location";

    public static final String ID = "id";

    public static final int CODE_INTERNAL_SERVER_ERROR = 500;

    public static final int CODE_NOT_IMPLEMENTED = 501;

    public static final int CODE_BAD_REQUEST = 400;

    public static final int CODE_NOT_FOUND = 404;

    public static final int CODE_OK = 200;

    public static final int CODE_CREATED = 201;

    public static final int CODE_NO_CONTENT = 204;

    public static final String DESC_BAD_REQUEST_GET = "GET request does not support the "
            + "requested URL query parameter combination.";

}