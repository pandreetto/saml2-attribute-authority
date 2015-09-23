package it.infn.security.saml.ocp;

import it.infn.security.saml.datasource.DataSource;
import it.infn.security.saml.datasource.DataSourceException;
import it.infn.security.saml.datasource.DataSourceFactory;
import it.infn.security.saml.iam.AccessManager;
import it.infn.security.saml.iam.AccessManagerFactory;
import it.infn.security.saml.iam.IdentityManager;
import it.infn.security.saml.iam.IdentityManagerFactory;
import it.infn.security.saml.ocp.hibernate.SPIDDataSource;
import it.infn.security.saml.utils.SCIMUtils;
import it.infn.security.saml.utils.charon.JAXRSResponseBuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.charon.core.protocol.ResponseCodeConstants;
import org.wso2.charon.core.schema.SCIMConstants;

@Path("/attributes")
public class SPIDAttributeManager {

    private static final Logger logger = Logger.getLogger(SPIDAttributeManager.class.getName());

    public SPIDAttributeManager() {

    }

    @GET
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributeKeys(@HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeListAttributes(requester);

            SPIDDataSource dataSource = checkDataSource(DataSourceFactory.getDataSource());
            String encodedKeys = encodeKeyList(dataSource.getAttributeKeys());
            return buildResponse(encodedKeys, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @GET
    @Path("{attrKey}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response getAttributesByKey(@PathParam("attrKey") String attrKey,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeShowAttribute(requester, attrKey);

            SPIDDataSource dataSource = checkDataSource(DataSourceFactory.getDataSource());
            String encodedAttr = encodeAttribute(dataSource.getAttribute(attrKey));
            return buildResponse(encodedAttr, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @DELETE
    @Path("{attrKey}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response deleteAllAttributesByKey(@PathParam("attrKey") String attrKey,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization) {

        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeDeleteAttribute(requester, attrKey);

            SPIDDataSource dataSource = checkDataSource(DataSourceFactory.getDataSource());
            dataSource.removeAttribute(attrKey);
            return buildResponse(ResponseCodeConstants.CODE_OK, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @PUT
    @Path("{attrKey}")
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response deleteAttribute(@PathParam("attrKey") String attrKey,
            @HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String payload) {

        inputFormat = SCIMUtils.normalizeFormat(inputFormat);
        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(inputFormat))
                || !SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SPIDAttribute attrItem = parsePayload(payload);
            SPIDDataSource dataSource = checkDataSource(DataSourceFactory.getDataSource());
            dataSource.updateAttribute(attrItem);
            String encodedAttr = encodeAttribute(attrItem);
            return buildResponse(encodedAttr, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    @POST
    @Produces(SCIMConstants.APPLICATION_JSON)
    public Response createAttribute(@HeaderParam(SCIMConstants.CONTENT_TYPE_HEADER) String inputFormat,
            @HeaderParam(SCIMConstants.ACCEPT_HEADER) String outputFormat,
            @HeaderParam(SCIMConstants.AUTHORIZATION_HEADER) String authorization, String payload) {

        inputFormat = SCIMUtils.normalizeFormat(inputFormat);
        outputFormat = SCIMUtils.normalizeFormat(outputFormat);

        if (!SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(inputFormat))
                || !SCIMConstants.APPLICATION_JSON.equals(SCIMUtils.normalizeFormat(outputFormat))) {
            return buildResponse(ResponseCodeConstants.CODE_BAD_REQUEST, outputFormat);
        }

        try {

            IdentityManager identityManager = IdentityManagerFactory.getManager();
            AccessManager accessManager = AccessManagerFactory.getManager();
            Subject requester = identityManager.authenticate();
            accessManager.authorizeCreateAttribute(requester);

            SPIDAttribute attrItem = parsePayload(payload);

            SPIDDataSource dataSource = checkDataSource(DataSourceFactory.getDataSource());
            dataSource.createAttribute(attrItem);
            String encodedAttr = encodeAttribute(attrItem);
            return buildResponse(encodedAttr, outputFormat);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return JAXRSResponseBuilder.buildResponse(SCIMUtils.responseFromException(ex, outputFormat));
        }

    }

    private SPIDDataSource checkDataSource(DataSource ds)
        throws DataSourceException {
        if (!(ds instanceof SPIDDataSource)) {
            throw new DataSourceException("SPIDDataSource implementation is required");
        }
        return (SPIDDataSource) ds;
    }

    private String encodeAttribute(SPIDAttribute attr)
        throws JSONException {
        JSONObject rootObject = new JSONObject();
        rootObject.put("schemas", SPIDSchemaManager.SPID_SCHEMA_URI);
        rootObject.put(SPIDSchemaManager.KEY_ATTR_ID, attr.getKey());
        rootObject.put(SPIDSchemaManager.DESCR_ATTR_ID, attr.getDescription());
        JSONArray arrayObject = new JSONArray();
        for (String value : attr.getValues()) {
            arrayObject.put(value);
        }
        rootObject.put(SPIDSchemaManager.VALUE_ATTR_ID, arrayObject);
        return rootObject.toString();
    }

    private String encodeKeyList(List<String> keys)
        throws JSONException {
        JSONObject rootObject = new JSONObject();
        rootObject.put("schemas", SPIDSchemaManager.SPID_SCHEMA_URI);
        JSONArray arrayObject = new JSONArray();
        for (String key : keys) {
            arrayObject.put(key);
        }
        rootObject.put(SPIDSchemaManager.KEY_ATTR_ID, arrayObject);
        return rootObject.toString();
    }

    private SPIDAttribute parsePayload(String payload)
        throws JSONException {
        JSONObject rootObject = new JSONObject(new JSONTokener(payload));

        Object keyObj = rootObject.opt(SPIDSchemaManager.KEY_ATTR_ID);
        if (keyObj == null || !(keyObj instanceof String)) {
            throw new JSONException("Missing or wrong " + SPIDSchemaManager.KEY_ATTR_ID);
        }

        Object valObj = rootObject.opt(SPIDSchemaManager.VALUE_ATTR_ID);
        if (valObj == null || !(valObj instanceof JSONArray)) {
            throw new JSONException("Missing or wrong " + SPIDSchemaManager.VALUE_ATTR_ID);
        }
        JSONArray jValues = (JSONArray) valObj;
        List<String> values = new ArrayList<String>(jValues.length());
        for (int k = 0; k < jValues.length(); k++) {
            Object tmpObj = jValues.get(k);
            if (tmpObj == null || !(tmpObj instanceof String)) {
                throw new JSONException("Missing or wrong " + SPIDSchemaManager.VALUE_ATTR_ID);
            }
            values.add((String) tmpObj);
        }

        Object descrObj = rootObject.opt(SPIDSchemaManager.DESCR_ATTR_ID);
        if (descrObj == null || !(descrObj instanceof String)) {
            throw new JSONException("Missing or wrong " + SPIDSchemaManager.DESCR_ATTR_ID);
        }

        return new SPIDAttribute((String) keyObj, values, (String) descrObj);
    }

    private Response buildResponse(String message, String format) {

        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return JAXRSResponseBuilder.buildResponse(ResponseCodeConstants.CODE_OK, httpHeaders, message);

    }

    private Response buildResponse(int code, String format) {
        Map<String, String> httpHeaders = new HashMap<String, String>();
        httpHeaders.put(SCIMConstants.CONTENT_TYPE_HEADER, format);
        return JAXRSResponseBuilder.buildResponse(code, httpHeaders, null);
    }

}