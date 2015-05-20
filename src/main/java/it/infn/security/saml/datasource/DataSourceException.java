package it.infn.security.saml.datasource;

import org.opensaml.saml2.core.StatusCode;

public class DataSourceException
    extends Exception {

    public static final long serialVersionUID = 1432129668;

    public DataSourceException(String msg, String code) {
        super(msg);
    }

    public DataSourceException(String msg, String code, Throwable th) {
        super(msg, th);
    }

    public String getStatusCode() {
        return StatusCode.RESPONDER_URI;
    }

    public String getSubStatusCode() {
        return null;
    }
}