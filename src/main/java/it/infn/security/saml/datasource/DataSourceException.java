package it.infn.security.saml.datasource;

import org.opensaml.saml2.core.StatusCode;

public class DataSourceException
    extends Exception {

    public static final long serialVersionUID = 1432129668;

    private String code;

    private String subcode;

    public DataSourceException(String msg, String code, String subcode) {
        super(msg);
        this.code = code;
        this.subcode = subcode;
    }

    public DataSourceException(String msg, String code) {
        this(msg, code, (String) null);
    }

    public DataSourceException(String msg) {
        this(msg, StatusCode.RESPONDER_URI, (String) null);
    }

    public DataSourceException(String msg, String code, String subcode, Throwable th) {
        super(msg, th);
        this.code = code;
        this.subcode = subcode;
    }

    public DataSourceException(String msg, String code, Throwable th) {
        this(msg, code, (String) null, th);
    }

    public DataSourceException(String msg, Throwable th) {
        this(msg, StatusCode.RESPONDER_URI, (String) null, th);
    }

    public String getStatusCode() {
        return code;
    }

    public String getSubStatusCode() {
        return subcode;
    }
}