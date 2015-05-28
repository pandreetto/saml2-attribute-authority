package it.infn.security.saml.datasource;

import it.infn.security.saml.aa.CodedException;

public class DataSourceException
    extends CodedException {

    public static final long serialVersionUID = 1432129668;

    public DataSourceException(String msg, String code, String subcode) {
        super(msg, code, subcode);
    }

    public DataSourceException(String msg, String code) {
        super(msg, code);
    }

    public DataSourceException(String msg) {
        super(msg);
    }

    public DataSourceException(String msg, String code, String subcode, Throwable th) {
        super(msg, code, subcode, th);
    }

    public DataSourceException(String msg, String code, Throwable th) {
        super(msg, code, th);
    }

    public DataSourceException(String msg, Throwable th) {
        super(msg, th);
    }

}