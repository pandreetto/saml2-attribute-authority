package it.infn.security.saml.spmetadata;

import it.infn.security.saml.aa.CodedException;

public class MetadataSourceException
    extends CodedException {

    public static final long serialVersionUID = 1461244964;

    public MetadataSourceException(String msg, int code) {
        super(msg, code);
    }

    public MetadataSourceException(String msg) {
        super(msg);
    }

    public MetadataSourceException(String msg, int code, Throwable th) {
        super(msg, code, th);
    }

    public MetadataSourceException(String msg, Throwable th) {
        super(msg, th);
    }

}
