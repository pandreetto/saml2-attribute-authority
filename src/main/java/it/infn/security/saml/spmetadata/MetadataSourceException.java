package it.infn.security.saml.spmetadata;

import it.infn.security.saml.aa.CodedException;

public class MetadataSourceException
    extends CodedException {

    public static final long serialVersionUID = 1461244964;

    public MetadataSourceException(String msg, String code, String subcode) {
        super(msg, code, subcode);
    }

    public MetadataSourceException(String msg, String code) {
        super(msg, code);
    }

    public MetadataSourceException(String msg) {
        super(msg);
    }

    public MetadataSourceException(String msg, String code, String subcode, Throwable th) {
        super(msg, code, subcode, th);
    }

    public MetadataSourceException(String msg, String code, Throwable th) {
        super(msg, code, th);
    }

    public MetadataSourceException(String msg, Throwable th) {
        super(msg, th);
    }

}
