package it.infn.security.saml.utils;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;

public class SignUtils {

    private static final Base64 base64Enc = new Base64(64, new byte[] { '\n' });

    public static KeyInfo buildKeyInfo(X509Certificate signCert)
        throws CertificateEncodingException {

        KeyInfo keyInfo = SAML2ObjectBuilder.buildKeyInfo();
        KeyName keyName = SAML2ObjectBuilder.buildKeyName();
        X509Data x509Data = SAML2ObjectBuilder.buildX509Data();
        X509SubjectName x509Sbj = SAML2ObjectBuilder.buildX509SubjectName();

        org.opensaml.xml.signature.X509Certificate x509Cert = SAML2ObjectBuilder.buildX509Certificate();
        /*
         * TODO verify keyName
         */
        keyName.setValue(signCert.getSubjectDN().getName());
        x509Sbj.setValue(signCert.getSubjectDN().getName());
        x509Data.getX509SubjectNames().add(x509Sbj);
        byte[] certEncoded = signCert.getEncoded();
        x509Cert.setValue(base64Enc.encodeToString(certEncoded));
        x509Data.getX509Certificates().add(x509Cert);

        keyInfo.getKeyNames().add(keyName);
        keyInfo.getX509Datas().add(x509Data);

        return keyInfo;
    }

    public static void signObject(SignableXMLObject object)
        throws ConfigurationException, SignatureException, MarshallingException, CertificateEncodingException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();

        X509Certificate srvCert = configuration.getServiceCertificate();
        PrivateKey srvKey = configuration.getServicePrivateKey();
        Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

        Signature objSignature = SAML2ObjectBuilder.buildSignature();
        objSignature.setSigningCredential(credential);
        objSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        objSignature.setSignatureAlgorithm(configuration.getSignatureAlgorithm());
        objSignature.setKeyInfo(SignUtils.buildKeyInfo(srvCert));

        object.setSignature(objSignature);

        /*
         * TODO verify workaround
         */
        Marshaller marshaller = SAML2ObjectBuilder.getMarshaller(object);
        marshaller.marshall(object);

        Signer.signObject(objSignature);
    }

}