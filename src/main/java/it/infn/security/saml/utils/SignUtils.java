package it.infn.security.saml.utils;

import it.infn.security.saml.configuration.AuthorityConfiguration;
import it.infn.security.saml.configuration.AuthorityConfigurationFactory;
import it.infn.security.saml.configuration.ConfigurationException;
import it.infn.security.saml.schema.SchemaManager;
import it.infn.security.saml.schema.SchemaManagerException;
import it.infn.security.saml.schema.SchemaManagerFactory;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.Subject;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
import org.opensaml.xml.validation.ValidationException;

public class SignUtils {

    private static final Logger logger = Logger.getLogger(SignUtils.class.getName());

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

    public static void signObject(SignableXMLObject object, String signAlgorithm)
        throws ConfigurationException, SchemaManagerException, SignatureException, MarshallingException,
        CertificateEncodingException {

        AuthorityConfiguration configuration = AuthorityConfigurationFactory.getConfiguration();
        SchemaManager schemaManager = SchemaManagerFactory.getManager();

        X509Certificate srvCert = configuration.getServiceCertificate();
        PrivateKey srvKey = configuration.getServicePrivateKey();
        Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

        if (signAlgorithm == null || signAlgorithm.length() == 0) {
            signAlgorithm = configuration.getSignatureAlgorithm();
        }
        schemaManager.checkSignatureAlgorithm(signAlgorithm);

        Signature objSignature = SAML2ObjectBuilder.buildSignature();
        objSignature.setSigningCredential(credential);
        objSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        objSignature.setSignatureAlgorithm(signAlgorithm);
        objSignature.setKeyInfo(SignUtils.buildKeyInfo(srvCert));

        object.setSignature(objSignature);

        /*
         * TODO verify workaround
         */
        Marshaller marshaller = SAML2ObjectBuilder.getMarshaller(object);
        marshaller.marshall(object);

        Signer.signObject(objSignature);
    }

    public static void signObject(SignableXMLObject object)
        throws ConfigurationException, SchemaManagerException, SignatureException, MarshallingException,
        CertificateEncodingException {
        signObject(object, null);
    }

    public static void verifySignature(Signature signature, Subject requester)
        throws SecurityException, SchemaManagerException, ConfigurationException, ValidationException {

        SchemaManager schemaManager = SchemaManagerFactory.getManager();
        schemaManager.checkSignatureAlgorithm(signature.getSignatureAlgorithm());

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        X509Certificate subjectCertificate = null;
        Set<X509Certificate[]> allChain = requester.getPublicCredentials(X509Certificate[].class);
        for (X509Certificate[] peerChain : allChain) {
            subjectCertificate = peerChain[0];
        }
        if (subjectCertificate == null) {
            /*
             * TODO get the certificate from <KeyInfo/> even if is not mandatory for SAML XMLSig profile certificate
             * requires validation
             */
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        SignatureValidator signatureValidator = new SignatureValidator(peerCredential);
        signatureValidator.validate(signature);
        logger.fine("Signature verified for " + subjectCertificate.getSubjectX500Principal().getName());

    }

}