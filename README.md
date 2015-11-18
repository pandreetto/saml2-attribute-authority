# SAML2 Attribute Authority


## Build with Maven

Requirements:

- Java 7
- Maven 3

Build it with the following command:

  mvn install
  
the web-application file is target/saml2-attribute-authority-*.*.war

## Eclipse import instructions

To import the project in Eclipse for development, do as follows:

  mvn clean eclipse:clean
  mvn eclipse:eclipse

From Eclipse menu, select “Import Existing Maven projects...”, and
point it to this project root directory.

## Build and deploy artifact on tomcat7

Requirements:

- the tomcat admin web-application
- mysql server


Tomcat configuration:

Define the following declarations in the tomcat admin configuration file (/etc/tomcat/tomcat-users.xml):
```
<tomcat-users>
  <role rolename="admin"/>
  <role rolename="admin-gui"/>
  <role rolename="admin-script"/>
  <role rolename="manager"/>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <role rolename="manager-jmx"/>
  <role rolename="manager-status"/>
  <user name="admin" password="***********" 
        roles="admin,manager,admin-gui,admin-script,manager-gui,manager-script,manager-jmx,manager-status" />
</tomcat-users>

```

Maven configuration:

In the maven per-user configuration file ($HOME/.m2/settings.xml) define the following properties:
```
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">

  <profiles>
    <profile>
      <id>tomcatenabled-profile</id>
      <activation><activeByDefault>true</activeByDefault></activation>
        <properties>
          <tomcat.manager.type>tomcat7</tomcat.manager.type>
          <tomcat.manager.epr>http://***************:****/manager/text</tomcat.manager.epr>
          <tomcat.manager.login>tomcatloginid</tomcat.manager.login>
        </properties>
    </profile>
  </profiles>
  
  <servers>
    <server>
      <id>tomcatloginid</id>
      <username>admin</username>
      <password>***********</password>
    </server>
  </servers>
  
</settings>
```
The property *tomcat.manager.epr* contains the url of tomcat installation.
The tags *username* and *password* refer to the administrator account configured in tomcat, as described above.

Deployment:

  mvn clean tomcat7:deploy

## Setup of the service

Configuration of the web application:

For a single context installation the default configuration file is */etc/saml2-attribute-authority/configuration.conf*.
The file is a simple java property file (key = value) with the following definitions:

  Generale definitions:
- authority.id : the SAML2 id of the service
- authority.url : the endpoint of the query attribute service

  Credential definitions:
- key.manager.file : the keystore file containing the server credentials
- key.manager.type : the type of the keystore file (JKS, PKCS12)
- key.manager.password : the password of the keystore file
- key.manager.alias : the alias of the credential to use inside the keystore file
- trust.manager.file : the truststore file containing the CA certificates
- trust.manager.type : the type of the truststore file (JKS, PKCS12)
- trust.manager.password : the password of the truststore
- signature.algorithm : the standard algorithm used for signing assertions and metadata (default http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)
- signature.policy : signature algorithm selection criterion, one of request_driven, authorization_driven, as_in_configuration(default)

  Metadata definitions:
- metadata.expiration_time : the expiration time of the published metadata
- organization.name.`<lang>` : the localized name of the organization running the service
- organization.displayname.`<lang>` : the localized human readable name of the organization
- organization.url.`<lang>` : the localized url of the organization site
- contact.type.`<contactid>` : the type of the contact for a given contactid (administrative, billing, support, technical, other)
- contact.givenName.`<contactid>` : the given name for a given contactid
- contact.surName.`<contactid>` : the family name a given contactid
- contact.emails.`<contactid>` : a comma separated list of email addresses a given contactid
- contact.phones.`<contactid>` : a comma separated list of phone numbers a given contactid

The lang suffix is the standard two-letters representation of the language used. More organization.* properties are allowed if they specify different languages.
The contactid suffix is 

  Datasource definitions (hibernate implementation):
The set of properties are the ones required by hibernate (http://docs.jboss.org/hibernate/orm/4.3/manual/en-US/html/ch03.html)

This is an example of a configuration file:
```
authority.id=saml2aa.infn.it:8443:it.infn.security.saml
authority.url=https://saml2aa.infn.it:8443/saml2-attribute-authority
key.manager.file=/etc/tomcat/hostkeys.p12
key.manager.type=PKCS12
key.manager.password=myp@ssw0rd
key.manager.alias=tomcat
trust.manager.file=/etc/tomcat/mytruststore.jks
trust.manager.type=JKS
trust.manager.password=myp@ssw0rd
signature.algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
metadata.expiration_time=432000

hibernate.connection.driver_class=org.gjt.mm.mysql.Driver
hibernate.connection.url=jdbc:mysql://saml2aa.infn.it:3306/db?autoReconnect=true
hibernate.connection.username=mbuto
hibernate.connection.password=myp@ssw0rd
hibernate.dialect=org.hibernate.dialect.MySQL5InnoDBDialect

hibernate.c3p0.min_size=5
hibernate.c3p0.max_size=20
hibernate.c3p0.timeout=60
hibernate.c3p0.max_statements=50
hibernate.c3p0.idle_test_period=3000

hibernate.current_session_context_class=thread
hibernate.cache.provider_class=org.hibernate.cache.internal.NoCacheProvider
hibernate.show_sql=true
hibernate.hbm2ddl.auto=update

contact.type.id01=support
contact.givenName.id01=Mario
contact.surName.id01=Rossi
contact.emails.id01=mario.rossi@example.it,rossim@example.com
contact.phones.id01=3456859386,340797234107

contact.type.id02=technical
contact.givenName.id02=Guido
contact.surName.id02=Bianchi
contact.emails.id02=guido.bianchi@example.net
contact.phones.id02=3354254523,352452345423

organization.name.en=Example.Com
organization.displayname.en=Site for examples
organization.url.en=http://www.example.com

```

Setup of the datasource (Mysql with Hibernate implementation):

The SQL script creating the database is the following:
```
create table attributes (attr_content varchar(255) not null, attr_key varchar(255) not null, attr_description varchar(255) not null, attr_type varchar(255) not null, primary key (attr_content, attr_key)) ENGINE=InnoDB;
create table bind_attribute (resource_id varchar(255) not null, attributes_attr_content varchar(255) not null, attributes_attr_key varchar(255) not null, primary key (resource_id, attributes_attr_content, attributes_attr_key)) ENGINE=InnoDB;
create table external_id (id bigint not null auto_increment, external_id varchar(255) not null, tenant varchar(255) not null, owner_id varchar(255) not null, primary key (id)) ENGINE=InnoDB;
create table groups (displayName varchar(255) not null, id varchar(255) not null, primary key (id)) ENGINE=InnoDB;
create table memberof (source varchar(255) not null, target varchar(255) not null, primary key (source, target)) ENGINE=InnoDB;
create table resources (id varchar(255) not null, creation_date datetime not null, last_update datetime not null, resource_status integer not null, resource_type integer not null, version varchar(255) not null, primary key (id)) ENGINE=InnoDB;
create table user_address (id bigint not null auto_increment, country varchar(255), locality varchar(255), zip varchar(255), region varchar(255), street varchar(255), addr_type varchar(255), user_id varchar(255) not null, primary key (id)) ENGINE=InnoDB;
create table user_attrs (id bigint not null auto_increment, attr_name varchar(255) not null, attr_type varchar(255), attr_value varchar(255) not null, user_id varchar(255) not null, primary key (id)) ENGINE=InnoDB;
create table users (userName varchar(255) not null, id varchar(255) not null, primary key (id)) ENGINE=InnoDB;
alter table users add constraint UK_mmns67o5v4bfippoqitu4v3t6  unique (userName);
alter table bind_attribute add constraint FK_tf0u67x5cfjadtw3ncflsh3sb foreign key (attributes_attr_content, attributes_attr_key) references attributes (attr_content, attr_key);
alter table bind_attribute add constraint FK_3ya8a5o0ows00kvr2962tcj9 foreign key (resource_id) references resources (id);
alter table external_id add constraint FK_m6ly072cao8tkkkwgp1xl96nm foreign key (owner_id) references resources (id);
alter table groups add constraint FK_4p5w2xqcslb4xl3180yx96vmw foreign key (id) references resources (id);
alter table memberof add constraint FK_gjc3c10e52s216ddmregrgs64 foreign key (target) references resources (id);
alter table memberof add constraint FK_dd6s4oamvxdg2u6ddish0q486 foreign key (source) references resources (id);
alter table user_address add constraint FK_kfu0161nvirkey6fwd6orucv7 foreign key (user_id) references users (id);
alter table user_attrs add constraint FK_an6eakllhpy6an4d49e3m82k5 foreign key (user_id) references users (id);
alter table users add constraint FK_6jvqtxgs6xvh0h0t261hurgqo foreign key (id) references resources (id);

```





