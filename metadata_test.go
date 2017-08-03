package saml

import (
	"time"

	"encoding/xml"

	"github.com/kr/pretty"
	. "gopkg.in/check.v1"
)

type MetadataTest struct{}

var _ = Suite(&MetadataTest{})

func (s *MetadataTest) TestCanParseMetadata(c *C) {
	buf := []byte(`<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor ID='_af805d1c-c2e3-444e-9cf5-efc664eeace6' entityID='https://dev.aa.kndr.org/users/auth/saml/metadata' cacheDuration='PT1H' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><md:SPSSODescriptor AuthnRequestsSigned='false' WantAssertionsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'><md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://dev.aa.kndr.org/users/auth/saml/callback' index='0' isDefault='true'/><md:AttributeConsumingService index='1' isDefault='true'><md:ServiceName xml:lang='en'>Required attributes</md:ServiceName><md:RequestedAttribute FriendlyName='Email address' Name='email' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Full name' Name='name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Given name' Name='first_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/><md:RequestedAttribute FriendlyName='Family name' Name='last_name' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'/></md:AttributeConsumingService></md:SPSSODescriptor></md:EntityDescriptor>`)

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	c.Assert(err, IsNil)
	pretty.Print(metadata)
	var False = false
	var True = true
	c.Assert(metadata, DeepEquals, EntityDescriptor{
		EntityID:      "https://dev.aa.kndr.org/users/auth/saml/metadata",
		ID:            "_af805d1c-c2e3-444e-9cf5-efc664eeace6",
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			SPSSODescriptor{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					},
				},
				AuthnRequestsSigned:  &False,
				WantAssertionsSigned: &False,
				AssertionConsumerServices: []IndexedEndpoint{
					IndexedEndpoint{
						Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location:  "https://dev.aa.kndr.org/users/auth/saml/callback",
						Index:     0,
						IsDefault: &True,
					},
				},
				AttributeConsumingServices: []AttributeConsumingService{
					AttributeConsumingService{
						Index:        1,
						IsDefault:    &True,
						ServiceNames: []LocalizedName{{Value: "Required attributes"}},
						RequestedAttributes: []RequestedAttribute{
							{
								Attribute: Attribute{
									FriendlyName: "Email address",
									Name:         "email",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Full name",
									Name:         "name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Given name",
									Name:         "first_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Family name",
									Name:         "last_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
						},
					},
				},
			},
		},
	})
}

func (s *MetadataTest) TestCanProduceSPMetadata(c *C) {
	WantAssertionsSigned := true
	metadata := EntityDescriptor{
		XMLNS:         "http://www.w3.org/2000/09/xmldsig#",
		EntityID:      "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/",
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			SPSSODescriptor{
				WantAssertionsSigned: &WantAssertionsSigned,
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									XMLNS: "http://www.w3.org/2000/09/xmldsig#",
									Certificate: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
								},
							},
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									XMLNS: "http://www.w3.org/2000/09/xmldsig#",
									Certificate: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
								},
							},
						},
					},

					SingleLogoutServices: []Endpoint{{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					}},
				},

				AssertionConsumerServices: []IndexedEndpoint{{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					Index:    1,
				}},
			},
		},
	}

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	c.Assert(err, IsNil)
	c.Assert(string(buf), Equals, ""+
		"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" cacheDuration=\"PT1H\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/\">\n"+
		"  <SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAssertionsSigned=\"true\">\n"+
		"    <KeyDescriptor use=\"encryption\">\n"+
		"      <KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"        <X509Data>\n"+
		"          <X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE&#xA;CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX&#xA;DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x&#xA;EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308&#xA;kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv&#xA;SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf&#xA;nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv&#xA;TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+&#xA;cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate>\n"+
		"        </X509Data>\n"+
		"      </KeyInfo>\n"+
		"    </KeyDescriptor>\n"+
		"    <KeyDescriptor use=\"signing\">\n"+
		"      <KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"+
		"        <X509Data>\n"+
		"          <X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE&#xA;CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX&#xA;DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x&#xA;EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308&#xA;kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv&#xA;SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf&#xA;nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv&#xA;TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+&#xA;cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</X509Certificate>\n"+
		"        </X509Data>\n"+
		"      </KeyInfo>\n"+
		"    </KeyDescriptor>\n"+
		"    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/\"></SingleLogoutService>\n"+
		"    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/\" index=\"1\"></AssertionConsumerService>\n"+
		"  </SPSSODescriptor>\n"+
		"</EntityDescriptor>")
}
