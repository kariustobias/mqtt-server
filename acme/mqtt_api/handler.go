package mqtt_api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	//import the Paho Go MQTT library
	MQTT "github.com/eclipse/paho.mqtt.golang"
	"github.com/go-chi/chi"
	acme "github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
	"gopkg.in/square/go-jose.v2"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=%q", url, typ)
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

var acmeDB acme.DB

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

type payloadByJWKOrKID struct {
	payload []byte
	jwk     *jose.JSONWebKey
	acc     *acme.Account
}

// HandlerOptions required to create a new ACME API request handler.
type HandlerOptions struct {
	// DB storage backend that implements the acme.DB interface.
	//
	// Deprecated: use acme.NewContex(context.Context, acme.DB)
	DB acme.DB

	// CA is the certificate authority interface.
	//
	// Deprecated: use authority.NewContext(context.Context, *authority.Authority)
	CA acme.CertificateAuthority

	// Backdate is the duration that the CA will subtract from the current time
	// to set the NotBefore in the certificate.
	Backdate provisioner.Duration

	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string

	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string

	// PrerequisitesChecker checks if all prerequisites for serving ACME are
	// met by the CA configuration.
	PrerequisitesChecker func(ctx context.Context) (bool, error)
}

var mustAuthority = func(ctx context.Context) acme.CertificateAuthority {
	return authority.MustFromContext(ctx)
}

// handler is the ACME API request handler.
type handler struct {
	opts *HandlerOptions
}

// Route traffic and implement the Router interface. This method requires that
// all the acme components, authority, db, client, linker, and prerequisite
// checker to be present in the context.
func Route(r api.Router) {
	route(r, nil)
}

// connects to MQTT Broker first
// subscribes to endpoint on broker
// saves db, since we dont have a context in MQTT
func Initialize(broker string, endpoint string, db acme.DB) error {
	client, err := connectToBroker(broker)
	if err != nil {
		return err
	}

	err = subscribe(endpoint, client)
	if err != nil {
		return err
	}

	acmeDB = db
	return nil
}

//start MQTT connection by connecting to broker
func connectToBroker(broker string) (MQTT.Client, error) {
	opts := MQTT.NewClientOptions().AddBroker(broker)
	opts.SetClientID("Device-sub")
	opts.SetDefaultPublishHandler(f)

	//create and start a client using the above ClientOptions
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("failed create new MQTT client: %w", token.Error())
	}
	return c, nil
}

//subscribe to MQTT endpoint
func subscribe(endpoint string, client MQTT.Client) error {
	if token := client.Subscribe(endpoint, 0, nil); token.Wait() && token.Error() != nil {
		return acme.WrapErrorISE(token.Error(), "failed to subscribe to MQTT endpoint")
	}
	return nil
}

type Path struct {
	Path string `json:"path"`
}

//define a function for the default message handler
var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {

	var path Path
	// get json out of msg
	json.Unmarshal(msg.Payload(), &path)
	var json []byte
	switch {
	case path.Path == "/acme/acme/directory":
		json = GetDirectoryMQTT()
	case path.Path == "/acme/acme/new-nonce":
		json = AddNonceMQTT(json)
	case path.Path == "/acme/acme/new-account":
		var payload *payloadByJWKOrKID
		payload, err := extractpayloadByJWKMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		json = NewAccountMQTT(acmeDB, payload.payload, nil, payload.jwk)
		json = AddNonceMQTT(json)
	case path.Path == "/acme/acme/new-order":
		var payload *payloadByJWKOrKID
		payload, err := extractPayloadByKidMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		json, err = NewOrderMQTT(acmeDB, payload.acc, payload.payload)
		if err != nil {
			fmt.Println(err)
		}
		json = AddNonceMQTT(json)
	case strings.Contains(path.Path, "/acme/authz"):
		var payload *payloadByJWKOrKID
		payload, err := extractPayloadByKidMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		authzID := path.Path[len("/acme/authz/"):]
		json, err = GetAuthorizationMQTT(acmeDB, payload.acc, authzID)
		if err != nil {
			fmt.Println(err)
		}
		json = AddNonceMQTT(json)
	case strings.Contains(path.Path, "/acme/challenge"):
		var payload *payloadByJWKOrKID
		payload, err := extractPayloadByKidMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		split, err := getAzIDChID(path.Path)
		if err != nil {
			fmt.Println(err)
		}
		json, err = GetChallengeMQTT(acmeDB, payload.acc, split[0], split[1], payload.jwk)
		if err != nil {
			fmt.Println(err)
		}
		json = AddNonceMQTT(json)
	case strings.Contains(path.Path, "finalize"):
		var payload *payloadByJWKOrKID
		payload, err := extractPayloadByKidMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		ordID := strings.ReplaceAll(path.Path, "/acme/order/", "")
		ordID = strings.ReplaceAll(ordID, "/finalize", "")

		json, err = FinalizeOrderMQTT(acmeDB, payload.acc, payload.payload, ordID)
		if err != nil {
			fmt.Println(err)
		}
		json = AddNonceMQTT(json)
	case strings.Contains(path.Path, "/acme/cert"):
		var payload *payloadByJWKOrKID
		payload, err := extractPayloadByKidMQTT(msg)
		if err != nil {
			fmt.Println(err)
		}
		json, err = GetCertificateMQTT(acmeDB, payload.acc, strings.ReplaceAll(path.Path, "/acme/cert/", ""))
		if err != nil {
			fmt.Println(err)
		}
	default:
		fmt.Printf("undefined path value: %s\n", path.Path)
		fmt.Println(string(msg.Payload()))
	}

	returnPath := fmt.Sprintf(",\"path\":\"%s\"}", path.Path)
	fmt.Printf("json before append: %s\n", string(json))
	json = append(json[:len(json)-1], returnPath...)
	fmt.Printf("json after append: %s\n", string(json))
	//publish json
	PublishMQTTMessage(client, json, "/acme/client")

}

func extractpayloadByJWKMQTT(msg MQTT.Message) (*payloadByJWKOrKID, error) {
	var payload *payloadByJWKOrKID
	payload = new(payloadByJWKOrKID)
	jws := parseJWSMQTT(msg)
	err := validateJwsMQTT(jws, acmeDB)
	if err != nil {
		return nil, err
	}
	payload.jwk, err = extractJWKMQTT(jws)
	if err != nil {
		return nil, err
	}
	payload.payload = verifyAndExtractJWSPayloadMQTT(jws, payload.jwk)
	return payload, nil
}

func extractPayloadByKidMQTT(msg MQTT.Message) (*payloadByJWKOrKID, error) {
	var payload *payloadByJWKOrKID
	payload = new(payloadByJWKOrKID)
	jws := parseJWSMQTT(msg)
	err := validateJwsMQTT(jws, acmeDB)
	if err != nil {
		return nil, err
	}
	acc, err := lookupJWKMQTT(jws, acmeDB)
	if err != nil {
		return nil, fmt.Errorf("lookupJWKMQTT Error : %w", err)
	}
	payload.jwk = acc.Key
	payload.acc = acc
	if err != nil {
		return nil, err
	}
	payload.payload = verifyAndExtractJWSPayloadMQTT(jws, payload.jwk)
	return payload, nil
}

func route(r api.Router, middleware func(next nextHTTP) nextHTTP) {
	commonMiddleware := func(next nextHTTP) nextHTTP {
		handler := func(w http.ResponseWriter, r *http.Request) {
			// Linker middleware gets the provisioner and current url from the
			// request and sets them in the context.
			linker := acme.MustLinkerFromContext(r.Context())
			linker.Middleware(http.HandlerFunc(checkPrerequisites(next))).ServeHTTP(w, r)
		}
		if middleware != nil {
			handler = middleware(handler)
		}
		return handler
	}
	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return commonMiddleware(addNonce(addDirLink(verifyContentType(parseJWS(validateJWS(next))))))
	}
	extractpayloadByJWKOrKID := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(lookupJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKidOrJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractOrLookupJWK(verifyAndExtractJWSPayload(next)))
	}

	getPath := acme.GetUnescapedPathSuffix

	// Standard ACME API

	//check
	r.MethodFunc("GET", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))
	//check
	r.MethodFunc("HEAD", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))

	//check
	r.MethodFunc("GET", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))
	//check
	r.MethodFunc("HEAD", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))

	//check
	r.MethodFunc("POST", getPath(acme.NewAccountLinkType, "{provisionerID}"),
		extractpayloadByJWKOrKID(NewAccount))
	//leave
	r.MethodFunc("POST", getPath(acme.AccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(GetOrUpdateAccount))
	//leave
	r.MethodFunc("POST", getPath(acme.KeyChangeLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(NotImplemented))

	//check
	r.MethodFunc("POST", getPath(acme.NewOrderLinkType, "{provisionerID}"),
		extractPayloadByKid(NewOrder))
	//leave
	r.MethodFunc("POST", getPath(acme.OrderLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(isPostAsGet(GetOrder)))
	//leave
	r.MethodFunc("POST", getPath(acme.OrdersByAccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(isPostAsGet(GetOrdersByAccountID)))
	//check
	r.MethodFunc("POST", getPath(acme.FinalizeLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(FinalizeOrder))
	//check
	r.MethodFunc("POST", getPath(acme.AuthzLinkType, "{provisionerID}", "{authzID}"),
		extractPayloadByKid(isPostAsGet(GetAuthorization)))
	//check
	r.MethodFunc("POST", getPath(acme.ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"),
		extractPayloadByKid(GetChallenge))
	//todo
	r.MethodFunc("POST", getPath(acme.CertificateLinkType, "{provisionerID}", "{certID}"),
		extractPayloadByKid(isPostAsGet(GetCertificate)))
	//leave
	r.MethodFunc("POST", getPath(acme.RevokeCertLinkType, "{provisionerID}"),
		extractPayloadByKidOrJWK(RevokeCert))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       Meta   `json:"meta"`
}

// ToLog enables response logging for the Directory type.
func (d *Directory) ToLog() (interface{}, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling directory for logging")
	}
	return string(b), nil
}

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func GetDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	linker := acme.MustLinkerFromContext(ctx)
	render.JSON(w, &Directory{
		NewNonce:   linker.GetLink(ctx, acme.NewNonceLinkType),
		NewAccount: linker.GetLink(ctx, acme.NewAccountLinkType),
		NewOrder:   linker.GetLink(ctx, acme.NewOrderLinkType),
		RevokeCert: linker.GetLink(ctx, acme.RevokeCertLinkType),
		KeyChange:  linker.GetLink(ctx, acme.KeyChangeLinkType),
		Meta: Meta{
			ExternalAccountRequired: acmeProv.RequireEAB,
		},
	})
}

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func GetDirectoryMQTT() []byte {
	fmt.Printf("GetDirectoryMQTT\n")
	// initialize json
	json, err := json.Marshal(&Directory{
		NewNonce:   "/acme/acme/new-nonce",
		NewAccount: "/acme/acme/new-account",
		NewOrder:   "/acme/acme/new-order",
		RevokeCert: "/acme/acme/revoke-cert",
		KeyChange:  "/acme/acme/key-change",
	})

	if err != nil {
		fmt.Println("could not marshal json: %s\n", err)
		return nil
	}

	return json
}

// creates a nonce and
// takes a JSON (marshal) as an argument and adds a nonce to it
func AddNonceMQTT(byteJson []byte) []byte {
	fmt.Printf("AddNonceMQTT\n")
	nonce, err := acmeDB.CreateNonce(nil)

	fmt.Println(nonce)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	// 3. set the nonce in the json and return the json

	// if statement is true on every request except "new-nonce". Here, the MQTT message is empty
	if len(byteJson) > 0 {
		toAppend := fmt.Sprintf(",\"nonce\":\"%s\"}", string(nonce))
		return append(byteJson[:len(byteJson)-1], toAppend...)
	}
	return []byte(fmt.Sprintf("{\"nonce\":\"%s\"}", string(nonce)))
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func NotImplemented(w http.ResponseWriter, r *http.Request) {
	render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	az, err := db.GetAuthorization(ctx, chi.URLParam(r, "authzID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving authorization"))
		return
	}
	if acc.ID != az.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID))
		return
	}
	if err = az.UpdateStatus(ctx, db); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error updating authorization status"))
		return
	}

	linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", linker.GetLink(ctx, acme.AuthzLinkType, az.ID))
	render.JSON(w, az)
}

func GetAuthorizationMQTT(db acme.DB, acc *acme.Account, authzID string) ([]byte, error) {
	fmt.Printf("GetAuthorizationMQTT\n")
	az, err := db.GetAuthorization(nil, authzID)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error retrieving authorization")
	}
	if acc.ID != az.AccountID {
		return nil, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID)
	}
	if err = az.UpdateStatus(nil, db); err != nil {
		return nil, acme.WrapErrorISE(err, "error updating authorization status")
	}
	linkAuthorization(az)
	json, err := json.Marshal(az)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "could not marshal json: %s")
	}
	return json, nil
}

func linkAuthorization(az *acme.Authorization) {
	for _, ch := range az.Challenges {
		ch.URL = fmt.Sprintf("/acme/challenge/%s/%s", az.ID, ch.ID)
	}
}

func linkChallenge(ch *acme.Challenge, azID string) {
	ch.URL = fmt.Sprintf("/acme/challenge/%s/%s", azID, ch.ID)
}

//takes a marshaled json as input parameter and publishes the json as string on given endpoint
func PublishMQTTMessage(client MQTT.Client, json []byte, endpoint string) {
	//string(json)
	token := client.Publish(endpoint, 0, false, string(json))
	token.Wait()
}

// GetChallenge ACME api for retrieving a Challenge.
func GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	// Just verify that the payload was set, since we're not strictly adhering
	// to ACME V2 spec for reasons specified below.
	_, err = payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	// NOTE: We should be checking ^^^ that the request is either a POST-as-GET, or
	// that the payload is an empty JSON block ({}). However, older ACME clients
	// still send a vestigial body (rather than an empty JSON block) and
	// strict enforcement would render these clients broken. For the time being
	// we'll just ignore the body.

	azID := chi.URLParam(r, "authzID")
	ch, err := db.GetChallenge(ctx, chi.URLParam(r, "chID"), azID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving challenge"))
		return
	}
	ch.AuthorizationID = azID
	if acc.ID != ch.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own challenge '%s'", acc.ID, ch.ID))
		return
	}
	jwk, err := jwkFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	if err = ch.Validate(ctx, db, jwk); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	linkChallenge(ch, azID)

	w.Header().Add("Link", link(linker.GetLink(ctx, acme.AuthzLinkType, azID), "up"))
	w.Header().Set("Location", linker.GetLink(ctx, acme.ChallengeLinkType, azID, ch.ID))
	render.JSON(w, ch)
}

func getAzIDChID(path string) ([]string, error) {
	authzIDchID := path[len("/acme/challenge/"):]
	split := strings.Split(authzIDchID, "/")
	if len(split) != 2 {
		return nil, fmt.Errorf("challenge path does not have the required format. Expected parameters : 2, have : %s", len(split))
	}
	return split, nil
}

func GetChallengeMQTT(db acme.DB, acc *acme.Account, azID string, chID string, jwk *jose.JSONWebKey) ([]byte, error) {
	fmt.Printf("GetChallengeMQTT\n")
	ch, err := db.GetChallenge(nil, chID, azID)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error retrieving challenge")
	}
	ch.AuthorizationID = azID
	if acc.ID != ch.AccountID {
		return nil, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own challenge '%s'", acc.ID, ch.ID)
	}
	if err = ch.ValidateMQTT(db, jwk); err != nil {
		return nil, acme.WrapErrorISE(err, "error validating challenge")
	}
	json, err := json.Marshal(ch)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "could not marshal json: %s")
	}
	return json, nil
}

// GetCertificate ACME api for retrieving a Certificate.
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	certID := chi.URLParam(r, "certID")
	cert, err := db.GetCertificate(ctx, certID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving certificate"))
		return
	}
	if cert.AccountID != acc.ID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own certificate '%s'", acc.ID, certID))
		return
	}

	var certBytes []byte
	for _, c := range append([]*x509.Certificate{cert.Leaf}, cert.Intermediates...) {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	api.LogCertificate(w, cert.Leaf)
	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.Write(certBytes)
}

func GetCertificateMQTT(db acme.DB, acc *acme.Account, certID string) ([]byte, error) {
	cert, err := db.GetCertificate(nil, certID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving certificate: %s\n", err)
	}

	if cert.AccountID != acc.ID {
		return nil, fmt.Errorf("account does not own certificate: %s\n", err)
	}
	var certBytes []byte
	for _, c := range append([]*x509.Certificate{cert.Leaf}, cert.Intermediates...) {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}
	fmt.Printf("CERTIFICATE:\n %s", string(certBytes))
	return certBytes, nil
}
