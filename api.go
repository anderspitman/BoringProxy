package boringproxy

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Api struct {
	config *BoringProxyConfig
	db     *Database
	auth   *Auth
	tunMan *TunnelManager
	mux    *http.ServeMux
}

func NewApi(config *BoringProxyConfig, db *Database, auth *Auth, tunMan *TunnelManager) *Api {

	mux := http.NewServeMux()

	api := &Api{config, db, auth, tunMan, mux}

	mux.Handle("/tunnels", http.StripPrefix("/tunnels", http.HandlerFunc(api.handleTunnels)))
	mux.Handle("/users/", http.StripPrefix("/users", http.HandlerFunc(api.handleUsers)))
	mux.Handle("/tokens/", http.StripPrefix("/tokens", http.HandlerFunc(api.handleTokens)))

	return api
}

func (a *Api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *Api) handleTunnels(w http.ResponseWriter, r *http.Request) {

	token, err := extractToken("access_token", r)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("No token provided"))
		return
	}

	tokenData, exists := a.db.GetTokenData(token)
	if !exists {
		w.WriteHeader(403)
		w.Write([]byte("Not authorized"))
		return
	}

	switch r.Method {
	case "GET":
		query := r.URL.Query()

		tunnels := a.GetTunnels(tokenData)

		if len(query["client-name"]) == 1 {
			clientName := query["client-name"][0]
			for k, tun := range tunnels {
				if tun.ClientName != clientName {
					delete(tunnels, k)
				}
			}
		}

		body, err := json.Marshal(tunnels)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte("Error encoding tunnels"))
			return
		}

		hash := md5.Sum(body)
		hashStr := fmt.Sprintf("%x", hash)

		w.Header()["ETag"] = []string{hashStr}

		w.Write([]byte(body))
	case "POST":
		r.ParseForm()
		_, err := a.CreateTunnel(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		}
	case "DELETE":
		r.ParseForm()
		err := a.DeleteTunnel(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		}
	default:
		w.WriteHeader(405)
		w.Write([]byte("Invalid method for /tunnels"))
	}
}

func (a *Api) handleUsers(w http.ResponseWriter, r *http.Request) {
	token, err := extractToken("access_token", r)
	if err != nil {
		w.WriteHeader(401)
		io.WriteString(w, "Invalid token")
		return
	}

	tokenData, exists := a.db.GetTokenData(token)
	if !exists {
		w.WriteHeader(401)
		io.WriteString(w, "Failed to get token")
		return
	}

	path := r.URL.Path
	parts := strings.Split(path[1:], "/")

	r.ParseForm()

	if path == "/" {
		switch r.Method {
		case "POST":
			err := a.CreateUser(tokenData, r.Form)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
		default:
			w.WriteHeader(406)
			io.WriteString(w, "Invalid method for /users")
			return
		}
	} else if len(parts) == 3 && parts[1] == "clients" {
		ownerId := parts[0]
		clientId := parts[2]
		if r.Method == "PUT" {
			err := a.SetClient(tokenData, r.Form, ownerId, clientId)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
		} else if r.Method == "DELETE" {
			err := a.DeleteClient(tokenData, ownerId, clientId)
			if err != nil {
				w.WriteHeader(500)
				io.WriteString(w, err.Error())
				return
			}
		}
	} else {
		w.WriteHeader(400)
		io.WriteString(w, "Invalid /users/<username>/clients request")
		return
	}
}

func (a *Api) handleTokens(w http.ResponseWriter, r *http.Request) {
	token, err := extractToken("access_token", r)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("No token provided"))
		return
	}

	tokenData, exists := a.db.GetTokenData(token)
	if !exists {
		w.WriteHeader(403)
		w.Write([]byte("Not authorized"))
		return
	}

	switch r.Method {
	case "POST":
		r.ParseForm()
		token, err := a.CreateToken(tokenData, r.Form)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		}

		io.WriteString(w, token)
	default:
		w.WriteHeader(405)
		w.Write([]byte(err.Error()))
	}
}

func (a *Api) GetTunnel(tokenData TokenData, params url.Values) (Tunnel, error) {
	domain := params.Get("domain")
	if domain == "" {
		return Tunnel{}, errors.New("Invalid domain parameter")
	}

	tun, exists := a.db.GetTunnel(domain)
	if !exists {
		return Tunnel{}, errors.New("Tunnel doesn't exist for domain")
	}

	user, _ := a.db.GetUser(tokenData.Owner)
	if user.IsAdmin || tun.Owner == tokenData.Owner {
		return tun, nil
	} else {
		return Tunnel{}, errors.New("Unauthorized")
	}
}

func (a *Api) GetTunnels(tokenData TokenData) map[string]Tunnel {

	user, _ := a.db.GetUser(tokenData.Owner)

	var tunnels map[string]Tunnel

	if user.IsAdmin {
		tunnels = a.db.GetTunnels()
	} else {
		tunnels = make(map[string]Tunnel)

		for domain, tun := range a.db.GetTunnels() {
			if tokenData.Owner == tun.Owner {
				tunnels[domain] = tun
			}
		}
	}

	return tunnels
}

func (a *Api) CreateTunnel(tokenData TokenData, params url.Values) (*Tunnel, error) {

	domain := params.Get("domain")
	if domain == "" {
		return nil, errors.New("Invalid domain parameter")
	}

	owner := params.Get("owner")
	if owner == "" {
		return nil, errors.New("Invalid owner parameter")
	}

	if tokenData.Owner != owner {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return nil, errors.New("Unauthorized")
		}
	}

	sshKeyId := params.Get("ssh-key-id")

	var sshKey SshKey
	if sshKeyId != "" {
		var exists bool
		sshKey, exists = a.db.GetSshKey(sshKeyId)
		if !exists {
			return nil, errors.New("SSH key does not exist")
		}
	}

	clientName := params.Get("client-name")

	clientPort := 0
	clientPortParam := params.Get("client-port")
	if clientPortParam != "" {
		var err error
		clientPort, err = strconv.Atoi(clientPortParam)
		if err != nil {
			return nil, errors.New("Invalid client-port parameter")
		}
	}

	clientAddr := params.Get("client-addr")
	if clientAddr == "" {
		clientAddr = "127.0.0.1"
	}

	allowExternalTcp := params.Get("allow-external-tcp") == "on"

	passwordProtect := params.Get("password-protect") == "on"

	var username string
	var password string
	if passwordProtect {
		username = params.Get("username")
		if username == "" {
			return nil, errors.New("Username required")
		}

		password = params.Get("password")
		if password == "" {
			return nil, errors.New("Password required")
		}
	}

	tlsTerm := params.Get("tls-termination")
	if tlsTerm != "server" && tlsTerm != "client" && tlsTerm != "passthrough" {
		return nil, errors.New("Invalid tls-termination parameter")
	}

	request := Tunnel{
		Domain:           domain,
		SshKey:           sshKey.Key,
		Owner:            tokenData.Owner,
		ClientName:       clientName,
		ClientPort:       clientPort,
		ClientAddress:    clientAddr,
		AllowExternalTcp: allowExternalTcp,
		AuthUsername:     username,
		AuthPassword:     password,
		TlsTermination:   tlsTerm,
	}

	tunnel, err := a.tunMan.RequestCreateTunnel(request)
	if err != nil {
		return nil, err
	}

	return &tunnel, nil
}

func (a *Api) DeleteTunnel(tokenData TokenData, params url.Values) error {
	domain := params.Get("domain")
	if domain == "" {
		return errors.New("Invalid domain parameter")
	}

	tun, exists := a.db.GetTunnel(domain)
	if !exists {
		return errors.New("Tunnel doesn't exist")
	}

	if tokenData.Owner != tun.Owner {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return errors.New("Unauthorized")
		}
	}

	a.tunMan.DeleteTunnel(domain)

	return nil
}

func (a *Api) CreateToken(tokenData TokenData, params url.Values) (string, error) {

	owner := params.Get("owner")
	if owner == "" {
		return "", errors.New("Invalid owner paramater")
	}

	if tokenData.Owner != owner {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return "", errors.New("Unauthorized")
		}
	}

	token, err := a.db.AddToken(owner)
	if err != nil {
		return "", errors.New("Failed to create token")
	}

	return token, nil
}

func (a *Api) DeleteToken(tokenData TokenData, params url.Values) error {
	token := params.Get("token")
	if token == "" {
		return errors.New("Invalid token parameter")
	}

	delTokenData, exists := a.db.GetTokenData(token)
	if !exists {
		return errors.New("Token doesn't exist")
	}

	if tokenData.Owner != delTokenData.Owner {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return errors.New("Unauthorized")
		}
	}

	a.db.DeleteTokenData(token)

	return nil

}

func (a *Api) CreateUser(tokenData TokenData, params url.Values) error {

	user, _ := a.db.GetUser(tokenData.Owner)
	if !user.IsAdmin {
		return errors.New("Unauthorized")
	}

	username := params.Get("username")
	minUsernameLen := 6
	if len(username) < minUsernameLen {
		errStr := fmt.Sprintf("Username must be at least %d characters", minUsernameLen)
		return errors.New(errStr)
	}

	isAdmin := params.Get("is-admin") == "on"

	err := a.db.AddUser(username, isAdmin)
	if err != nil {
		return err
	}

	return nil
}

func (a *Api) DeleteUser(tokenData TokenData, params url.Values) error {

	user, _ := a.db.GetUser(tokenData.Owner)
	if !user.IsAdmin {
		return errors.New("Unauthorized")
	}

	username := params.Get("username")
	if username == "" {
		return errors.New("Invalid username parameter")
	}

	_, exists := a.db.GetUser(username)
	if !exists {
		return errors.New("User doesn't exist")
	}

	a.db.DeleteUser(username)

	for token, tokenData := range a.db.GetTokens() {
		if tokenData.Owner == username {
			a.db.DeleteTokenData(token)
		}
	}

	return nil
}

func (a *Api) SetClient(tokenData TokenData, params url.Values, ownerId, clientId string) error {

	if tokenData.Owner != ownerId {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return errors.New("Unauthorized")
		}
	}

	// TODO: what if two users try to get then set at the same time?
	owner, _ := a.db.GetUser(ownerId)
	owner.Clients[clientId] = Client{}
	a.db.SetUser(ownerId, owner)

	return nil
}

func (a *Api) DeleteClient(tokenData TokenData, ownerId, clientId string) error {

	if tokenData.Owner != ownerId {
		user, _ := a.db.GetUser(tokenData.Owner)
		if !user.IsAdmin {
			return errors.New("Unauthorized")
		}
	}

	owner, _ := a.db.GetUser(ownerId)
	delete(owner.Clients, clientId)
	a.db.SetUser(ownerId, owner)

	return nil
}

func (a *Api) GetSshKeys(tokenData TokenData) map[string]SshKey {

	user, _ := a.db.GetUser(tokenData.Owner)

	var keys map[string]SshKey

	if user.IsAdmin {
		keys = a.db.GetSshKeys()
	} else {
		keys = make(map[string]SshKey)

		for id, key := range a.db.GetSshKeys() {
			if tokenData.Owner == key.Owner {
				keys[id] = key
			}
		}
	}

	return keys
}

func (a *Api) DeleteSshKey(tokenData TokenData, params url.Values) error {
	id := params.Get("id")
	if id == "" {
		return errors.New("Invalid id parameter")
	}

	a.db.DeleteSshKey(id)

	return nil
}
