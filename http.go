package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
)

var (
	allowedIPs   = []string{}
	allowedUsers = []string{}
	cookieKey    = []byte{}
	cookieEncKey = []byte{}
	proxyIP      = false
	store        *sessions.FilesystemStore
)

// Check if user is authenticated
func authHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isAuthorized(w, r) {
			handler(w, r)
			return
		} else {
			http.Redirect(w, r, "/login", 302)
		}
	}
}

// Check if user is allowed in config
func isAuthorized(w http.ResponseWriter, r *http.Request) bool {
	remoteIP := strings.Split(r.RemoteAddr, ":")[0]
	if proxyIP {
		// Proxy itself is behind proxy, trust X-Forwarded-IP header
		if proxyIP := r.Header.Get("X-Forwarded-For"); proxyIP != "" {
			remoteIP = proxyIP
		}
	}
	for i := 0; i < len(allowedIPs); i++ {
		if allowedIPs[i] == remoteIP ||
			(strings.HasSuffix(allowedIPs[i], ".") && strings.HasPrefix(remoteIP, allowedIPs[i])) {
			return true
		}
	}

	// Check if user has been authorized via session
	cookie, _ := r.Cookie("proxy")
	if cookie != nil && cookie.Value != "" {
		if session, err := store.Get(r, "proxy"); err == nil {
			if session.Values["auth"] != nil {
				for _, oneEmail := range allowedUsers {
					if oneEmail == session.Values["auth"] {
						return true
					}
				}
				// E-mail not found in configured allow list
				fmt.Println("Denied access to:", session.Values["auth"])
			}
		} else {
			// Cookie error, set new cookie
			session, err = store.New(r, "proxy")
			session.Values["auth"] = nil
			session.Save(r, w)
		}
	}

	return false
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate appleNonce
	var appleCode uint32
	var loggedInEmail string

	fmt.Println("loginHandler")
	googleIDToken := r.PostFormValue("idtoken")
	if googleIDToken != "" {
		// Google Sign In
		// fmt.Println(googleIDToken) // JWT Token
		resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + googleIDToken)
		if err != nil {
			// handle error
			fmt.Println("error", err)
		}
		// fmt.Println(resp)

		defer resp.Body.Close()
		bodyByte, err := ioutil.ReadAll(resp.Body)
		type googleResponseStruct struct {
			Iss   string `json:"iss"`
			Aud   string `json:"aud"`
			Exp   string `json:"exp"`
			Email string `json:"email"`
		}
		var googleResponse googleResponseStruct
		if err := json.Unmarshal(bodyByte, &googleResponse); err != nil {
			fmt.Println(err)
		}

		// fmt.Println(googleResponse)
		// Verify if token is valid
		if (googleResponse.Iss == "accounts.google.com" || googleResponse.Iss == "https://accounts.google.com") &&
			googleResponse.Aud == (googleClientID+".apps.googleusercontent.com") {
			if exp, err := strconv.ParseInt(googleResponse.Exp, 10, 64); err == nil {
				if exp > time.Now().Unix() {
					if session, err := store.Get(r, "proxy"); err == nil {
						session.Values["auth"] = googleResponse.Email
						session.Save(r, w)
						fmt.Println("Google Sign In", googleResponse.Email)

						w.Write([]byte("LoginOK"))
						return
					}
				}
			}
		}
		// fmt.Println(string(bodyByte))
		// fmt.Println(googleResponse)
	}

	if session, err := store.Get(r, "proxy"); err == nil {
		// Check for Apple ID login
		stateStr := r.PostFormValue("state")
		var state uint64
		if stateStr != "" {
			state, _ = strconv.ParseUint(stateStr, 10, 32)
		}
		code := r.PostFormValue("code")
		//user: {"name":{"firstName":"John","lastName":"Doe"},"email":"sample.email.that.probably.does.not.exist@gmail.com"}

		if stateStr != "" && code != "" {
			// Verify state code (nonce) and invalidate it
			if uint32(state) == session.Values["appleCode"].(uint32) {
				session.Values["appleCode"] = nil

				//Verify code with Apple
				client := http.Client{Timeout: time.Duration(20 * time.Second)}
				data := "grant_type=authorization_code&code=" + code + "&client_id=" + appleClientID + "&redirect_uri=https://" + config.ProxyHost + ":" + serverPort + "/login&client_secret=" + jwtSignature()

				resp, err := client.Post("https://appleid.apple.com/auth/token", "application/x-www-form-urlencoded", strings.NewReader(data))
				if err != nil {
					// handle error
					fmt.Println("error", err)
				}

				defer resp.Body.Close()
				bodyByte, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println("error", err)
				}
				email := jwtParse(bodyByte)
				session.Values["auth"] = email
				session.Save(r, w)

				http.Redirect(w, r, "/", 302)
				return
			}
		}

		if session.Values["appleCode"] == nil {
			appleBytes := make([]byte, 8)
			if _, err := rand.Read(appleBytes); err == nil {
				binary.Read(bytes.NewReader(appleBytes), binary.LittleEndian, &appleCode)
			}

			session.Values["appleCode"] = appleCode
			session.Save(r, w)
		} else {
			appleCode = session.Values["appleCode"].(uint32)
		}
	}

	if session, err := store.Get(r, "proxy"); err == nil {
		if session.Values["auth"] != nil {
			loggedInEmail = session.Values["auth"].(string)
		}
	}
	// Parse template
	type pageDataStruct struct {
		AppleCode      uint32
		LoggedInEmail  string
		LoggedIn       bool
		ProxyHost      string
		GoogleClientID string
		AppleClientID  string
		ServerPort     string
	}
	pageData := pageDataStruct{
		AppleCode:      appleCode,
		LoggedInEmail:  loggedInEmail,
		LoggedIn:       loggedInEmail != "",
		ProxyHost:      config.ProxyHost,
		GoogleClientID: googleClientID,
		AppleClientID:  appleClientID,
		ServerPort:     serverPort}
	tmpl := template.Must(template.ParseFiles("templates/login.tmpl"))
	_ = tmpl.Execute(w, pageData)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if session, err := store.Get(r, "proxy"); err == nil {
		session.Values["auth"] = nil
		session.Save(r, w)

		http.Redirect(w, r, "/", 302)
	}
}

// func proxyHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// newURLString := r.URL.String()[7:]
// 		// newURL, _ := url.Parse(newURLString)
// 		// r.URL = newURL

// 		log.Println(r.URL)
// 		// fmt.Println(r)
// 		p.ServeHTTP(w, r)
// 	}
// }

// func updateResponse(r *http.Response) error {
// 	b, _ := ioutil.ReadAll(r.Body)
// 	newB := bytes.ReplaceAll(b, []byte("src=\"/"), []byte("src=\"/influx/"))
// 	newB = bytes.ReplaceAll(newB, []byte("href=\"/"), []byte("href=\"/influx/"))
// 	buf := bytes.NewBuffer(newB)
// 	r.Body = ioutil.NopCloser(buf)
// 	r.Header["Content-Length"] = []string{fmt.Sprint(buf.Len())}
// 	return nil
// }

func mainHandler(w http.ResponseWriter, r *http.Request) {

	tmpl := template.Must(template.ParseFiles("templates/main.tmpl"))

	// Parse template
	type tmplServiceStruct struct {
		URL         string
		Description string
	}
	type pageDataStruct struct {
		Services       []tmplServiceStruct
		GoogleClientID string
	}

	var pageData pageDataStruct
	pageData.GoogleClientID = googleClientID
	host := "http://"
	if config.SSL {
		host = "https://"
	}
	host += config.ProxyHost

	// Generate service links for all services to show them in template
	for _, oneService := range config.Services {
		pageData.Services = append(pageData.Services, tmplServiceStruct{URL: host + oneService.Port + oneService.URLLink, Description: oneService.Description})
	}
	err := tmpl.Execute(w, pageData)
	if err != nil {
		fmt.Println("template execution:", err)
	}
}

type proxyHandler struct {
	proxy *httputil.ReverseProxy
}

// Check user authentication and proxy request to the service
func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// log.Println(r.URL)
	if !isAuthorized(w, r) {
		w.Write([]byte("<html>Access Denied <a href=https://" + config.ProxyHost + ":" + serverPort + "/logout>Logout</a>"))
		return
	}
	p.proxy.ServeHTTP(w, r)
}
