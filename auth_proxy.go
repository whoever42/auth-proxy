package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/gorilla/sessions"
	yaml "gopkg.in/yaml.v2"
)

var (
	serverIP       = "0.0.0.0"
	serverPort     = "4321"
	googleClientID = ""
	appleClientID  = ""
	appleTeamID    = ""
	appleKeyID     = ""
	config         configStruct
	debugLog       = false
	configFile     = "proxy_config.yaml"
)

type configStruct struct {
	ServerIP       string
	ServerPort     string
	ProxyHost      string
	SSL            bool
	GoogleClientID string
	AppleClientID  string
	AppleTeamID    string
	AppleKeyID     string
	CookieKey      []byte
	CookieEncKey   []byte
	AllowedIPs     []string
	AllowedUsers   []string
	Services       []serviceStruct
	DebugLog       bool
	ProxyIP        bool
}
type serviceStruct struct {
	Description string
	URL         string
	Port        string
	URLLink     string
}

func main() {
	// Log config from different file if specified as argument
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	// Load and process config file
	source, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		panic(err)
	}
	allowedIPs = config.AllowedIPs
	allowedUsers = config.AllowedUsers
	serverIP = config.ServerIP
	serverPort = ":" + config.ServerPort
	debugLog = config.DebugLog
	proxyIP = config.ProxyIP
	googleClientID = config.GoogleClientID
	appleClientID = config.AppleClientID
	appleTeamID = config.AppleTeamID
	appleKeyID = config.AppleKeyID
	cookieKey = config.CookieKey
	cookieEncKey = config.CookieEncKey

	// Session storage options
	store = sessions.NewFilesystemStore(os.TempDir(), cookieKey, cookieEncKey)
	// Authenticated session valid for 7 days, however, access to the service is blocked immediatelly after config change and reload
	store.Options = &sessions.Options{MaxAge: 60 * 60 * 24 * 7, HttpOnly: true}

	http.HandleFunc("/", authHandler(mainHandler))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets/"))))

	// Initial service port, following services are assigned port number +1
	servicePort := 9001
	for idx, oneService := range config.Services {
		remote, err := url.Parse(oneService.URL)
		if err != nil {
			fmt.Println(err)
			panic("Invalid service config")
		}
		// proxy.ModifyResponse = updateResponse

		config.Services[idx].Port = ":" + strconv.Itoa(servicePort)
		h := httputil.NewSingleHostReverseProxy(remote)
		if config.SSL {
			var InsecureTransport http.RoundTripper = &http.Transport{
				// Dial: (&net.Dialer{
				// 	Timeout:   30 * time.Second,
				// 	KeepAlive: 30 * time.Second,
				// }).Dial,
				// TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				// TLSHandshakeTimeout: 10 * time.Second,
			}
			h.Transport = InsecureTransport
			go http.ListenAndServeTLS(config.Services[idx].Port, "cert.pem", "key.pem", &proxyHandler{proxy: h})
		} else {
			go http.ListenAndServe(config.Services[idx].Port, &proxyHandler{proxy: h})
		}
		servicePort++
	}

	if config.SSL {
		http.ListenAndServeTLS(serverIP+":"+serverPort, "cert.pem", "key.pem", nil)
	} else {
		http.ListenAndServe(serverIP+":"+serverPort, nil)
	}
}

// /lib/systemd/system/proxy.service
// sudo systemctl enable proxy-service
// sudo systemctl start proxy-service
