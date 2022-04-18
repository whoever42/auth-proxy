# Intro
There are numerous better alternatives around nowadays.

Purpose of this project was to have hands-on experience with external Google and Apple SSO services.

# How it works
1. This proxy service allows users to authenticate via Google and Apple SSO services.
2. After authentication, if particular users their e-mail address is specified in configuration file, user can access the service via this proxy, e.g.:
- service that is listening on local interface of the proxy server (e.g. 127.0.0.1);
- service that is not directly available on proxy server due to firewall rules;
- any other service, incl. external sites, that are not directly available from the Internet but are accessible from proxy server.
3. Each service configured for proxying is listening on it's own TCP port, to avoid issues with URL path rewrite.