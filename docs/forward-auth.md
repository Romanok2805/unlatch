# Forward authentication

For services that don't support OpenID Connect, your reverse proxy asks Unlatch about every request
and lets it through only for signed-in users who may use the service. How it works is described in
[the architecture](architecture.md#forward-authentication).

1. In administration, add an application of the kind *Forward auth* with the host of the service,
   such as `photos.example.com`, and choose who may use it.
2. List the address of your proxy in `UNLATCH_TRUSTED_PROXIES`; Unlatch answers forward-auth
   requests only from there.
3. Configure the proxy as below. Two things are needed for each protected host: requests to
   `/_unlatch/` go to Unlatch, and every other request is checked first.

The service receives the user in `Remote-User`, `Remote-Name`, `Remote-Email` and `Remote-Groups`
(group names separated by commas). The configurations below replace whatever the client sent in
these headers; a service must not be reachable around the proxy, or anyone could send them.

In the examples Unlatch runs at `https://login.example.com`, reachable from the proxy as
`unlatch:8080`, and the service as `photos:2342`.

## Caddy

```caddy
photos.example.com {
	handle /_unlatch/* {
		reverse_proxy unlatch:8080
	}
	handle {
		forward_auth unlatch:8080 {
			uri /forward-auth
			copy_headers Remote-User Remote-Name Remote-Email Remote-Groups
		}
		reverse_proxy photos:2342
	}
}
```

## Traefik

```yaml
http:
  middlewares:
    unlatch:
      forwardAuth:
        address: http://unlatch:8080/forward-auth
        authResponseHeaders: [Remote-User, Remote-Name, Remote-Email, Remote-Groups]
  routers:
    photos:
      rule: Host(`photos.example.com`)
      middlewares: [unlatch]
      service: photos
    photos-unlatch:
      rule: Host(`photos.example.com`) && PathPrefix(`/_unlatch/`)
      service: unlatch
  services:
    photos:
      loadBalancer:
        servers: [{ url: http://photos:2342 }]
    unlatch:
      loadBalancer:
        servers: [{ url: http://unlatch:8080 }]
```

## nginx

nginx's `auth_request` only understands success or 401, so it uses `/forward-auth/nginx`, which
answers 401 with the sign-in address in `Location` and a cookie that ties the sign-in to this
browser; nginx has to pass the cookie on.

```nginx
server {
    server_name photos.example.com;

    location /_unlatch/ {
        proxy_pass http://unlatch:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /_unlatch_check {
        internal;
        proxy_pass http://unlatch:8080/forward-auth/nginx;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        auth_request /_unlatch_check;
        auth_request_set $sign_in $upstream_http_location;
        auth_request_set $sign_in_cookie $upstream_http_set_cookie;
        add_header Set-Cookie $sign_in_cookie always;
        error_page 401 =302 $sign_in;

        auth_request_set $user $upstream_http_remote_user;
        auth_request_set $name $upstream_http_remote_name;
        auth_request_set $email $upstream_http_remote_email;
        auth_request_set $groups $upstream_http_remote_groups;
        proxy_set_header Remote-User $user;
        proxy_set_header Remote-Name $name;
        proxy_set_header Remote-Email $email;
        proxy_set_header Remote-Groups $groups;

        proxy_pass http://photos:2342;
    }
}
```

## Signing out

A link to `/_unlatch/logout` on the protected host ends its session there and continues to sign
out of Unlatch, which asks the user to confirm.
