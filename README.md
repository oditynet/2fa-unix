# 2fa-unix
2FA авторизация в unix система со своим сервером


### Build

```
gcc -fPIC -shared -o pam_2fact.so 2fact.c -lcurl -lpam
go build -o aserver server.go 
```

### Install

```
sudo cp aserver /usr/local/bin/
sudo cp aserver.service /etc/systemd/system/
sudo cp pam_2fact.so /lib64/security/

systemctl daemon-reload
systemctl restart aserver.service
systemctl enable aserver
```

#### Register user


```
curl -X POST http://localhost:13031/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

### Get token

```
curl -X POST http://localhost:13031/api/v1/token \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

#### Config PAM.d

```
echo "auth required pam_2fact.so username=<username> token=<token>" >>  /etc/pam.d/system-auth
```


```
viva:pam.d # cat system-auth|grep -v ^$|grep -v ^#
auth       required                    pam_faillock.so      preauth
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth required pam_2fact.so username=user token=c4ef1bd58b3105b
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
-account   [success=1 default=ignore]  pam_systemd_home.so
account    required                    pam_unix.so
account    optional                    pam_permit.so
account    required                    pam_time.so
-password  [success=1 default=ignore]  pam_systemd_home.so
password   required                    pam_unix.so          try_first_pass nullok shadow sha512
password   optional                    pam_permit.so
password	optional	pam_gnome_keyring.so
-session   optional                    pam_systemd_home.so
session    required                    pam_limits.so
session    required                    pam_unix.so
session    optional                    pam_permit.so
```
