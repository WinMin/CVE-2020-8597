# CVE-2020-8597

I use two virtual machines to test on the same computer.One as server and one as client，and they all use NAT for network connection.
So they are all under the ens33 network card..

## set up a pppoe-server

You can set up the service according to the following article

https://askubuntu.com/questions/934685/pppoe-server-on-ubuntu-14-04-not-working-peer-xxx-failed-chap-session-verifica

http://www.howtodoityourself.org/pppoe-server-how-to-do-it-yourself.html

open the debug mode and set log file:
Add the following to the `/etc/ppp/pppoe-server-options` file
```
debug
logfile /var/log/pppoe-server-log
```

## set up a ppoe client

Start the clietn:

```bash
sudo pppoeconf 
```

## Screenshot

![image-20200308221134194](./img/crash.png)

## Ref

https://github.com/marcinguy/CVE-2020-8597
