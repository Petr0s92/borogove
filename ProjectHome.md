# Description #

Borogove is a python script for sniff Facebook chat traffic over the network.

It uses the pypcap module and supports Man-In-The-Middle ARP poisoning attacks.


**[Latest version](http://borogove.googlecode.com/svn/trunk/borogove.py)**

# Requirements #

**Python 2.x**

**[arpspoof](http://www.monkey.org/~dugsong/dsniff/) (dsniff suite)**

**[dpkt](http://code.google.com/p/dpkt/)**

**[pypcap](http://code.google.com/p/pypcap/)**


# Installation #

## Ubuntu ##

```
sudo apt-get install python-dpkt python-pypcap dsniff
```

## ArchLinux ##

```
pacman -Sy dsniff
```

install AUR packages:

[dpkt-svn](https://aur.archlinux.org/packages.php?ID=21579)

[pypcap-svn](https://aur.archlinux.org/packages.php?ID=41944)
