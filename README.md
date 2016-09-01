# What's all this then?

`dot-iptables.py` reads the output of `iptables-save` and then
generates a [dot][] graph showing the relationship between chains in your
iptables configuration, with clickable chain names to see the rules in
the given chain.

[dot]: http://www.graphviz.org/

# Run with Docker 

```
git clone https://github.com/allanhung/dot-iptables
cd dot-iptables
docker build -t dot-iptables .
docker run --privileged --name=dotiptables --rm -p 8000:8000 dot-iptables
```
